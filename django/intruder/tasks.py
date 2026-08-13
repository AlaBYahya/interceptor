from collections import Counter

from celery import shared_task
from django.utils import timezone

from core.scope import OutOfScopeError, is_in_scope
from core.senders import send_request
from repeater.headers_text import headers_to_text, text_to_headers

from .markers import count_points, strip_markers, substitute_point
from .models import IntruderAttack, IntruderResult


def _strip_nul(value):
    """Postgres text columns reject a raw NUL byte outright — strip it
    rather than let a save() blow up on a response body that happens to
    contain one (rare, but real servers can send it)."""
    return value.replace("\x00", "") if isinstance(value, str) else value


def _render(attack, headers_text, point_index, payload, url_count, headers_count):
    """Build (url, headers_dict, body) for one payload at one insertion
    point, leaving every other marked position at its original value."""
    if point_index < url_count:
        url = substitute_point(attack.url, point_index, payload)
        rendered_headers_text = strip_markers(headers_text)
        body = strip_markers(attack.body)
    elif point_index < url_count + headers_count:
        url = strip_markers(attack.url)
        rendered_headers_text = substitute_point(headers_text, point_index - url_count, payload)
        body = strip_markers(attack.body)
    else:
        url = strip_markers(attack.url)
        rendered_headers_text = strip_markers(headers_text)
        body = substitute_point(attack.body, point_index - url_count - headers_count, payload)
    return url, text_to_headers(rendered_headers_text), body


@shared_task
def run_intruder_attack(attack_id):
    """Sniper attack: for each §marked§ insertion point (independently),
    sweep the full payload list through just that position while every
    other marked position stays at its original value. Scope-checked once
    up front (the base URL's host doesn't change across substitutions
    unless a point is IN the host itself, in which case core.senders'
    per-request check still catches it)."""
    try:
        attack = IntruderAttack.objects.get(id=attack_id)
    except IntruderAttack.DoesNotExist:
        return

    if not is_in_scope(attack.project, attack.url):
        attack.status = "failed"
        attack.save(update_fields=["status"])
        return

    headers_text = headers_to_text(attack.headers)
    url_count = count_points(attack.url)
    headers_count = count_points(headers_text)
    body_count = count_points(attack.body)
    total_points = url_count + headers_count + body_count

    payloads = [line for line in attack.payload_set.splitlines() if line != ""]

    if total_points == 0 or not payloads:
        attack.status = "failed"
        attack.save(update_fields=["status"])
        return

    attack.status = "running"
    attack.save(update_fields=["status"])

    for point_index in range(total_points):
        for payload in payloads:
            url, headers, body = _render(attack, headers_text, point_index, payload, url_count, headers_count)
            start = timezone.now()
            try:
                response = send_request(attack.project, attack.method, url, headers=headers, body=body)
                IntruderResult.objects.create(
                    attack=attack,
                    payload=_strip_nul(payload),
                    request_url=_strip_nul(url),
                    request_headers=headers,
                    request_body=_strip_nul(body),
                    status_code=response.status_code,
                    length=len(response.content),
                    duration_ms=int((timezone.now() - start).total_seconds() * 1000),
                    response_headers=dict(response.headers),
                    response_body=_strip_nul(response.text),
                )
            except OutOfScopeError:
                # A point substituted into the host itself pushed this
                # request out of scope — skip it, keep the rest of the sweep.
                IntruderResult.objects.create(
                    attack=attack, payload=payload, request_url=url, request_headers=headers, request_body=body,
                    error="SKIPPED: out of scope",
                )
            except Exception as exc:  # noqa: BLE001 — record and keep sweeping
                IntruderResult.objects.create(
                    attack=attack, payload=payload, request_url=url, request_headers=headers, request_body=body,
                    error=f"ERROR: {exc}",
                )

    _flag_anomalies(attack)

    attack.status = "done"
    attack.save(update_fields=["status"])


def _flag_anomalies(attack):
    """Flag results whose status code or response length differs from the
    most common (baseline) value — the quick way to spot which payload did
    something different, same idea as Burp's Intruder results grid."""
    results = list(attack.results.all())
    if not results:
        return

    baseline_status = Counter(r.status_code for r in results).most_common(1)[0][0]
    baseline_length = Counter(r.length for r in results).most_common(1)[0][0]

    for result in results:
        result.is_anomaly = result.status_code != baseline_status or result.length != baseline_length
    IntruderResult.objects.bulk_update(results, ["is_anomaly"])
