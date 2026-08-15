"""Single choke point for all outbound requests this tool sends on the
user's behalf (Repeater, Intruder, Active Scanner). Every call goes through
the scope check first — see core/scope.py.
"""

import threading
import time

import httpx

from .scope import OutOfScopeError, is_in_scope

# Neither the active scanner's per-parameter probe loops nor Intruder's
# payload sweep otherwise pace themselves at all — without this they'd fire
# requests back-to-back, which blows past typical bug-bounty rate-limit
# rules (e.g. "max 1 request/second") the moment either is pointed at a real
# program. One conservative global floor here, matching the crawler's own
# default pace, covers every caller through this single choke point instead
# of each one needing its own throttling.
_MIN_REQUEST_INTERVAL_SECONDS = 1.0
_throttle_lock = threading.Lock()
_last_send_at = 0.0


def _throttle():
    global _last_send_at
    with _throttle_lock:
        wait = _MIN_REQUEST_INTERVAL_SECONDS - (time.monotonic() - _last_send_at)
        if wait > 0:
            time.sleep(wait)
        _last_send_at = time.monotonic()


def _with_project_headers(project, headers):
    """Layer in the project's tool-scoped custom headers (e.g. a bug-bounty
    program's required identification header) without overwriting anything
    already explicitly set on this request, unless the header is marked
    `append_to_existing` (e.g. a UA suffix that must be appended, not
    replace the real User-Agent already on the request)."""
    merged = dict(headers or {})
    existing_lower = {k.lower(): k for k in merged}
    for header in project.custom_headers.filter(apply_to_tool_traffic=True):
        name_lower = header.name.lower()
        if name_lower not in existing_lower:
            merged[header.name] = header.value
        elif header.append_to_existing:
            existing_key = existing_lower[name_lower]
            merged[existing_key] = merged[existing_key] + header.value
    return merged


def strip_nul(value):
    """Postgres text columns reject a raw NUL byte outright — strip it
    rather than let a save() blow up on a response body that happens to
    contain one (rare, but real servers can send it)."""
    return value.replace("\x00", "") if isinstance(value, str) else value


def recalculate_content_length(headers, content: bytes):
    """Like Burp's Repeater/Intruder, always keep Content-Length in sync with
    the actual body being sent — the user edits a body and shouldn't have to
    remember to fix this header by hand (a stale value causes truncated or
    hung requests). Public so callers can also reflect the recalculated
    value back in what they display/store, not just what's sent on the wire.
    """
    headers = {k: v for k, v in headers.items() if k.lower() != "content-length"}
    headers["Content-Length"] = str(len(content))
    return headers


def send_request(project, method, url, headers=None, body=None, timeout=15.0, throttle=True):
    if not is_in_scope(project, url):
        raise OutOfScopeError(f"'{url}' is not in the '{project.name}' project scope")

    content = body.encode() if isinstance(body, str) else (body or b"")
    headers = _with_project_headers(project, headers)
    headers = recalculate_content_length(headers, content)

    # Skippable for callers that already pace themselves (the crawler has
    # its own configurable, jittered rate limiter) — without this, this
    # blanket 1 req/s floor silently overrides a faster user-configured
    # crawl rate instead of just acting as the safety net it's meant to be
    # for Repeater/Intruder/Active Scanner, which have no pacing of their own.
    if throttle:
        _throttle()

    # This is a security-testing tool: it's expected to hit self-signed/
    # invalid certs on test targets, so certificate verification is
    # intentionally disabled here, the same way Burp/ZAP behave by default.
    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False) as client:
        response = client.request(method, url, headers=headers, content=content)
    return response
