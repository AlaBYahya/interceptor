from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.shortcuts import get_object_or_404, redirect, render

from core.models import Project
from repeater.headers_text import headers_to_text, text_to_headers
from traffic.models import Flow

from .markers import auto_mark_form_body, auto_mark_url, count_points
from .models import IntruderAttack
from .payload_generators import GENERATOR_LABELS, generate_payloads
from .tasks import run_intruder_attack

RESULT_SORT_FIELDS = {
    "payload": "payload",
    "status": "status_code",
    "length": "length",
    "time": "duration_ms",
}


@login_required
def list_view(request):
    project = Project.get_active()
    attacks = IntruderAttack.objects.filter(project=project)
    return render(request, "intruder/list.html", {"attacks": attacks})


@login_required
def new_from_flow(request, flow_pk):
    project = Project.get_active()
    flow = get_object_or_404(Flow, pk=flow_pk, project=project)

    body = "" if flow.request_body_is_base64 else flow.request_body
    content_type = next((v for k, v in flow.request_headers.items() if k.lower() == "content-type"), "")

    attack = IntruderAttack.objects.create(
        project=project,
        source_flow=flow,
        label=f"{flow.method} {flow.host}",
        method=flow.method,
        # Auto-mark likely insertion points (UUID/numeric path segments,
        # query param values, form-body values) so the common case works
        # without the user having to hand-type §markers§ first.
        url=auto_mark_url(flow.url),
        headers=flow.request_headers,
        body=auto_mark_form_body(body, content_type),
    )
    return redirect("intruder:detail", pk=attack.pk)


@login_required
def detail(request, pk):
    project = Project.get_active()
    attack = get_object_or_404(IntruderAttack, pk=pk, project=project)

    if request.method == "POST":
        intent = request.POST.get("intent", "start")

        if intent in ("generate", "upload"):
            append = request.POST.get("append") == "on"
            existing = [line for line in attack.payload_set.splitlines() if line != ""] if append else []

            if intent == "generate":
                new_payloads = generate_payloads(request.POST)
                if new_payloads is None:
                    messages.error(request, "Could not generate payloads — check the parameters (and the 10,000 cap).")
                    return redirect("intruder:detail", pk=attack.pk)
            else:
                uploaded = request.FILES.get("payload_file")
                if not uploaded:
                    messages.error(request, "Choose a file to upload.")
                    return redirect("intruder:detail", pk=attack.pk)
                text = uploaded.read().decode("utf-8", errors="replace").replace("\x00", "")
                new_payloads = [line for line in text.splitlines() if line != ""]

            attack.payload_set = "\n".join(existing + new_payloads)
            attack.save(update_fields=["payload_set"])
            messages.success(request, f"{'Generated' if intent == 'generate' else 'Loaded'} {len(new_payloads)} payload(s).")
            return redirect("intruder:detail", pk=attack.pk)

        attack.method = request.POST.get("method", "GET").strip().upper()
        attack.url = request.POST.get("url", "").strip()
        attack.headers = text_to_headers(request.POST.get("headers_text", ""))
        attack.body = request.POST.get("body", "")
        attack.payload_set = request.POST.get("payload_set", "")

        headers_text = headers_to_text(attack.headers)
        total_points = count_points(attack.url) + count_points(headers_text) + count_points(attack.body)
        payload_lines = [line for line in attack.payload_set.splitlines() if line != ""]

        if total_points == 0:
            messages.error(request, "Mark at least one insertion point first, e.g. wrap a value in §payload§.")
            attack.save()
        elif not payload_lines:
            messages.error(request, "Add at least one payload (one per line).")
            attack.save()
        else:
            attack.status = "pending"
            attack.save()
            attack.results.all().delete()
            run_intruder_attack.delay(attack.pk)
            total_requests = total_points * len(payload_lines)
            messages.success(
                request,
                f"Attack started: {total_points} insertion point(s) x {len(payload_lines)} payload(s) = {total_requests} requests.",
            )
        return redirect("intruder:detail", pk=attack.pk)

    results = attack.results.all()

    q = request.GET.get("q", "").strip()
    if q:
        results = results.filter(Q(payload__icontains=q) | Q(response_body__icontains=q))

    sort = request.GET.get("sort", "")
    direction = request.GET.get("dir", "asc")
    if sort in RESULT_SORT_FIELDS:
        order_field = RESULT_SORT_FIELDS[sort]
        results = results.order_by(order_field if direction == "asc" else f"-{order_field}")

    base_params = {"q": q} if q else {}
    sort_urls, sort_arrows = {}, {}
    for col in RESULT_SORT_FIELDS:
        next_dir = "desc" if (sort == col and direction == "asc") else "asc"
        sort_urls[col] = "?" + urlencode({**base_params, "sort": col, "dir": next_dir})
        sort_arrows[col] = ("▲" if direction == "asc" else "▼") if sort == col else ""

    selected_result = None
    selected_id = request.GET.get("result")
    if selected_id:
        selected_result = attack.results.filter(pk=selected_id).first()

    return render(
        request,
        "intruder/detail.html",
        {
            "attack": attack,
            "headers_text": headers_to_text(attack.headers),
            "results": results,
            "generator_labels": GENERATOR_LABELS,
            "filters": {"q": q},
            "sort_urls": sort_urls,
            "sort_arrows": sort_arrows,
            "selected_result": selected_result,
        },
    )
