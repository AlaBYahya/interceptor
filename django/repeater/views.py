from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render
from django.utils import timezone

from core.models import Project
from core.scope import OutOfScopeError
from core.senders import recalculate_content_length, send_request
from traffic.models import Flow

from .headers_text import headers_to_text, text_to_headers
from .models import RepeaterEntry


@login_required
def new_from_flow(request, flow_pk):
    project = Project.get_active()
    flow = get_object_or_404(Flow, pk=flow_pk, project=project)

    entry = RepeaterEntry.objects.create(
        project=project,
        source_flow=flow,
        label=f"{flow.method} {flow.host}",
        method=flow.method,
        url=flow.url,
        headers=flow.request_headers,
        body="" if flow.request_body_is_base64 else flow.request_body,
    )
    return redirect("repeater:detail", pk=entry.pk)


@login_required
def list_view(request):
    project = Project.get_active()
    entries = RepeaterEntry.objects.filter(project=project)
    return render(request, "repeater/list.html", {"entries": entries})


@login_required
def detail(request, pk):
    project = Project.get_active()
    entry = get_object_or_404(RepeaterEntry, pk=pk, project=project)

    if request.method == "POST":
        entry.method = request.POST.get("method", "GET").strip().upper()
        entry.url = request.POST.get("url", "").strip()
        entry.body = request.POST.get("body", "")
        # Recalculated here too (not just inside send_request) so the header
        # shown back in the editor after sending matches what was actually
        # sent on the wire, same as Burp's Repeater.
        entry.headers = recalculate_content_length(
            text_to_headers(request.POST.get("headers_text", "")), entry.body.encode()
        )
        entry.save()

        try:
            response = send_request(project, entry.method, entry.url, headers=entry.headers, body=entry.body)
            entry.response_status = response.status_code
            entry.response_headers = dict(response.headers)
            entry.response_body = response.text
            entry.error = ""
        except OutOfScopeError as exc:
            entry.error = str(exc)
            messages.error(request, str(exc))
        except Exception as exc:  # noqa: BLE001 — surface any send failure to the user
            entry.error = str(exc)
            messages.error(request, f"Request failed: {exc}")
        entry.sent_at = timezone.now()
        entry.save()
        return redirect("repeater:detail", pk=entry.pk)

    return render(
        request,
        "repeater/detail.html",
        {"entry": entry, "headers_text": headers_to_text(entry.headers)},
    )
