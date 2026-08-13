from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from core.models import Project
from traffic.models import Flow

from .models import Vulnerability


@login_required
def vulnerabilities_list(request):
    project = Project.get_active()

    if request.method == "POST":
        title = request.POST.get("title", "").strip()
        if not title:
            messages.error(request, "Enter a name for the vulnerability.")
        else:
            vuln = Vulnerability.objects.create(project=project, title=title)
            return redirect("scanner:vulnerability_detail", pk=vuln.pk)
        return redirect("scanner:vulnerabilities")

    vulns = Vulnerability.objects.filter(project=project).prefetch_related("flows")
    return render(request, "scanner/vulnerabilities.html", {"vulns": vulns})


@login_required
def vulnerability_detail(request, pk):
    project = Project.get_active()
    vuln = get_object_or_404(Vulnerability, pk=pk, project=project)

    if request.method == "POST":
        vuln.title = request.POST.get("title", vuln.title).strip() or vuln.title
        severity = request.POST.get("severity", vuln.severity)
        if severity in dict(Vulnerability._meta.get_field("severity").choices):
            vuln.severity = severity
        vuln.description = request.POST.get("description", "")
        vuln.save()
        messages.success(request, "Saved.")
        return redirect("scanner:vulnerability_detail", pk=vuln.pk)

    return render(request, "scanner/vulnerability_detail.html", {"vuln": vuln, "flows": vuln.flows.all()})


@login_required
@require_POST
def vulnerability_delete(request, pk):
    project = Project.get_active()
    vuln = get_object_or_404(Vulnerability, pk=pk, project=project)
    vuln.delete()
    messages.success(request, "Deleted.")
    return redirect("scanner:vulnerabilities")


@login_required
@require_POST
def vulnerability_remove_flow(request, pk, flow_pk):
    project = Project.get_active()
    vuln = get_object_or_404(Vulnerability, pk=pk, project=project)
    vuln.flows.remove(flow_pk)
    return redirect("scanner:vulnerability_detail", pk=vuln.pk)


@login_required
@require_POST
def flow_save_to_vulnerability(request, flow_pk):
    project = Project.get_active()
    flow = get_object_or_404(Flow, pk=flow_pk, project=project)

    existing_id = request.POST.get("existing_vuln")
    new_title = request.POST.get("new_vuln_title", "").strip()

    if existing_id:
        vuln = get_object_or_404(Vulnerability, pk=existing_id, project=project)
    elif new_title:
        vuln = Vulnerability.objects.create(project=project, title=new_title)
    else:
        messages.error(request, "Pick an existing vulnerability or name a new one.")
        return redirect("traffic:flow_detail", pk=flow.pk)

    vuln.flows.add(flow)
    messages.success(request, f"Saved to '{vuln.title}'.")
    return redirect("scanner:vulnerability_detail", pk=vuln.pk)


def _format_flow_evidence(flow, max_len=2000):
    def trim(text):
        text = text or ""
        return text if len(text) <= max_len else text[:max_len] + f"\n... (truncated, see flow #{flow.pk} in Interceptor for the full body)"

    req_headers = "\n".join(f"{k}: {v}" for k, v in flow.request_headers.items())
    resp_headers = "\n".join(f"{k}: {v}" for k, v in flow.response_headers.items())
    return (
        f"**Request** (flow #{flow.pk}):\n"
        f"```\n{flow.method} {flow.url}\n{req_headers}\n\n{trim(flow.request_body)}\n```\n\n"
        f"**Response** ({flow.status_code}):\n"
        f"```\n{resp_headers}\n\n{trim(flow.response_body)}\n```\n"
    )


@login_required
def export_vulnerabilities(request):
    project = Project.get_active()
    vulns = Vulnerability.objects.filter(project=project).prefetch_related("flows")

    lines = [f"# Vulnerabilities — {project.name}", ""]
    for vuln in vulns:
        lines.append(f"## [{vuln.severity.upper()}] {vuln.title}")
        lines.append(f"_Last updated: {vuln.updated_at:%Y-%m-%d %H:%M}_")
        lines.append("")
        if vuln.description:
            lines.append(vuln.description)
            lines.append("")
        flows = list(vuln.flows.all())
        if flows:
            lines.append("### Evidence")
            lines.append("")
            for flow in flows:
                lines.append(_format_flow_evidence(flow))
        lines.append("---")
        lines.append("")

    response = HttpResponse("\n".join(lines), content_type="text/markdown")
    response["Content-Disposition"] = f'attachment; filename="{project.name}-vulnerabilities.md"'
    return response
