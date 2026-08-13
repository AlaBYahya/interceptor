import csv

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from core.models import Project

from .active_checks import CHECK_LABELS
from .models import FINDING_REVIEW_STATUS_CHOICES, SEVERITY_ORDER, ActiveScanJob, Finding, Technology
from .tasks import run_active_scan


def _filtered_findings(request, project):
    qs = Finding.objects.filter(project=project).select_related("flow")
    severity = request.GET.get("severity", "").strip()
    source = request.GET.get("source", "").strip()
    review_status = request.GET.get("review_status", "").strip()
    if severity:
        qs = qs.filter(severity=severity)
    if source:
        qs = qs.filter(source=source)
    if review_status:
        qs = qs.filter(review_status=review_status)
    return qs, {"severity": severity, "source": source, "review_status": review_status}


@login_required
def findings(request):
    project = Project.get_active()
    qs, filters = _filtered_findings(request, project)
    return render(request, "scanner/findings.html", {"findings": qs[:500], "filters": filters})


@login_required
def export_findings(request):
    project = Project.get_active()
    qs, _ = _filtered_findings(request, project)
    findings_list = sorted(qs, key=lambda f: -SEVERITY_ORDER[f.severity])
    fmt = request.GET.get("format", "csv")

    if fmt == "markdown":
        lines = [f"# Findings — {project.name}", ""]
        for f in findings_list:
            lines.append(f"## [{f.severity.upper()}] {f.title}")
            lines.append(f"- Source: {f.source}")
            lines.append(f"- Triage: {f.get_review_status_display()}")
            if f.flow:
                lines.append(f"- Request: {f.flow.method} {f.flow.url}")
            lines.append(f"- Found: {f.created_at:%Y-%m-%d %H:%M}")
            if f.description:
                lines.append("")
                lines.append(f.description)
            lines.append("")
        response = HttpResponse("\n".join(lines), content_type="text/markdown")
        response["Content-Disposition"] = f'attachment; filename="{project.name}-findings.md"'
        return response

    response = HttpResponse(content_type="text/csv")
    response["Content-Disposition"] = f'attachment; filename="{project.name}-findings.csv"'
    writer = csv.writer(response)
    writer.writerow(["Severity", "Title", "Source", "Request", "Description", "Triage", "Found At"])
    for f in findings_list:
        writer.writerow([
            f.severity,
            f.title,
            f.source,
            f"{f.flow.method} {f.flow.url}" if f.flow else "",
            f.description,
            f.get_review_status_display(),
            f.created_at.strftime("%Y-%m-%d %H:%M"),
        ])
    return response


@login_required
@require_POST
def finding_update(request, pk):
    project = Project.get_active()
    finding = get_object_or_404(Finding, pk=pk, project=project)

    status = request.POST.get("review_status")
    if status in dict(FINDING_REVIEW_STATUS_CHOICES):
        finding.review_status = status
        finding.save(update_fields=["review_status"])
        messages.success(request, "Updated.")

    next_url = request.POST.get("next")
    return redirect(next_url) if next_url else redirect("scanner:findings")


@login_required
def technologies(request):
    project = Project.get_active()
    techs = Technology.objects.filter(project=project)

    by_host = {}
    for tech in techs:
        by_host.setdefault(tech.host, []).append(tech)

    return render(request, "scanner/technologies.html", {"by_host": sorted(by_host.items())})


@login_required
def active_scan(request):
    project = Project.get_active()

    if request.method == "POST":
        target = request.POST.get("target", "").strip()
        checks = [c for c in request.POST.getlist("checks") if c in CHECK_LABELS]
        if not target:
            messages.error(request, "Enter a target URL.")
        elif not checks:
            messages.error(request, "Select at least one check.")
        else:
            job = ActiveScanJob.objects.create(project=project, target=target, checks=checks, status="pending")
            run_active_scan.delay(job.pk)
            messages.success(request, f"Active scan started against {target}.")
        return redirect("scanner:active_scan")

    jobs = ActiveScanJob.objects.filter(project=project)
    return render(
        request,
        "scanner/active_scan.html",
        {
            "jobs": jobs,
            "check_labels": CHECK_LABELS,
            "prefill_target": request.GET.get("target", ""),
            "has_active_job": jobs.filter(status__in=["pending", "running"]).exists(),
        },
    )
