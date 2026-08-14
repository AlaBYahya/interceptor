import csv
from urllib.parse import urlencode

from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.http import HttpResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.http import require_POST

from core.models import Project
from core.scope import is_in_scope

from .active_checks import CHECK_LABELS
from .models import FINDING_REVIEW_STATUS_CHOICES, SEVERITY_ORDER, ActiveScanJob, Finding, Technology
from .tasks import run_active_scan


def _filtered_findings(request, project):
    qs = Finding.objects.filter(project=project).select_related("flow")
    severity = request.GET.get("severity", "").strip()
    source = request.GET.get("source", "").strip()
    review_status = request.GET.get("review_status", "").strip()
    scope_only = request.GET.get("scope_only") == "1"
    if severity:
        qs = qs.filter(severity=severity)
    if source:
        qs = qs.filter(source=source)
    if review_status:
        qs = qs.filter(review_status=review_status)
    if scope_only:
        # Findings survive their source Flow being deleted (Finding.flow is
        # SET_NULL, deliberately — see the model docstring), so a project
        # whose capture_mode was "all" for a while can accumulate findings
        # for hosts that were never actually in scope, with nothing left to
        # filter them by except this. Scope entries fetched once here
        # rather than per-row inside is_in_scope - a real N+1 otherwise,
        # verified on the equivalent Traffic history filter (158 rows ->
        # 164 queries vs. 5 without the caching).
        scope_entries = list(project.scope_entries.values_list("pattern", "exclude"))
        in_scope_ids = [f.id for f in qs if is_in_scope(project, f.host, entries=scope_entries)]
        qs = qs.filter(id__in=in_scope_ids)
    return qs, {"severity": severity, "source": source, "review_status": review_status, "scope_only": scope_only}


@login_required
def findings(request):
    project = Project.get_active()
    qs, filters = _filtered_findings(request, project)

    per_page = request.GET.get("per_page", "50")
    if per_page not in ("25", "50", "100"):
        per_page = "50"
    paginator = Paginator(qs, int(per_page))
    page_obj = paginator.get_page(request.GET.get("page"))

    page_params = {k: v for k, v in filters.items() if v and k != "scope_only"}
    if filters["scope_only"]:
        page_params["scope_only"] = "1"
    prev_url = "?" + urlencode({**page_params, "page": page_obj.previous_page_number()}) if page_obj.has_previous() else None
    next_url = "?" + urlencode({**page_params, "page": page_obj.next_page_number()}) if page_obj.has_next() else None
    per_page_urls = {
        n: "?" + urlencode({**page_params, "per_page": n}) for n in ("25", "50", "100")
    }

    return render(
        request,
        "scanner/findings.html",
        {
            "findings": page_obj.object_list,
            "filters": filters,
            "page_obj": page_obj,
            "prev_url": prev_url,
            "next_url": next_url,
            "per_page": per_page,
            "per_page_urls": per_page_urls,
        },
    )


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
def finding_detail(request, pk):
    project = Project.get_active()
    finding = get_object_or_404(Finding, pk=pk, project=project)
    return render(request, "scanner/finding_detail.html", {"finding": finding})


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
