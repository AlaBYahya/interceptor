from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import redirect, render

from core.models import Project

from .models import ScanJob
from .tasks import NMAP_PROFILES, NUCLEI_DEFAULT_ARGS, run_nmap, run_nuclei, run_nuclei_update, run_searchsploit


def _handle_nmap(request, project):
    target = request.POST.get("target", "").strip()
    profile = request.POST.get("profile", "version")
    if not target:
        messages.error(request, "Enter a target.")
    elif profile not in NMAP_PROFILES:
        messages.error(request, "Unknown scan profile.")
    else:
        job = ScanJob.objects.create(
            project=project, tool="nmap", target=target, args=NMAP_PROFILES[profile], status="pending"
        )
        run_nmap.delay(job.pk)
        messages.success(request, f"nmap scan started against {target} ({profile}).")


def _handle_searchsploit(request, project):
    query = request.POST.get("query", "").strip()
    if not query:
        messages.error(request, "Enter a search query (e.g. a service/version string).")
    else:
        job = ScanJob.objects.create(project=project, tool="searchsploit", query=query, status="pending")
        run_searchsploit.delay(job.pk)
        messages.success(request, f"searchsploit lookup started for '{query}'.")


def _handle_nuclei(request, project):
    target = request.POST.get("target", "").strip()
    if not target:
        messages.error(request, "Enter a target.")
    else:
        job = ScanJob.objects.create(
            project=project, tool="nuclei", target=target, args=NUCLEI_DEFAULT_ARGS, status="pending"
        )
        run_nuclei.delay(job.pk)
        messages.success(request, f"nuclei scan started against {target}.")


def _handle_nuclei_update(request, project):
    job = ScanJob.objects.create(project=project, tool="nuclei_update", status="pending")
    run_nuclei_update.delay(job.pk)
    messages.success(request, "nuclei template update started.")


TOOL_HANDLERS = {
    "nmap": _handle_nmap,
    "searchsploit": _handle_searchsploit,
    "nuclei": _handle_nuclei,
    "nuclei_update": _handle_nuclei_update,
}


@login_required
def list_view(request):
    project = Project.get_active()

    if request.method == "POST":
        tool = request.POST.get("tool", "")
        handler = TOOL_HANDLERS.get(tool)
        if handler is None:
            messages.error(request, "Unknown tool.")
        else:
            handler(request, project)
        return redirect("toolbox:list")

    jobs = ScanJob.objects.filter(project=project)
    return render(
        request,
        "toolbox/list.html",
        {
            "jobs": jobs,
            "nmap_profiles": list(NMAP_PROFILES),
            "prefill_target": request.GET.get("target", ""),
            "has_active_job": jobs.filter(status__in=["pending", "running"]).exists(),
        },
    )


@login_required
def job_detail(request, pk):
    project = Project.get_active()
    job = ScanJob.objects.filter(project=project, pk=pk).first()
    if job is None:
        return redirect("toolbox:list")
    return render(request, "toolbox/job_detail.html", {"job": job})
