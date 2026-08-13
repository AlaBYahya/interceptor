from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.shortcuts import get_object_or_404, redirect, render

from core.models import Project

from .crawler import run_crawl
from .models import CrawlJob


@login_required
def crawler_list(request):
    project = Project.get_active()

    if request.method == "POST":
        seed_url = request.POST.get("seed_url", "").strip()
        try:
            max_pages = int(request.POST.get("max_pages") or 100)
            requests_per_second = float(request.POST.get("requests_per_second") or 1.0)
            concurrency = int(request.POST.get("concurrency") or 1)
        except ValueError:
            messages.error(request, "Invalid number in one of the fields.")
            return redirect("traffic:crawler")

        max_pages = max(1, min(max_pages, 5000))
        requests_per_second = max(0.1, min(requests_per_second, 50))
        concurrency = max(1, min(concurrency, 20))

        if not seed_url:
            messages.error(request, "Enter a seed URL to start crawling from.")
        else:
            job = CrawlJob.objects.create(
                project=project,
                seed_url=seed_url,
                max_pages=max_pages,
                requests_per_second=requests_per_second,
                concurrency=concurrency,
                status="pending",
            )
            run_crawl.delay(job.pk)
            messages.success(
                request,
                f"Crawl started from {seed_url} (max {max_pages} pages, "
                f"{requests_per_second}/s across {concurrency} worker(s)).",
            )
        return redirect("traffic:crawler")

    jobs = CrawlJob.objects.filter(project=project)
    return render(
        request,
        "traffic/crawler.html",
        {
            "jobs": jobs,
            "prefill_seed": request.GET.get("seed", ""),
            "has_active_job": jobs.filter(status__in=["pending", "running"]).exists(),
        },
    )


@login_required
def crawler_stop(request, pk):
    project = Project.get_active()
    job = get_object_or_404(CrawlJob, pk=pk, project=project)
    job.stop_requested = True
    job.save(update_fields=["stop_requested"])
    messages.success(request, "Stop requested — the crawl will wind down within a few requests.")
    return redirect("traffic:crawler")
