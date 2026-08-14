import re

from celery import shared_task

from core.scope import is_in_scope
from traffic.models import Flow

from . import passive_checks, tech_detection
from .active_checks import CHECK_FUNCTIONS
from .models import ActiveScanJob, Finding, Technology

# Same trimming logic proven necessary for nmap-derived versions (see
# toolbox/tasks.py::_parse_nmap_xml) — searchsploit's search is a plain
# substring match, so an overly specific version string matches nothing.
_VERSION_RE = re.compile(r"\d+(?:\.\d+){0,2}")


def _queue_searchsploit(project, name, version, host=""):
    from toolbox.models import ScanJob
    from toolbox.tasks import run_searchsploit

    version_match = _VERSION_RE.match(version)
    if not version_match:
        return
    query = f"{name} {version_match.group(0)}"
    if ScanJob.objects.filter(project=project, tool="searchsploit", query=query).exists():
        return
    job = ScanJob.objects.create(project=project, tool="searchsploit", query=query, target=host, status="pending")
    run_searchsploit.delay(job.pk)


@shared_task
def run_passive_checks(flow_id):
    flow = Flow.objects.filter(id=flow_id).first()
    if flow is None:
        return

    for finding in passive_checks.run_structural(flow):
        severity = finding.pop("severity")
        description = finding.pop("description")
        Finding.objects.get_or_create(
            project=flow.project,
            source="passive",
            title=finding["title"],
            host=flow.host,
            is_structural=True,
            defaults={"flow": flow, "severity": severity, "description": description},
        )

    for finding in passive_checks.run_per_request(flow):
        Finding.objects.create(project=flow.project, flow=flow, host=flow.host, source="passive", **finding)

    # JS endpoint discovery and technology fingerprinting piggyback on the
    # same signal since they inspect the same already-captured response.
    from traffic.js_endpoints import maybe_extract_endpoints

    maybe_extract_endpoints(flow)

    for name, version in tech_detection.run_all(flow):
        tech, created = Technology.objects.get_or_create(
            project=flow.project, host=flow.host, name=name, defaults={"version": version, "source_flow": flow}
        )
        version_changed = False
        if not created and version and tech.version != version:
            tech.version = version
            tech.source_flow = flow
            tech.save(update_fields=["version", "source_flow"])
            version_changed = True

        # Auto-chain into searchsploit the same way nmap-detected
        # product+version pairs do — only on a genuinely new signal (first
        # detection or a better version), not on every flow that re-detects
        # the same already-known tech.
        if version and (created or version_changed):
            _queue_searchsploit(flow.project, name, version, host=flow.host)


@shared_task
def run_active_scan(job_id):
    """Opt-in active scan: a small curated set of checks (see
    scanner/active_checks.py) against a single scope-checked target."""
    try:
        job = ActiveScanJob.objects.get(id=job_id)
    except ActiveScanJob.DoesNotExist:
        return

    if not is_in_scope(job.project, job.target):
        job.status = "failed"
        job.save(update_fields=["status"])
        return

    job.status = "running"
    job.save(update_fields=["status"])

    for check_name in job.checks:
        check_fn = CHECK_FUNCTIONS.get(check_name)
        if check_fn is None:
            continue
        for finding in check_fn(job.project, job.target):
            Finding.objects.create(project=job.project, flow=None, source="active", **finding)

    job.status = "done"
    job.save(update_fields=["status"])
