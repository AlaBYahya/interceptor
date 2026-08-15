import json
import re
import subprocess
import xml.etree.ElementTree as ET
from urllib.parse import urlparse

from celery import shared_task
from django.utils import timezone

from core.scope import is_in_scope
from scanner.models import Finding

from .models import ScanJob

# Fixed, curated flag sets rather than free-text args from the UI — avoids
# any nmap-flag/argument-injection surface entirely (subprocess.run with a
# list already prevents shell injection via the target string; this closes
# the remaining "what flags get passed" question too).
NMAP_PROFILES = {
    "quick": ["-T4", "-F"],
    "version": ["-sV", "-T4", "--top-ports", "100"],
    "full": ["-sV", "-T4", "-p-"],
}

# Excludes dos/intrusive/fuzz-tagged templates by default — this is meant
# to be a safe opt-in check, not a template-library power-user tool.
# Rate-limited to 10 req/s: nuclei is a subprocess making its own direct
# connections, so it never goes through core.senders.send_request's 1 req/s
# throttle (that only covers Repeater/Intruder/Active Scanner) — nuclei's
# own default is 150 req/s. Verified this matters: an unthrottled run
# against a real target triggered what looked like target-side rate
# limiting/blocking partway through, aborting most of the scan. 10 req/s
# (not 1) because nuclei sweeps thousands of templates per run, where the
# same 1 req/s used elsewhere would turn a scan into a multi-hour job.
NUCLEI_DEFAULT_ARGS = ["-severity", "medium,high,critical", "-etags", "dos,intrusive,fuzz", "-rate-limit", "10"]

NUCLEI_SEVERITY_MAP = {"info": "info", "low": "low", "medium": "medium", "high": "high", "critical": "high"}


def _fail(job, message):
    job.status = "failed"
    job.raw_output = message
    job.finished_at = timezone.now()
    job.save(update_fields=["status", "raw_output", "finished_at"])


@shared_task
def run_nmap(job_id):
    try:
        job = ScanJob.objects.get(id=job_id)
    except ScanJob.DoesNotExist:
        return

    if not is_in_scope(job.project, job.target):
        _fail(job, f"'{job.target}' is not in the '{job.project.name}' project scope.")
        return

    job.status = "running"
    job.save(update_fields=["status"])

    flags = job.args or NMAP_PROFILES["version"]
    cmd = ["nmap", "-oX", "-", *flags, job.target]

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        _fail(job, "nmap timed out after 300s.")
        return
    except FileNotFoundError:
        _fail(job, "nmap is not installed in this container.")
        return

    job.raw_output = result.stdout or result.stderr
    _parse_nmap_xml(job, result.stdout)

    job.status = "done"
    job.finished_at = timezone.now()
    job.save(update_fields=["status", "raw_output", "finished_at"])


def _parse_nmap_xml(job, xml_text):
    if not xml_text:
        return
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError:
        return

    queried = set()  # dedupe searchsploit lookups when the same product/version shows up on multiple ports

    for host_el in root.findall("host"):
        addr_el = host_el.find("address")
        addr = addr_el.get("addr") if addr_el is not None else job.target

        for port_el in host_el.findall("ports/port"):
            state_el = port_el.find("state")
            if state_el is None or state_el.get("state") != "open":
                continue

            portid = port_el.get("portid")
            protocol = port_el.get("protocol")
            service_el = port_el.find("service")
            name = service_el.get("name", "unknown") if service_el is not None else "unknown"
            product = service_el.get("product", "") if service_el is not None else ""
            version = service_el.get("version", "") if service_el is not None else ""
            service_desc = " ".join(p for p in (name, product, version) if p)

            Finding.objects.create(
                project=job.project,
                flow=None,
                source="nmap",
                severity="info",
                title=f"Open port {portid}/{protocol} on {addr}: {name}",
                description=f"nmap detected {service_desc} on {addr}:{portid}/{protocol}.",
                # job.target (the hostname scanned) rather than addr (its
                # resolved IP), so this rolls up onto the same Site Map host
                # node as everything else captured for that domain.
                host=job.target,
            )

            # Auto-chain into searchsploit: a product+version pair is exactly
            # the kind of string that lookup is meant for, and it's a local,
            # network-free lookup, so firing it automatically costs nothing.
            # Trim to major.minor(.patch): searchsploit's search is a plain
            # substring match, and nmap's full version string often carries
            # OS-packaging suffixes (e.g. "6.6.1p1 Ubuntu 2ubuntu2.13") that
            # make the query too specific to match anything, even when a
            # real advisory exists for that release.
            version_match = re.match(r"\d+(?:\.\d+){0,2}", version)
            if product and version_match:
                query = f"{product} {version_match.group(0)}"
                if query not in queried:
                    queried.add(query)
                    ss_job = ScanJob.objects.create(
                        project=job.project, tool="searchsploit", query=query, target=job.target, status="pending"
                    )
                    run_searchsploit.delay(ss_job.pk)


@shared_task
def run_searchsploit(job_id):
    """Local exploit-db lookup by free-text query (service/version string,
    e.g. "apache 2.4.49") — no scope check needed, it never touches the
    network."""
    try:
        job = ScanJob.objects.get(id=job_id)
    except ScanJob.DoesNotExist:
        return

    job.status = "running"
    job.save(update_fields=["status"])

    cmd = ["searchsploit", "--json", job.query]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        _fail(job, "searchsploit timed out after 60s.")
        return
    except FileNotFoundError:
        _fail(job, "searchsploit is not installed in this container.")
        return

    job.raw_output = result.stdout or result.stderr
    _parse_searchsploit_json(job, result.stdout)

    job.status = "done"
    job.finished_at = timezone.now()
    job.save(update_fields=["status", "raw_output", "finished_at"])


def _parse_searchsploit_json(job, output):
    if not output:
        return
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return

    for entry in data.get("RESULTS_EXPLOIT", []):
        title = entry.get("Title", "unknown")
        edb_id = entry.get("EDB-ID", "")
        cve = entry.get("Codes", "")
        Finding.objects.create(
            project=job.project,
            flow=None,
            source="searchsploit",
            severity="info",
            title=f"Exploit-DB match: {title}",
            description=f"EDB-ID {edb_id}{' | ' + cve if cve else ''} — query {job.query!r}.",
            # Only set when this job was auto-chained from nmap/tech-detection
            # (both now pass the originating host through as ScanJob.target);
            # a searchsploit run started directly from the Toolbox UI has no
            # host to attach to, same as before.
            host=job.target,
        )


@shared_task
def run_nuclei(job_id):
    """Template-based vulnerability scan against a single scope-checked
    target, restricted by default to medium+ severity and excluding
    dos/intrusive/fuzz-tagged templates (see NUCLEI_DEFAULT_ARGS) — an
    opt-in safety check, not the full power-user template library."""
    try:
        job = ScanJob.objects.get(id=job_id)
    except ScanJob.DoesNotExist:
        return

    if not is_in_scope(job.project, job.target):
        _fail(job, f"'{job.target}' is not in the '{job.project.name}' project scope.")
        return

    job.status = "running"
    job.save(update_fields=["status"])

    flags = job.args or NUCLEI_DEFAULT_ARGS
    cmd = ["nuclei", "-target", job.target, "-jsonl", "-silent", *flags]

    try:
        # NUCLEI_DEFAULT_ARGS' filter (medium+ severity, no dos/intrusive/
        # fuzz tags) still matches ~7000 templates as of the current
        # nuclei-templates snapshot — at the enforced 10 req/s rate limit
        # that's a ~700s floor just to dispatch one request per template,
        # before accounting for templates that issue more than one. A 600s
        # timeout here guaranteed every default-args scan would time out
        # before finishing, regardless of target (verified against a local,
        # zero-latency target). 3600s leaves real headroom.
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)
    except subprocess.TimeoutExpired:
        _fail(job, "nuclei timed out after 3600s.")
        return
    except FileNotFoundError:
        _fail(job, "nuclei is not installed in this container.")
        return

    job.raw_output = result.stdout or result.stderr
    _parse_nuclei_jsonl(job, result.stdout)

    job.status = "done"
    job.finished_at = timezone.now()
    job.save(update_fields=["status", "raw_output", "finished_at"])


@shared_task
def run_nuclei_update(job_id):
    """Refreshes nuclei's template library in place (`-update-templates`)
    without needing a full `docker compose build worker`. No scope check —
    this talks to the template repo, not a test target."""
    try:
        job = ScanJob.objects.get(id=job_id)
    except ScanJob.DoesNotExist:
        return

    job.status = "running"
    job.save(update_fields=["status"])

    cmd = ["nuclei", "-update-templates"]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    except subprocess.TimeoutExpired:
        _fail(job, "nuclei -update-templates timed out after 300s.")
        return
    except FileNotFoundError:
        _fail(job, "nuclei is not installed in this container.")
        return

    job.raw_output = result.stdout or result.stderr
    job.status = "done"
    job.finished_at = timezone.now()
    job.save(update_fields=["status", "raw_output", "finished_at"])


def _parse_nuclei_jsonl(job, output):
    for line in (output or "").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line)
        except json.JSONDecodeError:
            continue

        info = entry.get("info", {})
        severity = NUCLEI_SEVERITY_MAP.get(info.get("severity", "info"), "info")
        template_id = entry.get("template-id", "")
        matched_at = entry.get("matched-at", job.target)
        Finding.objects.create(
            project=job.project,
            flow=None,
            source="nuclei",
            severity=severity,
            title=f"nuclei: {info.get('name', template_id or 'finding')}",
            description=f"Template '{template_id}' matched at {matched_at}.",
            host=urlparse(matched_at).hostname or job.target,
        )
