"""Export/import an entire project — every model across every app that
hangs off it (flows, findings, vulnerabilities, scope, custom headers,
technologies, repeater/intruder/toolbox/crawl data) — as one JSON document.
For backup, transfer between Interceptor instances, or archiving a
finished engagement.

Import always creates a NEW Project and remaps every internal ID (Flow,
IntruderAttack) as objects are recreated, in dependency order, rather than
reusing the original primary keys — reusing PKs directly would either
collide with unrelated existing data or silently overwrite it.
"""

from django.utils.dateparse import parse_datetime

from intruder.models import IntruderAttack, IntruderResult
from repeater.models import RepeaterEntry
from scanner.models import ActiveScanJob, Finding, Technology, Vulnerability
from toolbox.models import ScanJob
from traffic.models import CrawlJob, DiscoveredEndpoint, Flow

from .models import CustomHeader, Project, ScopeEntry

EXPORT_VERSION = 1


def _dt(value):
    return value.isoformat() if value else None


def export_project(project):
    flows = list(Flow.objects.filter(project=project))

    data = {
        "interceptor_export_version": EXPORT_VERSION,
        "project": {
            "name": project.name,
            "description": project.description,
            "capture_mode": project.capture_mode,
        },
        "scope_entries": [{"pattern": e.pattern, "note": e.note} for e in project.scope_entries.all()],
        "custom_headers": [
            {
                "name": h.name,
                "value": h.value,
                "apply_to_proxy_traffic": h.apply_to_proxy_traffic,
                "apply_to_tool_traffic": h.apply_to_tool_traffic,
            }
            for h in project.custom_headers.all()
        ],
        "flows": [
            {
                "id": f.id,
                "method": f.method,
                "url": f.url,
                "host": f.host,
                "request_headers": f.request_headers,
                "request_body": f.request_body,
                "request_body_is_base64": f.request_body_is_base64,
                "status_code": f.status_code,
                "response_headers": f.response_headers,
                "response_body": f.response_body,
                "response_body_is_base64": f.response_body_is_base64,
                "client_ip": f.client_ip,
                "duration_ms": f.duration_ms,
                "timestamp": _dt(f.timestamp),
                "note": f.note,
                "review_status": f.review_status,
            }
            for f in flows
        ],
        "discovered_endpoints": [
            {"host": e.host, "path": e.path, "source_flow_id": e.source_flow_id}
            for e in DiscoveredEndpoint.objects.filter(project=project)
        ],
        "crawl_jobs": [
            {
                "seed_url": j.seed_url,
                "max_pages": j.max_pages,
                "requests_per_second": j.requests_per_second,
                "concurrency": j.concurrency,
                "status": j.status,
                "pages_visited": j.pages_visited,
            }
            for j in CrawlJob.objects.filter(project=project)
        ],
        "repeater_entries": [
            {
                "source_flow_id": r.source_flow_id,
                "label": r.label,
                "method": r.method,
                "url": r.url,
                "headers": r.headers,
                "body": r.body,
                "response_status": r.response_status,
                "response_headers": r.response_headers,
                "response_body": r.response_body,
                "error": r.error,
                "sent_at": _dt(r.sent_at),
            }
            for r in RepeaterEntry.objects.filter(project=project)
        ],
        "intruder_attacks": [
            {
                "source_flow_id": a.source_flow_id,
                "label": a.label,
                "method": a.method,
                "url": a.url,
                "headers": a.headers,
                "body": a.body,
                "attack_type": a.attack_type,
                "payload_set": a.payload_set,
                "status": a.status,
                "results": [
                    {
                        "payload": r.payload,
                        "request_url": r.request_url,
                        "request_headers": r.request_headers,
                        "request_body": r.request_body,
                        "status_code": r.status_code,
                        "length": r.length,
                        "duration_ms": r.duration_ms,
                        "response_headers": r.response_headers,
                        "response_body": r.response_body,
                        "error": r.error,
                        "is_anomaly": r.is_anomaly,
                    }
                    for r in a.results.all()
                ],
            }
            for a in IntruderAttack.objects.filter(project=project)
        ],
        "active_scan_jobs": [
            {"target": j.target, "checks": j.checks, "status": j.status}
            for j in ActiveScanJob.objects.filter(project=project)
        ],
        "technologies": [
            {"host": t.host, "name": t.name, "version": t.version, "source_flow_id": t.source_flow_id}
            for t in Technology.objects.filter(project=project)
        ],
        "scan_jobs": [
            {
                "tool": j.tool,
                "target": j.target,
                "query": j.query,
                "args": j.args,
                "status": j.status,
                "raw_output": j.raw_output,
            }
            for j in ScanJob.objects.filter(project=project)
        ],
        "findings": [
            {
                "flow_id": f.flow_id,
                "source": f.source,
                "severity": f.severity,
                "title": f.title,
                "description": f.description,
                "host": f.host,
                "is_structural": f.is_structural,
                "review_status": f.review_status,
            }
            for f in Finding.objects.filter(project=project)
        ],
        "vulnerabilities": [
            {
                "title": v.title,
                "severity": v.severity,
                "description": v.description,
                "flow_ids": list(v.flows.values_list("id", flat=True)),
            }
            for v in Vulnerability.objects.filter(project=project)
        ],
    }
    return data


def _unique_name(base_name):
    name = base_name
    n = 1
    while Project.objects.filter(name=name).exists():
        n += 1
        name = f"{base_name} ({n})"
    return name


def import_project(data):
    if data.get("interceptor_export_version") != EXPORT_VERSION:
        raise ValueError("Unrecognized or missing export version — this doesn't look like an Interceptor project export.")

    project_data = data.get("project", {})
    project = Project.objects.create(
        name=_unique_name(project_data.get("name", "Imported project")),
        description=project_data.get("description", ""),
        capture_mode=project_data.get("capture_mode", Project.CAPTURE_ALL),
    )

    for e in data.get("scope_entries", []):
        ScopeEntry.objects.create(project=project, pattern=e["pattern"], note=e.get("note", ""))

    for h in data.get("custom_headers", []):
        CustomHeader.objects.create(
            project=project,
            name=h["name"],
            value=h["value"],
            apply_to_proxy_traffic=h.get("apply_to_proxy_traffic", True),
            apply_to_tool_traffic=h.get("apply_to_tool_traffic", True),
        )

    flow_id_map = {}
    for f in data.get("flows", []):
        new_flow = Flow.objects.create(
            project=project,
            method=f["method"],
            url=f["url"],
            host=f["host"],
            request_headers=f.get("request_headers") or {},
            request_body=f.get("request_body", ""),
            request_body_is_base64=f.get("request_body_is_base64", False),
            status_code=f.get("status_code"),
            response_headers=f.get("response_headers") or {},
            response_body=f.get("response_body", ""),
            response_body_is_base64=f.get("response_body_is_base64", False),
            client_ip=f.get("client_ip"),
            duration_ms=f.get("duration_ms"),
            note=f.get("note", ""),
            review_status=f.get("review_status", "unreviewed"),
        )
        if f.get("timestamp"):
            new_flow.timestamp = parse_datetime(f["timestamp"])
            new_flow.save(update_fields=["timestamp"])
        flow_id_map[f["id"]] = new_flow

    def flow(old_id):
        return flow_id_map.get(old_id) if old_id is not None else None

    for e in data.get("discovered_endpoints", []):
        DiscoveredEndpoint.objects.get_or_create(
            project=project, host=e["host"], path=e["path"], defaults={"source_flow": flow(e.get("source_flow_id"))}
        )

    for j in data.get("crawl_jobs", []):
        CrawlJob.objects.create(
            project=project,
            seed_url=j["seed_url"],
            max_pages=j.get("max_pages", 100),
            requests_per_second=j.get("requests_per_second", 1.0),
            concurrency=j.get("concurrency", 1),
            status=j.get("status", "done"),
            pages_visited=j.get("pages_visited", 0),
        )

    for r in data.get("repeater_entries", []):
        RepeaterEntry.objects.create(
            project=project,
            source_flow=flow(r.get("source_flow_id")),
            label=r.get("label", ""),
            method=r.get("method", "GET"),
            url=r["url"],
            headers=r.get("headers") or {},
            body=r.get("body", ""),
            response_status=r.get("response_status"),
            response_headers=r.get("response_headers") or {},
            response_body=r.get("response_body", ""),
            error=r.get("error", ""),
            sent_at=parse_datetime(r["sent_at"]) if r.get("sent_at") else None,
        )

    for a in data.get("intruder_attacks", []):
        attack = IntruderAttack.objects.create(
            project=project,
            source_flow=flow(a.get("source_flow_id")),
            label=a.get("label", ""),
            method=a.get("method", "GET"),
            url=a["url"],
            headers=a.get("headers") or {},
            body=a.get("body", ""),
            attack_type=a.get("attack_type", "sniper"),
            payload_set=a.get("payload_set", ""),
            status=a.get("status", "done"),
        )
        for r in a.get("results", []):
            IntruderResult.objects.create(
                attack=attack,
                payload=r["payload"],
                request_url=r.get("request_url", ""),
                request_headers=r.get("request_headers") or {},
                request_body=r.get("request_body", ""),
                status_code=r.get("status_code"),
                length=r.get("length"),
                duration_ms=r.get("duration_ms"),
                response_headers=r.get("response_headers") or {},
                response_body=r.get("response_body", ""),
                error=r.get("error", ""),
                is_anomaly=r.get("is_anomaly", False),
            )

    for j in data.get("active_scan_jobs", []):
        ActiveScanJob.objects.create(
            project=project, target=j["target"], checks=j.get("checks") or [], status=j.get("status", "done")
        )

    for t in data.get("technologies", []):
        Technology.objects.get_or_create(
            project=project,
            host=t["host"],
            name=t["name"],
            defaults={"version": t.get("version", ""), "source_flow": flow(t.get("source_flow_id"))},
        )

    for j in data.get("scan_jobs", []):
        ScanJob.objects.create(
            project=project,
            tool=j["tool"],
            target=j.get("target", ""),
            query=j.get("query", ""),
            args=j.get("args") or [],
            status=j.get("status", "done"),
            raw_output=j.get("raw_output", ""),
        )

    for f in data.get("findings", []):
        Finding.objects.create(
            project=project,
            flow=flow(f.get("flow_id")),
            source=f.get("source", "passive"),
            severity=f.get("severity", "info"),
            title=f["title"],
            description=f.get("description", ""),
            host=f.get("host", ""),
            is_structural=f.get("is_structural", False),
            review_status=f.get("review_status", "unreviewed"),
        )

    for v in data.get("vulnerabilities", []):
        vuln = Vulnerability.objects.create(
            project=project, title=v["title"], severity=v.get("severity", "medium"), description=v.get("description", "")
        )
        flow_objs = [flow_id_map[old_id] for old_id in v.get("flow_ids", []) if old_id in flow_id_map]
        if flow_objs:
            vuln.flows.set(flow_objs)

    return project
