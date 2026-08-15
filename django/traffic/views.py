import hmac
import json
from collections import defaultdict
from urllib.parse import urlencode, urlparse

from django.conf import settings
from django.contrib import messages
from django.contrib.auth.decorators import login_required
from django.core.paginator import Paginator
from django.db.models.functions import Length
from django.http import JsonResponse
from django.shortcuts import get_object_or_404, redirect, render
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_POST

from core.models import Project
from core.scope import is_in_scope

from .models import DiscoveredEndpoint, Flow
from .signals import flow_ingested

SORT_FIELDS = {
    "time": "timestamp",
    "method": "method",
    "host": "host",
    "status": "status_code",
    "length": "resp_length",
}


@csrf_exempt
@require_POST
def ingest_flow(request):
    """Called by the mitmproxy addon for every captured flow.

    Machine-to-machine only: authenticated with a shared-secret header
    token (INGEST_TOKEN), not a browser session — see
    core.middleware.LoginRequiredMiddleware's EXEMPT_PREFIXES.
    """
    token = request.headers.get("X-Ingest-Token", "")
    if not settings.INGEST_TOKEN or not hmac.compare_digest(token, settings.INGEST_TOKEN):
        return JsonResponse({"error": "unauthorized"}, status=401)

    try:
        data = json.loads(request.body)
    except json.JSONDecodeError:
        return JsonResponse({"error": "invalid json"}, status=400)

    project = Project.get_active()
    host = data.get("host", "")

    if project.capture_mode == Project.CAPTURE_IN_SCOPE_ONLY and not is_in_scope(project, host):
        # Still proxied through to the real destination either way (that
        # already happened before the addon called us) — this only decides
        # whether Django logs it.
        return JsonResponse({"skipped": "out of scope"}, status=200)

    flow = Flow.objects.create(
        project=project,
        method=data.get("method", ""),
        url=data.get("url", ""),
        host=host,
        request_headers=data.get("request_headers") or {},
        request_body=data.get("request_body", ""),
        request_body_is_base64=bool(data.get("request_body_is_base64")),
        status_code=data.get("status_code"),
        response_headers=data.get("response_headers") or {},
        response_body=data.get("response_body", ""),
        response_body_is_base64=bool(data.get("response_body_is_base64")),
        client_ip=data.get("client_ip") or None,
        duration_ms=data.get("duration_ms"),
    )

    flow_ingested.send(sender=Flow, flow_id=flow.id)

    return JsonResponse({"id": flow.id}, status=201)


@login_required
def history(request):
    project = Project.get_active()
    flows = Flow.objects.filter(project=project)

    q = request.GET.get("q", "").strip()
    method = request.GET.get("method", "").strip()
    status = request.GET.get("status", "").strip()
    scope_only = request.GET.get("scope_only") == "1"
    review_status = request.GET.get("review_status", "").strip()
    severity = request.GET.get("severity", "").strip()

    if q:
        # Matches host, the full URL (path/query/filename), or note text —
        # a filter like "dynamic.config.json" or a word from a note should
        # find it wherever it appears, not just when it's the host.
        from django.db.models import Q

        flows = flows.filter(Q(host__icontains=q) | Q(url__icontains=q) | Q(note__icontains=q))
    if method:
        flows = flows.filter(method__iexact=method)
    if status:
        flows = flows.filter(status_code=status)
    if scope_only:
        scope_entries = list(project.scope_entries.values_list("pattern", "exclude"))
        in_scope_ids = [f.id for f in flows if is_in_scope(project, f.host, entries=scope_entries)]
        flows = flows.filter(id__in=in_scope_ids)
    if review_status:
        flows = flows.filter(review_status=review_status)
    if severity:
        from scanner.models import Finding

        # "has a finding of this severity", not "highest finding equals
        # this severity" — a flow with both a high and a low finding
        # should still show up under the "low" filter, not just "high".
        matching_ids = Finding.objects.filter(project=project, severity=severity, flow_id__isnull=False).values_list(
            "flow_id", flat=True
        )
        flows = flows.filter(id__in=matching_ids)

    sort = request.GET.get("sort", "time")
    direction = request.GET.get("dir", "desc")
    if sort not in SORT_FIELDS:
        sort = "time"
    if direction not in ("asc", "desc"):
        direction = "desc"

    order_field = SORT_FIELDS[sort]
    flows = flows.annotate(resp_length=Length("response_body")).order_by(
        order_field if direction == "asc" else f"-{order_field}"
    )

    per_page = request.GET.get("per_page", "50")
    if per_page not in ("25", "50", "100"):
        per_page = "50"
    paginator = Paginator(flows, int(per_page))
    page_obj = paginator.get_page(request.GET.get("page"))
    flows = list(page_obj.object_list)

    # Column header links: preserve the current filters, flip direction if
    # already sorted by that column, else default to ascending. Changing
    # sort intentionally drops back to page 1 rather than carrying a page
    # number that may not exist under the new ordering's row count.
    base_params = {
        k: v
        for k, v in {"q": q, "method": method, "status": status, "review_status": review_status, "severity": severity}.items()
        if v
    }
    if scope_only:
        base_params["scope_only"] = "1"
    if per_page != "50":
        base_params["per_page"] = per_page

    sort_urls, sort_arrows = {}, {}
    for col in SORT_FIELDS:
        next_dir = "desc" if (sort == col and direction == "asc") else "asc"
        sort_urls[col] = "?" + urlencode({**base_params, "sort": col, "dir": next_dir})
        sort_arrows[col] = ("▲" if direction == "asc" else "▼") if sort == col else ""

    # Pagination links preserve every current filter/sort/per_page choice,
    # only the page number changes.
    page_params = {**base_params, "sort": sort, "dir": direction}
    prev_url = "?" + urlencode({**page_params, "page": page_obj.previous_page_number()}) if page_obj.has_previous() else None
    next_url = "?" + urlencode({**page_params, "page": page_obj.next_page_number()}) if page_obj.has_next() else None
    per_page_urls = {
        n: "?" + urlencode({**{k: v for k, v in page_params.items() if k != "per_page"}, "per_page": n})
        for n in ("25", "50", "100")
    }

    # Attach each flow's highest-severity finding so history rows can be
    # highlighted (out-of-line import to avoid a circular import at app-load
    # time between traffic and scanner).
    from scanner.models import SEVERITY_ORDER, Finding

    severities = {}
    finding_rows = Finding.objects.filter(flow_id__in=[f.id for f in flows]).values_list("flow_id", "severity")
    for flow_id, severity in finding_rows:
        current = severities.get(flow_id)
        if current is None or SEVERITY_ORDER[severity] > SEVERITY_ORDER[current]:
            severities[flow_id] = severity
    for flow in flows:
        flow.finding_severity = severities.get(flow.id)

    return render(
        request,
        "traffic/history.html",
        {
            "project": project,
            "flows": flows,
            "filters": {
                "q": q,
                "method": method,
                "status": status,
                "scope_only": scope_only,
                "review_status": review_status,
                "severity": severity,
            },
            "sort_urls": sort_urls,
            "sort_arrows": sort_arrows,
            "page_obj": page_obj,
            "prev_url": prev_url,
            "next_url": next_url,
            "per_page": per_page,
            "per_page_urls": per_page_urls,
        },
    )


@login_required
def flow_detail(request, pk):
    project = Project.get_active()
    flow = get_object_or_404(Flow, pk=pk, project=project)

    from scanner.models import Vulnerability

    return render(
        request,
        "traffic/flow_detail.html",
        {
            "flow": flow,
            "in_scope": is_in_scope(project, flow.host),
            "vulnerabilities": Vulnerability.objects.filter(project=project),
        },
    )


@login_required
@require_POST
def flow_update(request, pk):
    project = Project.get_active()
    flow = get_object_or_404(Flow, pk=pk, project=project)

    update_fields = []
    if "review_status" in request.POST:
        status = request.POST.get("review_status")
        if status in dict(Flow.REVIEW_STATUS_CHOICES):
            flow.review_status = status
            update_fields.append("review_status")
    if "note" in request.POST:
        flow.note = request.POST.get("note", "")
        update_fields.append("note")

    if update_fields:
        flow.save(update_fields=update_fields)
        messages.success(request, "Updated.")

    next_url = request.POST.get("next")
    return redirect(next_url) if next_url else redirect("traffic:flow_detail", pk=flow.pk)


@login_required
@require_POST
def flow_delete(request, pk):
    project = Project.get_active()
    flow = get_object_or_404(Flow, pk=pk, project=project)
    flow.delete()
    messages.success(request, "Deleted request from history.")
    return redirect("traffic:history")


@login_required
@require_POST
def flow_delete_selected(request):
    project = Project.get_active()
    ids = request.POST.getlist("selected")
    if not ids:
        messages.info(request, "No requests selected.")
    else:
        count, _ = Flow.objects.filter(project=project, id__in=ids).delete()
        messages.success(request, f"Deleted {count} selected request(s).")
    return redirect("traffic:history")


@login_required
@require_POST
def history_clear(request):
    project = Project.get_active()
    count, _ = Flow.objects.filter(project=project).delete()
    messages.success(request, f"Cleared {count} request(s) from history.")
    return redirect("traffic:history")


def _new_tree_node():
    return {
        "children": {},
        "methods": set(),
        "statuses": set(),
        "discovered_only": False,
        "is_leaf": False,
        "severity": None,
        "method_flow_ids": {},
        "method_counts": {},
    }


def _finalize_tree_node(node, name=None, parent_path="", host=""):
    full_path = "/" if name is None else f"{parent_path.rstrip('/')}/{name}"
    children = [
        _finalize_tree_node(child, child_name, full_path, host)
        for child_name, child in sorted(node["children"].items())
    ]

    from scanner.models import SEVERITY_ORDER

    rolled_severity = node["severity"]
    for child in children:
        child_severity = child["rolled_severity"]
        if child_severity and (rolled_severity is None or SEVERITY_ORDER[child_severity] > SEVERITY_ORDER[rolled_severity]):
            rolled_severity = child_severity

    # One entry per method actually seen at this path, carrying the most
    # recent flow's id (for the inline click-through detail panel) and the
    # total count (so multiple hits to the same endpoint show a "+N" link
    # to the full filtered list rather than only ever showing the latest).
    method_entries = [
        {"method": m, "flow_id": node["method_flow_ids"][m], "count": node["method_counts"][m]}
        for m in sorted(node["methods"])
    ]

    return {
        "name": name,
        "full_path": full_path,
        "full_url": f"https://{host}{full_path}",
        "is_leaf": node["is_leaf"],
        "method_entries": method_entries,
        "statuses": sorted(node["statuses"]),
        "discovered_only": node["discovered_only"],
        "own_severity": node["severity"],
        "rolled_severity": rolled_severity,
        "children": children,
    }


@login_required
def sitemap(request):
    """Host -> nested folder tree by path segment, ZAP/Burp "site map"
    style (e.g. /ui/assets/fonts and /ui/assets/img nest under ui > assets).

    Merges paths actually observed in captured traffic with paths that were
    only ever discovered by parsing JavaScript (DiscoveredEndpoint) — those
    show up flagged as not-yet-requested so they're easy to go try. Every
    node shows a risk badge rolled up from any Findings on flows under it
    (ZAP colors Sites-tree nodes by alert risk the same way). Clicking a
    method badge selects that request (?flow=<id>) and shows its full
    request/response in a sticky panel alongside the tree — like ZAP's
    split Sites/Request/Response view — without leaving this page; "view
    all" links still go to the filtered Traffic history list.
    """
    from scanner.models import SEVERITY_ORDER, Finding

    project = Project.get_active()
    scope_only = request.GET.get("scope_only") == "1"
    # Fetched once and threaded through every is_in_scope() call below
    # instead of each one re-querying it fresh — this loop runs once per
    # row across five different querysets, so that difference is a real
    # N+1, not a hypothetical one (same fix as history()'s scope_only).
    scope_entries = list(project.scope_entries.values_list("pattern", "exclude")) if scope_only else None
    flat = defaultdict(
        lambda: defaultdict(
            lambda: {"methods": set(), "statuses": set(), "method_flow_ids": {}, "method_counts": {}}
        )
    )

    # Default Flow ordering is -timestamp (newest first, see Flow.Meta), so
    # the first flow id seen per method below is the most recent one.
    for flow_id, host, url, method, status in Flow.objects.filter(project=project).values_list(
        "id", "host", "url", "method", "status_code"
    ):
        if scope_only and not is_in_scope(project, host, entries=scope_entries):
            continue
        path = urlparse(url).path or "/"
        node = flat[host][path]
        node["methods"].add(method)
        if status:
            node["statuses"].add(status)
        node["method_flow_ids"].setdefault(method, flow_id)
        node["method_counts"][method] = node["method_counts"].get(method, 0) + 1

    observed = {(host, path) for host, paths in flat.items() for path in paths}

    for host, path in DiscoveredEndpoint.objects.filter(project=project).values_list("host", "path"):
        if scope_only and not is_in_scope(project, host, entries=scope_entries):
            continue
        flat[host][path]  # touch to ensure the key exists even with no methods yet

    # Highest finding severity per (host, path), for the leaf's own badge.
    node_severity = {}
    finding_rows = Finding.objects.filter(project=project, flow__isnull=False).values_list(
        "flow__host", "flow__url", "severity"
    )
    for host, url, severity in finding_rows:
        if scope_only and not is_in_scope(project, host, entries=scope_entries):
            continue
        key = (host, urlparse(url).path or "/")
        current = node_severity.get(key)
        if current is None or SEVERITY_ORDER[severity] > SEVERITY_ORDER[current]:
            node_severity[key] = severity

    # Findings with no flow (Active Scanner, nmap, searchsploit, nuclei —
    # anything not tied to one captured request) have no path to attach to,
    # only a host, so they roll up onto that host's root node instead of a
    # specific leaf.
    host_severity = {}
    for host, severity in Finding.objects.filter(project=project, flow__isnull=True).exclude(host="").values_list(
        "host", "severity"
    ):
        if scope_only and not is_in_scope(project, host, entries=scope_entries):
            continue
        current = host_severity.get(host)
        if current is None or SEVERITY_ORDER[severity] > SEVERITY_ORDER[current]:
            host_severity[host] = severity

    for host in host_severity:
        flat[host]  # ensure a host-only-finding host still gets a tree/badge even with nothing else captured

    from scanner.models import Technology

    tech_by_host = defaultdict(list)
    for host, name, version in Technology.objects.filter(project=project).values_list("host", "name", "version"):
        if scope_only and not is_in_scope(project, host, entries=scope_entries):
            continue
        tech_by_host[host].append(f"{name} {version}".strip())

    hosts = []
    for host in sorted(flat):
        root = _new_tree_node()
        root["severity"] = host_severity.get(host)
        for path, data in flat[host].items():
            segments = [s for s in path.split("/") if s]
            node = root
            for segment in segments:
                node = node["children"].setdefault(segment, _new_tree_node())
            node["is_leaf"] = True
            node["methods"] = data["methods"]
            node["statuses"] = data["statuses"]
            node["discovered_only"] = (host, path) not in observed
            node["severity"] = node_severity.get((host, path))
            node["method_flow_ids"] = data["method_flow_ids"]
            node["method_counts"] = data["method_counts"]
        hosts.append(
            {"host": host, "root": _finalize_tree_node(root, host=host), "technologies": sorted(tech_by_host[host])}
        )

    selected_flow = None
    selected_flow_id = request.GET.get("flow")
    if selected_flow_id:
        selected_flow = Flow.objects.filter(project=project, pk=selected_flow_id).first()

    return render(
        request, "traffic/sitemap.html", {"hosts": hosts, "selected_flow": selected_flow, "scope_only": scope_only}
    )
