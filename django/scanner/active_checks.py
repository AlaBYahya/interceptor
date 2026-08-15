"""Active scanner checks. Unlike scanner/passive_checks.py (pure functions
over already-captured data), these send real requests via
core.senders.send_request — the caller (scanner/tasks.py) is responsible
for the scope check before any of this runs.
"""

import secrets
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

from core.senders import send_request
from traffic.models import DiscoveredEndpoint

SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
]

SQL_ERROR_MARKERS = [
    "SQL syntax",
    "mysql_fetch",
    "Unclosed quotation mark",
    "quoted string not properly terminated",
    "SQLite3::",
    "PostgreSQL query failed",
    "ORA-01756",
    "Microsoft OLE DB Provider for ODBC",
    "pg_query()",
    "Warning: mysql_",
]

SQLI_PROBES = ["'", '"', "' OR '1'='1", "1' AND '1'='2"]

# Small, curated, deliberately not a giant wordlist — this is a quick opt-in
# check, not a dedicated dir-brute tool.
DIR_BRUTE_WORDLIST = [
    "admin",
    "backup",
    "backup.zip",
    "config",
    "config.php",
    ".env",
    ".git/config",
    "robots.txt",
    "sitemap.xml",
    "api",
    "test",
    ".well-known/security.txt",
    "phpinfo.php",
    "server-status",
    ".DS_Store",
    "wp-admin",
    "swagger.json",
]


def _with_query_param(url, key, value):
    parsed = urlparse(url)
    params = dict(parse_qsl(parsed.query))
    params[key] = value
    return urlunparse(parsed._replace(query=urlencode(params)))


def check_headers(project, target):
    host = urlparse(target).hostname or ""
    try:
        response = send_request(project, "GET", target)
    except Exception as exc:  # noqa: BLE001
        return [{"title": "Active headers check failed to send", "severity": "info", "description": str(exc), "host": host}]

    headers = {k.lower(): v for k, v in response.headers.items()}
    return [
        {
            "title": f"Missing security header: {h}",
            "severity": "low",
            "description": f"Active fetch of {target} did not return the {h} header.",
            "host": host,
        }
        for h in SECURITY_HEADERS
        if h not in headers
    ]


def check_reflected_xss(project, target):
    host = urlparse(target).hostname or ""
    params = parse_qsl(urlparse(target).query)
    if not params:
        return []

    marker = f"xss{secrets.token_hex(4)}<z>"
    findings = []
    for key, _ in params:
        probe_url = _with_query_param(target, key, marker)
        try:
            response = send_request(project, "GET", probe_url)
        except Exception:  # noqa: BLE001
            continue
        if marker in response.text:
            findings.append({
                "title": f"Possible reflected XSS via parameter '{key}'",
                "severity": "high",
                "description": f"An unescaped marker injected into '{key}' ({probe_url}) was reflected verbatim in the response body.",
                "host": host,
            })
    return findings


def check_sqli(project, target):
    host = urlparse(target).hostname or ""
    params = parse_qsl(urlparse(target).query)
    if not params:
        return []

    try:
        baseline_text = send_request(project, "GET", target).text
    except Exception:  # noqa: BLE001
        baseline_text = ""

    findings = []
    for key, _ in params:
        for probe in SQLI_PROBES:
            probe_url = _with_query_param(target, key, probe)
            try:
                response = send_request(project, "GET", probe_url)
            except Exception:  # noqa: BLE001
                continue
            marker_hit = next((m for m in SQL_ERROR_MARKERS if m in response.text and m not in baseline_text), None)
            if marker_hit:
                findings.append({
                    "title": f"Possible SQL error triggered via parameter '{key}'",
                    "severity": "high",
                    "description": f"Payload {probe!r} on '{key}' ({probe_url}) produced a response containing '{marker_hit}', absent from the baseline response.",
                    "host": host,
                })
                break  # one hit is enough evidence for this parameter
    return findings


def check_dir_brute(project, target):
    parsed = urlparse(target)
    host = parsed.hostname or ""
    base_path = parsed.path.rstrip("/")
    findings = []

    # SPA-style apps (Angular/React/Vue with client-side routing) commonly
    # serve a 200 catch-all for literally any unmatched path — verified
    # against a real target where every single wordlist entry, including
    # nonsense ones like "config.php" on a Node.js app, returned 200 with
    # byte-identical content to a deliberately-bogus random path (100%
    # false positive rate). Probing that baseline first and skipping any
    # wordlist hit that matches it filters this out while still catching
    # real distinct content (verified: a real robots.txt, 28 bytes, stayed
    # distinguishable from a 9393-byte SPA-shell fallback).
    baseline_path = f"{base_path}/__interceptor_baseline_{secrets.token_hex(8)}__"
    baseline_url = urlunparse(parsed._replace(path=baseline_path, query=""))
    try:
        baseline_response = send_request(project, "GET", baseline_url)
        baseline_signature = (baseline_response.status_code, len(baseline_response.content))
    except Exception:  # noqa: BLE001
        baseline_signature = None

    for word in DIR_BRUTE_WORDLIST:
        probe_url = urlunparse(parsed._replace(path=f"{base_path}/{word}", query=""))
        try:
            response = send_request(project, "GET", probe_url)
        except Exception:  # noqa: BLE001
            continue
        if response.status_code >= 400:
            continue
        signature = (response.status_code, len(response.content))
        if baseline_signature is not None and signature == baseline_signature:
            continue
        # Same reasoning as Site Map's JS-endpoint discovery: a dir-brute hit
        # is a real path this tool now knows about even though it was never
        # captured as proxied traffic — without this it only ever existed as
        # freeform text in the Finding description, invisible to Site Map.
        if host:
            DiscoveredEndpoint.objects.get_or_create(project=project, host=host, path=f"{base_path}/{word}")
        findings.append({
            "title": f"Discovered path: /{word}",
            "severity": "info",
            "description": f"{probe_url} returned HTTP {response.status_code}.",
            "host": host,
        })
    return findings


CHECK_FUNCTIONS = {
    "headers": check_headers,
    "xss": check_reflected_xss,
    "sqli": check_sqli,
    "dirbrute": check_dir_brute,
}

CHECK_LABELS = {
    "headers": "Missing security headers",
    "xss": "Reflected XSS probe (query params)",
    "sqli": "Error-based SQLi probe (query params)",
    "dirbrute": "Directory/file brute force (small built-in wordlist)",
}
