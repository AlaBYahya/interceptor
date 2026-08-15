"""Pure functions, one per check. Each takes a Flow and returns a list of
finding dicts ({title, severity, description}). Run automatically on every
ingested flow — see scanner/tasks.py and scanner/apps.py.
"""

import re
from urllib.parse import parse_qsl, urlparse

SECURITY_HEADERS = [
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "strict-transport-security",
    "referrer-policy",
]

# Parameter names commonly worth a closer manual look — auth/session/IDOR/
# SSRF/traversal/debug surface. Matched as a whole segment (split on
# non-alnum), not a raw substring, to avoid noise like "guided" matching "id".
INTERESTING_PARAM_NAMES = {
    "id", "uid", "user_id", "userid", "account", "token", "access_token",
    "auth", "authorization", "key", "api_key", "apikey", "secret",
    "password", "passwd", "pwd", "session", "sessionid", "sid", "csrf",
    "csrf_token", "admin", "role", "debug", "test", "redirect", "return",
    "returnurl", "return_url", "next", "url", "uri", "path", "file",
    "filename", "filepath", "callback", "cmd", "exec", "command", "code",
}

# Regexes for secrets/credentials that shouldn't appear in a response body.
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("Generic API key assignment", re.compile(r"""(?i)api[_-]?key["']?\s*[:=]\s*["'][A-Za-z0-9_\-]{16,}["']""")),
    ("JWT", re.compile(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("Private key block", re.compile(r"-----BEGIN (?:RSA|EC|OPENSSH|DSA|PGP) PRIVATE KEY-----")),
    ("Password field in response", re.compile(r"""(?i)"?passw(?:or)?d"?\s*[:=]\s*["'][^"']{3,}["']""")),
]

VERBOSE_ERROR_MARKERS = [
    "Traceback (most recent call last)",
    "Warning: mysql_",
    "ORA-01756",
    "Microsoft OLE DB Provider",
    "Fatal error:",
    "Exception in thread",
    "django.core.exceptions",
    "at java.lang.",
]

# Modern REST APIs often return the exception as structured JSON (fields
# like "stackTrace"/"className"/"methodName") rather than a plain-text
# traceback — plain substring markers above miss this shape entirely.
JSON_STACK_TRACE_RE = re.compile(r'"(?:stackTrace|className|methodName)"\s*:')


def _param_segments(name: str):
    return [seg for seg in re.split(r"[^a-zA-Z0-9]+", name.lower()) if seg]


def check_missing_security_headers(flow):
    findings = []
    headers = {k.lower(): v for k, v in (flow.response_headers or {}).items()}
    for h in SECURITY_HEADERS:
        if h not in headers:
            findings.append({
                "title": f"Missing security header: {h}",
                "severity": "low",
                "description": f"Response from {flow.host} does not set the {h} header.",
            })
    return findings


def check_reflected_params(flow):
    findings = []
    if not flow.response_body or flow.response_body_is_base64 or "?" not in flow.url:
        return findings
    query = parse_qsl(urlparse(flow.url).query)
    body = flow.response_body
    for key, value in query:
        if value and len(value) > 2 and value in body:
            findings.append({
                "title": f"Possible reflected parameter: {key}",
                "severity": "info",
                "description": f"Value of query parameter '{key}' appears unescaped in the response body — check for XSS.",
            })
    return findings


def check_verbose_errors(flow):
    if not flow.response_body or flow.response_body_is_base64:
        return []
    for marker in VERBOSE_ERROR_MARKERS:
        if marker in flow.response_body:
            return [{
                "title": "Verbose error / stack trace exposed",
                "severity": "medium",
                "description": f"Response body contains a marker suggesting a verbose error page ('{marker}').",
            }]
    if JSON_STACK_TRACE_RE.search(flow.response_body):
        return [{
            "title": "Verbose error / stack trace exposed",
            "severity": "medium",
            "description": "Response body contains a JSON-structured stack trace (stackTrace/className/methodName fields) — internal exception details are being returned to the client.",
        }]
    return []


def check_mixed_content(flow):
    if not flow.url.startswith("https://") or not flow.response_body or flow.response_body_is_base64:
        return []
    if "http://" in flow.response_body:
        return [{
            "title": "Possible mixed content",
            "severity": "info",
            "description": "HTTPS page response body references an http:// resource.",
        }]
    return []


def check_interesting_parameters(flow):
    """Flags requests carrying auth/IDOR/SSRF/traversal-flavored parameter
    names, in the query string or a form-encoded body — worth a manual look,
    not proof of a bug. Drives the history-table row highlighting."""
    findings = []
    seen = set()

    names = [k for k, _ in parse_qsl(urlparse(flow.url).query)]
    if flow.request_body and not flow.request_body_is_base64:
        names += [k for k, _ in parse_qsl(flow.request_body)]

    for name in names:
        if name in seen:
            continue
        if INTERESTING_PARAM_NAMES & set(_param_segments(name)):
            seen.add(name)
            findings.append({
                "title": f"Interesting parameter: {name}",
                "severity": "info",
                "description": f"Parameter '{name}' on {flow.method} {flow.host} matches a name commonly relevant to auth/IDOR/SSRF/traversal testing.",
            })
    return findings


def check_leaked_secrets(flow):
    """Flags likely secrets/credentials appearing in a response body."""
    findings = []
    if not flow.response_body or flow.response_body_is_base64:
        return findings
    body = flow.response_body
    for label, pattern in SECRET_PATTERNS:
        if pattern.search(body):
            findings.append({
                "title": f"Possible leaked secret: {label}",
                "severity": "high",
                "description": f"Response body from {flow.host} matches a pattern for '{label}'. Verify and rotate if genuine.",
            })
    return findings


# Structural checks describe a property of the host/config, not of the
# specific request — the same missing header fires on nearly every response
# from a host, so scanner/tasks.py dedupes these per (project, host, title)
# instead of creating one Finding per flow. Per-request checks describe
# something specific to that exact request/response (a reflected value, a
# secret in this body) and stay one-per-flow. Mixed content belongs here, not
# structural: it depends on what a specific page's body happens to reference,
# not a host-wide constant — a title-only dedup key would silently drop every
# occurrence past the first page found per host (verified: two pages with
# different http:// resources on the same host produced only one Finding).
STRUCTURAL_CHECKS = (check_missing_security_headers,)
PER_REQUEST_CHECKS = (
    check_reflected_params,
    check_verbose_errors,
    check_mixed_content,
    check_interesting_parameters,
    check_leaked_secrets,
)
CHECKS = STRUCTURAL_CHECKS + PER_REQUEST_CHECKS


def run_structural(flow):
    findings = []
    for check in STRUCTURAL_CHECKS:
        findings.extend(check(flow))
    return findings


def run_per_request(flow):
    findings = []
    for check in PER_REQUEST_CHECKS:
        findings.extend(check(flow))
    return findings


def run_all(flow):
    return run_structural(flow) + run_per_request(flow)
