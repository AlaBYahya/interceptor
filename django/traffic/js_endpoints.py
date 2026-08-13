"""Heuristic extraction of endpoint/link-like strings from captured
JavaScript response bodies — the same general idea as tools like LinkFinder:
pull quoted strings that look like absolute URLs or root-relative/API paths
out of JS source, so endpoints only ever referenced by client-side code
(never directly requested by whatever traffic you generated) still show up
in the site map.
"""

import re
from urllib.parse import urlparse

from .models import DiscoveredEndpoint

_PATH_RE = re.compile(
    r"""["'](
        https?://[^"'\s]{4,200}
        |
        /(?:[a-zA-Z0-9_\-]+/){0,10}[a-zA-Z0-9_\-.]{1,80}
    )["']""",
    re.VERBOSE,
)

_IGNORED_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".ico",
    ".woff", ".woff2", ".ttf", ".eot", ".css", ".map",
)


def _looks_like_js(flow) -> bool:
    content_type = ""
    for key, value in (flow.response_headers or {}).items():
        if key.lower() == "content-type":
            content_type = value.lower()
            break
    return "javascript" in content_type or flow.url.split("?")[0].split("#")[0].endswith(".js")


def extract_paths(js_source: str) -> set:
    found = set()
    for match in _PATH_RE.finditer(js_source):
        candidate = match.group(1)
        if candidate.lower().endswith(_IGNORED_EXTENSIONS):
            continue
        if len(candidate) < 2 or candidate in ("//", "/"):
            continue
        found.add(candidate)
    return found


def maybe_extract_endpoints(flow):
    """No-op unless the flow looks like a JavaScript response with a usable
    (non-binary) body. Safe to call on every ingested flow."""
    if not _looks_like_js(flow) or not flow.response_body or flow.response_body_is_base64:
        return

    for candidate in extract_paths(flow.response_body):
        if candidate.startswith(("http://", "https://")):
            parsed = urlparse(candidate)
            host, path = parsed.netloc, (parsed.path or "/")
        else:
            host, path = flow.host, candidate

        if not host:
            continue

        DiscoveredEndpoint.objects.get_or_create(
            project=flow.project, host=host, path=path,
            defaults={"source_flow": flow},
        )
