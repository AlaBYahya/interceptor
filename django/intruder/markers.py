"""§marker§ insertion-point parsing, Burp-style. A user wraps the part(s) of
a request template they want fuzzed in § characters, e.g. `/user?id=§1§`.
Each marked pair is one insertion point; the text between the markers is
that point's original value, restored whenever a different point is being
substituted.
"""

import re
from urllib.parse import urlparse, urlunparse

MARKER_RE = re.compile(r"§(.*?)§")

_UUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_NUMERIC_RE = re.compile(r"^\d+$")


def count_points(template: str) -> int:
    return len(MARKER_RE.findall(template or ""))


def strip_markers(template: str) -> str:
    """Remove marker syntax, keeping the original enclosed value."""
    return MARKER_RE.sub(lambda m: m.group(1), template or "")


def substitute_point(template: str, index: int, payload: str) -> str:
    """Replace the Nth (0-indexed) marked position with payload; every
    other marked position reverts to its original enclosed value."""
    counter = {"i": 0}

    def repl(match):
        current = counter["i"]
        counter["i"] += 1
        return payload if current == index else match.group(1)

    return MARKER_RE.sub(repl, template or "")


def _mark_query(query: str) -> str:
    """Wrap each parameter's value in §markers§, operating on the raw query
    string rather than parse_qsl's decoded form — parse_qsl unescapes
    percent-encoding (and "+") with no way to re-encode symmetrically when
    rebuilding, which silently corrupted every *other* (non-fuzzed)
    parameter for the whole attack: a redirect=https%3A%2F%2F... became a
    literal, structurally-different https://... in the "restored" URL, and
    a bare flag param like "?foo" grew a spurious "=" it never had."""
    if not query:
        return query
    marked = []
    for pair in query.split("&"):
        if "=" in pair:
            key, value = pair.split("=", 1)
            marked.append(f"{key}=§{value}§")
        else:
            marked.append(f"§{pair}§")
    return "&".join(marked)


def auto_mark_url(url: str) -> str:
    """Wrap likely-fuzzable positions in §markers§ automatically: every
    query parameter's value, and any path segment that looks like an ID
    (a UUID, or a plain number) — e.g.
    `/person/4a30b832-2a3e-4427-ad27-af7814e3a289?random=123` becomes
    `/person/§4a30b832-2a3e-4427-ad27-af7814e3a289§?random=§123§`.
    Mirrors Burp's default auto-markup when a request is sent to Intruder,
    so the common IDOR-probing case needs no manual marking at all — you
    can still add/remove §marks§ by hand for anything else."""
    parsed = urlparse(url)

    segments = parsed.path.split("/")
    marked_segments = [
        f"§{seg}§" if seg and (_UUID_RE.match(seg) or _NUMERIC_RE.match(seg)) else seg for seg in segments
    ]

    return urlunparse(parsed._replace(path="/".join(marked_segments), query=_mark_query(parsed.query)))


def auto_mark_form_body(body: str, content_type: str) -> str:
    """Same idea as auto_mark_url but for an application/x-www-form-urlencoded
    body — leaves anything else (JSON, multipart, etc.) untouched since
    those need context-aware marking that isn't safe to guess at."""
    if "x-www-form-urlencoded" not in (content_type or "").lower():
        return body
    return _mark_query(body or "")
