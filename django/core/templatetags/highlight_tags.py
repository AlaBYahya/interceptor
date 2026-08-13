import re
from urllib.parse import urlparse

from django import template
from django.utils.html import escape
from django.utils.safestring import mark_safe

register = template.Library()


@register.filter
def path_only(url):
    """Strip scheme+host, keeping just path (+query+fragment) — the Host
    column already shows the domain, so repeating it in the URL column is
    redundant."""
    parsed = urlparse(url or "")
    result = parsed.path or "/"
    if parsed.query:
        result += "?" + parsed.query
    if parsed.fragment:
        result += "#" + parsed.fragment
    return result

# Kept in sync conceptually with scanner.passive_checks.INTERESTING_PARAM_NAMES
# (imported directly, not duplicated) so the highlight always matches what
# actually produced a Finding.
from scanner.passive_checks import INTERESTING_PARAM_NAMES  # noqa: E402

_PARAM_RE = re.compile(r"(?P<name>[A-Za-z0-9_\-]+)=(?P<value>[^&#]*)")


@register.filter
def highlight_url_params(url):
    """Wrap interesting query-string parameter names/values in <mark> for
    display. Escapes first, then only ever inserts our own safe markup, so
    this stays safe even though the input is untrusted proxied traffic."""
    escaped = escape(url or "")

    def repl(match):
        segments = {seg for seg in re.split(r"[^a-zA-Z0-9]+", match.group("name").lower()) if seg}
        if INTERESTING_PARAM_NAMES & segments:
            return f'<mark class="param-interesting">{match.group(0)}</mark>'
        return match.group(0)

    return mark_safe(_PARAM_RE.sub(repl, escaped))
