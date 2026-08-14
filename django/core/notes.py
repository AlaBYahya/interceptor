"""Renders ProjectNote text to safe HTML, turning [req:N]/[finding:N]/
[vuln:N] references into links to that item's detail page — a lightweight
cross-reference system so a note can point at the exact request/finding/
vulnerability it's about instead of just describing it in prose."""

import re

from django.urls import reverse
from django.utils.html import escape
from django.utils.safestring import mark_safe

REF_PATTERN = re.compile(r"\[(req|finding|vuln):(\d+)\]")

REF_URL_NAMES = {
    "req": "traffic:flow_detail",
    "finding": "scanner:finding_detail",
    "vuln": "scanner:vulnerability_detail",
}


def render_note_text(text):
    pieces = []
    pos = 0
    for m in REF_PATTERN.finditer(text):
        pieces.append(escape(text[pos:m.start()]))
        kind, pk = m.group(1), m.group(2)
        url = reverse(REF_URL_NAMES[kind], args=[pk])
        pieces.append(f'<a href="{url}" class="note-ref">[{kind}:{pk}]</a>')
        pos = m.end()
    pieces.append(escape(text[pos:]))
    # Rendered outside a <pre>/textarea, so newlines need to become <br>
    # explicitly or the note collapses onto one line.
    return mark_safe("".join(pieces).replace("\n", "<br>"))
