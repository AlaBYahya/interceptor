"""Stateless text transforms for the Decoder page. No models — nothing
here persists anything."""

import base64
import html
import urllib.parse


def _b64_encode(text):
    return base64.b64encode(text.encode("utf-8", errors="replace")).decode("ascii")


def _b64_decode(text):
    padded = text.strip() + "=" * (-len(text.strip()) % 4)
    try:
        return base64.b64decode(padded).decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return f"(decode error: {exc})"


def _url_encode(text):
    return urllib.parse.quote(text, safe="")


def _url_decode(text):
    return urllib.parse.unquote(text)


def _html_encode(text):
    return html.escape(text)


def _html_decode(text):
    return html.unescape(text)


def _hex_encode(text):
    return text.encode("utf-8", errors="replace").hex()


def _hex_decode(text):
    cleaned = "".join(text.split())
    try:
        return bytes.fromhex(cleaned).decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return f"(decode error: {exc})"


OPERATIONS = {
    "base64_encode": _b64_encode,
    "base64_decode": _b64_decode,
    "url_encode": _url_encode,
    "url_decode": _url_decode,
    "html_encode": _html_encode,
    "html_decode": _html_decode,
    "hex_encode": _hex_encode,
    "hex_decode": _hex_decode,
}

OPERATION_LABELS = {
    "base64_encode": "Base64 encode",
    "base64_decode": "Base64 decode",
    "url_encode": "URL encode",
    "url_decode": "URL decode",
    "html_encode": "HTML encode",
    "html_decode": "HTML decode",
    "hex_encode": "Hex encode",
    "hex_decode": "Hex decode",
}
