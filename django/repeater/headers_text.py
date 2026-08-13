"""Convert between a headers dict and the editable "Key: Value" per-line
textarea format used in the Repeater UI."""


def headers_to_text(headers: dict) -> str:
    return "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())


def text_to_headers(text: str) -> dict:
    headers = {}
    for line in (text or "").splitlines():
        line = line.strip()
        if not line or ":" not in line:
            continue
        key, _, value = line.partition(":")
        headers[key.strip()] = value.strip()
    return headers
