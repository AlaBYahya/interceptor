"""mitmproxy addon: captures every flow and posts it to the Django ingest
API, and injects the active project's custom headers (e.g. a bug-bounty
program's required identification header) into every request it forwards.

Both the POST and the header-cache refresh run off mitmproxy's asyncio event
loop via run_in_executor — blocking network calls in the request/response
hooks directly would stall the whole proxy for every in-flight connection.
"""

import asyncio
import base64
import os
import time

import requests
from mitmproxy import http

INGEST_URL = os.environ.get("INGEST_URL", "http://web:8000/api/flows/ingest/")
HEADERS_URL = os.environ.get("HEADERS_URL", "http://web:8000/api/custom-headers/")
INGEST_TOKEN = os.environ.get("INGEST_TOKEN", "")

HEADERS_CACHE_TTL = 30  # seconds
_headers_cache = {"headers": [], "last_fetch": 0.0, "fetching": False}


def _safe_text(data: bytes):
    """Returns (text, is_base64). Bodies that aren't valid UTF-8 get
    base64-encoded rather than dropped or mangled."""
    if not data:
        return "", False
    try:
        return data.decode("utf-8"), False
    except UnicodeDecodeError:
        return base64.b64encode(data).decode("ascii"), True


def _post_flow(payload):
    try:
        requests.post(
            INGEST_URL,
            json=payload,
            headers={"X-Ingest-Token": INGEST_TOKEN},
            timeout=5,
        )
    except requests.RequestException:
        pass  # never let a logging failure affect the proxied traffic


def _refresh_headers_cache():
    try:
        resp = requests.get(HEADERS_URL, headers={"X-Ingest-Token": INGEST_TOKEN}, timeout=5)
        if resp.ok:
            _headers_cache["headers"] = resp.json().get("headers", [])
            _headers_cache["last_fetch"] = time.time()
    except requests.RequestException:
        pass
    finally:
        _headers_cache["fetching"] = False


class IngestAddon:
    def request(self, flow: http.HTTPFlow) -> None:
        # Kick off a background refresh if the cache is stale; use whatever
        # is currently cached (possibly empty on cold start) for this
        # request rather than blocking on the network.
        if not _headers_cache["fetching"] and time.time() - _headers_cache["last_fetch"] > HEADERS_CACHE_TTL:
            _headers_cache["fetching"] = True
            asyncio.get_event_loop().run_in_executor(None, _refresh_headers_cache)

        existing_lower = {k.lower(): k for k in flow.request.headers.keys()}
        for header in _headers_cache["headers"]:
            name_lower = header["name"].lower()
            if name_lower not in existing_lower:
                flow.request.headers[header["name"]] = header["value"]
            elif header.get("append_to_existing"):
                existing_key = existing_lower[name_lower]
                flow.request.headers[existing_key] = flow.request.headers[existing_key] + header["value"]

    def response(self, flow: http.HTTPFlow) -> None:
        req, resp = flow.request, flow.response
        # .content, not .raw_content: mitmproxy's .raw_content is the raw
        # wire bytes (still gzip/deflate/br-compressed if Content-Encoding
        # says so), while .content is decompressed. Using raw_content meant
        # any compressed response's body failed the UTF-8 decode below and
        # got treated as opaque base64 — silently disabling every
        # text-based check (leaked secrets, reflected params, verbose
        # errors, JS endpoint discovery, tech fingerprinting from body) for
        # any gzip-compressed response, which real servers send constantly
        # (Express/nginx compression is on by default almost everywhere).
        req_body_text, req_b64 = _safe_text(req.content or b"")
        resp_body_text, resp_b64 = _safe_text(resp.content or b"") if resp else ("", False)

        duration_ms = None
        if resp and resp.timestamp_end and req.timestamp_start:
            duration_ms = int((resp.timestamp_end - req.timestamp_start) * 1000)

        payload = {
            "method": req.method,
            "url": req.pretty_url,
            "host": req.pretty_host,
            "request_headers": dict(req.headers),
            "request_body": req_body_text,
            "request_body_is_base64": req_b64,
            "status_code": resp.status_code if resp else None,
            "response_headers": dict(resp.headers) if resp else {},
            "response_body": resp_body_text,
            "response_body_is_base64": resp_b64,
            "client_ip": flow.client_conn.peername[0] if flow.client_conn.peername else None,
            "duration_ms": duration_ms,
        }

        asyncio.get_event_loop().run_in_executor(None, _post_flow, payload)


addons = [IngestAddon()]
