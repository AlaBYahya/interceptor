"""Single choke point for all outbound requests this tool sends on the
user's behalf (Repeater, Intruder, Active Scanner). Every call goes through
the scope check first — see core/scope.py.
"""

import httpx

from .scope import OutOfScopeError, is_in_scope


def _with_project_headers(project, headers):
    """Layer in the project's tool-scoped custom headers (e.g. a bug-bounty
    program's required identification header) without overwriting anything
    already explicitly set on this request."""
    merged = dict(headers or {})
    existing_lower = {k.lower() for k in merged}
    for header in project.custom_headers.filter(apply_to_tool_traffic=True):
        if header.name.lower() not in existing_lower:
            merged[header.name] = header.value
    return merged


def recalculate_content_length(headers, content: bytes):
    """Like Burp's Repeater/Intruder, always keep Content-Length in sync with
    the actual body being sent — the user edits a body and shouldn't have to
    remember to fix this header by hand (a stale value causes truncated or
    hung requests). Public so callers can also reflect the recalculated
    value back in what they display/store, not just what's sent on the wire.
    """
    headers = {k: v for k, v in headers.items() if k.lower() != "content-length"}
    headers["Content-Length"] = str(len(content))
    return headers


def send_request(project, method, url, headers=None, body=None, timeout=15.0):
    if not is_in_scope(project, url):
        raise OutOfScopeError(f"'{url}' is not in the '{project.name}' project scope")

    content = body.encode() if isinstance(body, str) else (body or b"")
    headers = _with_project_headers(project, headers)
    headers = recalculate_content_length(headers, content)

    # This is a security-testing tool: it's expected to hit self-signed/
    # invalid certs on test targets, so certificate verification is
    # intentionally disabled here, the same way Burp/ZAP behave by default.
    with httpx.Client(verify=False, timeout=timeout, follow_redirects=False) as client:
        response = client.request(method, url, headers=headers, content=content)
    return response
