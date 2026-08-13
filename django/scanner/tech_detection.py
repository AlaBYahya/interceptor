"""Passive technology fingerprinting from an already-captured Flow's
response headers/HTML — a curated signature set (not an exhaustive
Wappalyzer-style database), covering what's actually common to run into:
web servers, PHP/ASP.NET, a handful of JS frameworks, and CMS "generator"
meta tags. Each detector returns a list of (name, version) tuples; version
is "" when detected but unspecified.
"""

import json
import re
import subprocess


def _header(headers, name):
    name = name.lower()
    for key, value in (headers or {}).items():
        if key.lower() == name:
            return value
    return ""


def _cookie_names(headers):
    raw = _header(headers, "set-cookie")
    return {part.split("=", 1)[0].strip().lower() for part in raw.split(";") if "=" in part}


def detect_server(flow):
    server = _header(flow.response_headers, "server")
    if not server:
        return []
    results = []
    for name, pattern in (("Apache", r"Apache/([\d.]+)"), ("nginx", r"nginx/([\d.]+)"), ("IIS", r"Microsoft-IIS/([\d.]+)")):
        m = re.search(pattern, server)
        if m:
            results.append((name, m.group(1)))
        elif name.lower() in server.lower():
            results.append((name, ""))
    return results


def detect_powered_by(flow):
    powered_by = _header(flow.response_headers, "x-powered-by")
    results = []
    if powered_by:
        m = re.search(r"PHP/([\d.]+)", powered_by)
        if m:
            results.append(("PHP", m.group(1)))
        elif "php" in powered_by.lower():
            results.append(("PHP", ""))
        if "asp.net" in powered_by.lower():
            m = re.search(r"ASP\.NET,?\s*Version=([\d.]+)", powered_by, re.IGNORECASE)
            results.append(("ASP.NET", m.group(1) if m else ""))
        if "express" in powered_by.lower():
            results.append(("Express", ""))
    if not any(name == "PHP" for name, _ in results) and "phpsessid" in _cookie_names(flow.response_headers):
        results.append(("PHP", ""))
    return results


def detect_cookies(flow):
    cookie_names = _cookie_names(flow.response_headers)
    mapping = {
        "jsessionid": ("Java (JSP/Servlet)", ""),
        "laravel_session": ("Laravel", ""),
        "asp.net_sessionid": ("ASP.NET", ""),
    }
    return [tech for cookie, tech in mapping.items() if cookie in cookie_names]


def detect_meta_generator(flow):
    if flow.response_body_is_base64 or not flow.response_body:
        return []
    m = re.search(r'<meta\s+name=["\']generator["\']\s+content=["\']([^"\']+)["\']', flow.response_body, re.IGNORECASE)
    if not m:
        return []
    content = m.group(1).strip()
    vm = re.match(r"([A-Za-z][A-Za-z .]*?)\s+([\d][\d.]*)$", content)
    if vm:
        return [(vm.group(1).strip(), vm.group(2))]
    return [(content, "")]


def detect_frontend_frameworks(flow):
    if flow.response_body_is_base64 or not flow.response_body:
        return []
    body = flow.response_body
    results = []

    m = re.search(r'ng-version=["\']([\d.]+)["\']', body)
    if m:
        results.append(("Angular", m.group(1)))

    if re.search(r"data-reactroot|__REACT_DEVTOOLS_GLOBAL_HOOK__", body):
        results.append(("React", ""))

    m = re.search(r"Vue\.js v([\d.]+)", body)
    if m:
        results.append(("Vue.js", m.group(1)))
    elif re.search(r"data-v-[0-9a-f]{6,8}", body):
        results.append(("Vue.js", ""))

    m = re.search(r"jQuery v?([\d.]+)", body)
    if m:
        results.append(("jQuery", m.group(1)))

    return results


def detect_from_errors(flow):
    """Verbose error pages / stack traces are one of the richest tech
    fingerprinting signals there is — they name the exact framework and
    sometimes the exact version. Covers both classic plain-text tracebacks
    and the JSON-structured stack traces modern REST APIs often return
    (fields like "stackTrace"/"className"/"methodName" instead of a
    formatted "at package.Class.method(File:line)" string)."""
    if flow.response_body_is_base64 or not flow.response_body:
        return []
    body = flow.response_body
    results = []

    if "org.springframework" in body:
        results.append(("Spring Framework", ""))
    if re.search(r"at java\.lang\.|javax\.servlet", body) or ('"fileName"' in body and ".java" in body):
        results.append(("Java", ""))

    m = re.search(r"Django Version:\s*([\d.]+)", body)
    if m:
        results.append(("Django", m.group(1)))
    elif "django.core" in body:
        results.append(("Django", ""))

    if "Fatal error:" in body or ("Stack trace:" in body and "#0 {main}" in body):
        results.append(("PHP", ""))

    if "/node_modules/" in body or "at Module._compile" in body:
        results.append(("Node.js", ""))

    if "ActionController::" in body or re.search(r"app/controllers/\S+\.rb", body):
        results.append(("Ruby on Rails", ""))

    if "Server Error in '/' Application" in body or re.search(r"System\.Web\.", body):
        results.append(("ASP.NET", ""))

    return results


def detect_via_wappalyzer(flow):
    """Runs the `techdetect` binary (a thin Go wrapper around
    wappalyzergo/ProjectDiscovery's actively-maintained fork of the
    Wappalyzer fingerprint database — thousands of signatures vs. the
    handful curated above) against this flow's already-captured headers/
    body. Purely offline pattern matching — no request of its own — since
    it's only ever given data we already captured. Silently returns []
    if the binary isn't present (e.g. running outside the worker image)."""
    if flow.response_body_is_base64:
        return []

    payload = json.dumps({"headers": dict(flow.response_headers or {}), "body": flow.response_body or ""})
    try:
        result = subprocess.run(
            ["techdetect"], input=payload, capture_output=True, text=True, timeout=10
        )
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0 or not result.stdout:
        return []
    try:
        matches = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    return [(m["name"], m.get("version", "")) for m in matches if m.get("name")]


DETECTORS = (
    detect_server,
    detect_powered_by,
    detect_cookies,
    detect_meta_generator,
    detect_frontend_frameworks,
    detect_from_errors,
    detect_via_wappalyzer,
)


def run_all(flow):
    seen = {}
    for detector in DETECTORS:
        for name, version in detector(flow):
            if name not in seen or (not seen[name] and version):
                seen[name] = version
    return list(seen.items())
