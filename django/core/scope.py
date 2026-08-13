"""Target-scope enforcement.

Every code path that sends real traffic to a real host (Repeater resend,
Intruder attacks, the active scanner, nmap/nuclei jobs) must check the target
against the active project's scope before firing. This mirrors Burp's target
scope and exists specifically so this tool can't accidentally fire requests
at hosts you're not authorized to test.
"""

import fnmatch
import ipaddress
from urllib.parse import urlparse


def extract_host(host_or_url: str) -> str:
    if "://" in host_or_url:
        host = urlparse(host_or_url).hostname
        return host or ""
    # bare "host" or "host:port"
    return host_or_url.split("/")[0].split(":")[0]


def is_in_scope(project, host_or_url: str) -> bool:
    """True if host_or_url matches any of the project's scope entries."""
    host = extract_host(host_or_url)
    if not host:
        return False

    patterns = project.scope_entries.values_list("pattern", flat=True)
    for pattern in patterns:
        if fnmatch.fnmatch(host.lower(), pattern.lower()):
            return True
        try:
            network = ipaddress.ip_network(pattern, strict=False)
            addr = ipaddress.ip_address(host)
        except ValueError:
            continue
        if addr in network:
            return True
    return False


class OutOfScopeError(Exception):
    """Raised when a send is attempted against a host outside project scope."""
