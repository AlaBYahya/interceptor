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


def _pattern_matches(pattern: str, host: str) -> bool:
    if fnmatch.fnmatch(host.lower(), pattern.lower()):
        return True
    try:
        network = ipaddress.ip_network(pattern, strict=False)
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    return addr in network


def is_in_scope(project, host_or_url: str, entries=None) -> bool:
    """True if host_or_url matches an in-scope pattern and no exclusion.

    Exclusions always win, even over a broader in-scope wildcard that also
    matches — this is how a program's "*.example.com except www/support"
    carve-outs get enforced.

    `entries` lets a caller checking many hosts against the same project
    (e.g. filtering a whole page of Traffic/Findings rows to "in-scope
    only") fetch the scope list once and pass it in, instead of this
    re-querying it fresh on every single call — that difference is a
    real N+1 (verified: 158 rows -> 164 queries filtering, vs. 5 without),
    not a hypothetical one.
    """
    host = extract_host(host_or_url)
    if not host:
        return False

    if entries is None:
        entries = project.scope_entries.values_list("pattern", "exclude")
    includes = [pattern for pattern, exclude in entries if not exclude]
    excludes = [pattern for pattern, exclude in entries if exclude]

    if any(_pattern_matches(pattern, host) for pattern in excludes):
        return False
    return any(_pattern_matches(pattern, host) for pattern in includes)


class OutOfScopeError(Exception):
    """Raised when a send is attempted against a host outside project scope."""
