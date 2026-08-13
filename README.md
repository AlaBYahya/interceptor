<img src="docs/logo.svg" width="72" height="72" alt="Interceptor logo">

# Interceptor

A self-hosted, Burp Suite-style web security testing toolkit — Django +
Docker instead of the Java desktop app. Built for authorized testing
(bug bounty, pentest engagements, your own apps).

## What's working now

- **Intercepting proxy + HTTP history** — mitmproxy captures every request/
  response into Django. Search, filter, and sort history; mark requests
  Tested/Interesting with notes; scope-aware capture mode.
- **Open Browser** (`./browse.sh`) — isolated Chromium profile pre-pointed
  at the proxy, Burp-style. Run on your desktop, not in a container.
- **Site map** — folder-style host/path tree merged with JS-discovered
  endpoints, with risk badges rolled up from Findings, ZAP Sites-tree style.
- **Repeater** — edit and resend a captured request, response side-by-side,
  auto-recalculated `Content-Length`.
- **Intruder** — Sniper attack with auto-marked `§payload§` insertion
  points, typed/generated/wordlist payloads, sortable/filterable results
  with anomaly highlighting.
- **Active scanner** — opt-in, scope-checked: missing security headers,
  reflected-XSS and error-based-SQLi probes, directory/file brute force.
- **Toolbox** — `nmap` scans, `searchsploit` (~48k exploits), and `nuclei`
  (~13.5k templates) integration, auto-chained from detected
  services/technologies, all scope-checked and parsed into Findings.
- **Crawler** — rate-limited, concurrency-controlled spider with randomized,
  human-like timing; ignores `robots.txt` on purpose; captured pages flow
  into Traffic/Site map like proxied requests.
- **Technology detection** — passive fingerprinting (hand-written signatures
  plus a Go `techdetect` wrapper around `wappalyzergo`) from data already
  captured, no extra requests.
- **Decoder / Comparer** — Base64/URL/HTML/hex encode-decode and a
  line-by-line text diff, both stateless.
- **Passive scanner** — automatic checks on every flow (headers, reflected
  params, error pages, mixed content, interesting params, leaked secrets),
  driving severity-colored Findings with triage status and CSV/Markdown
  export.
- **Vulnerabilities** — manually-curated report workspace: write up a
  vuln, attach proof requests, export the project as a Markdown report.
- **Scope enforcement** — every traffic-sending feature checks the active
  project's scope list first and refuses if the target isn't in it.
- **Custom headers** — per-project headers auto-injected into outbound
  traffic (e.g. bug-bounty program identification), configurable per
  traffic source.
- **Project delete / export / import** — cascading delete, full JSON
  export/import with ID remapping into a new project.

See each feature's code/templates for implementation details.

## Setup

1. `cp .env.example .env` and fill in real values — at minimum
   `DJANGO_SECRET_KEY`, `POSTGRES_PASSWORD`, `INGEST_TOKEN`, and
   `ADMIN_USERNAME`/`ADMIN_PASSWORD`.
2. `docker compose up -d --build`
3. On first startup the `web` container automatically runs migrations and
   creates an admin user from `ADMIN_USERNAME`/`ADMIN_PASSWORD` in `.env`.
4. Open http://127.0.0.1:8000 and log in.
5. **Add a scope entry first** (Scope in the nav) — nothing can be sent to
   until you do. Patterns are host globs (`*.example.com`) or CIDR ranges
   (`10.0.0.0/8`).

### Intercepting HTTPS traffic

1. Configure your browser/OS to use `127.0.0.1:8080` as the HTTP **and**
   HTTPS proxy — or just run `./browse.sh` for a pre-configured isolated
   Chromium profile.
2. With the proxy active, visit `http://mitm.it` and install mitmproxy's
   generated CA certificate for your browser/OS — this is mitmproxy's
   standard flow, nothing custom here.
3. Browse to something in scope — it should show up in **Traffic** within a
   couple seconds.

### Custom headers (bug-bounty program identification, etc.)

Go to **Headers** in the nav, add a name/value, and choose whether it
applies to proxy traffic, the tool's own sends (Repeater etc.), or both. It
won't overwrite a header a request already explicitly sets.

### Toolbox: searchsploit and nuclei

Both are installed in the `worker` image (`django/Dockerfile.worker`):
`searchsploit` via a shallow clone of the `exploitdb` repo, `nuclei` via
its current release binary fetched through the GitHub API (not a
hardcoded version, so rebuilding stays current) with its template library
pre-downloaded at build time. Rebuild with `docker compose build worker`
if you want to refresh either (or use the "Update nuclei templates" button
in the Toolbox UI to refresh just the templates without a full rebuild).

The same `Dockerfile.worker` also builds `techdetect` (`django/techdetect/`,
a small Go program) in an earlier build stage — needs the `golang:1.25-bookworm`
image on first build, but the Go toolchain itself doesn't end up in the
final worker image, just the compiled binary.

## Architecture

| service | role |
|---|---|
| `db` (Postgres) | all persistent data |
| `redis` | Celery broker/result backend |
| `web` (Django + Gunicorn) | UI + ingestion API, `127.0.0.1:8000` |
| `proxy` (mitmproxy + addon) | intercepting proxy, `127.0.0.1:8080` |
| `worker` (Celery) | passive scan, active scan, intruder, nmap/searchsploit/nuclei tasks |

All ports bind to `127.0.0.1` only — nothing is exposed off this host.
Every UI view requires login. Outbound sends (Repeater etc.) disable TLS
certificate verification by design, the same way Burp/ZAP do, since test
targets often have self-signed certs.

Data flow: the mitmproxy addon (`mitmproxy/ingest_addon.py`) posts each
captured flow to `POST /api/flows/ingest/` (shared-secret token auth, not a
browser session) and separately polls `GET /api/custom-headers/` every 30s
to pick up header changes. Saving a `Flow` fires a Django signal that
enqueues the passive-scan Celery task, which also runs the JS
endpoint-extraction pass on the same response body.

## Safety notes

- This tool captures live traffic, including credentials/tokens, and can
  send real requests to real hosts (Repeater, Intruder, Active Scanner,
  nmap/nuclei). Only use it against targets you're authorized to test.
- The scope allowlist is the safety gate for anything that sends traffic on
  your behalf — keep it accurate and specific to your current engagement.
