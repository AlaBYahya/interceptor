# Architecture

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
