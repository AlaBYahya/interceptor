<img src="docs/logo.svg" width="72" height="72" alt="Interceptor logo">

# Interceptor

A self-hosted, Burp Suite-style web security testing toolkit — Django +
Docker instead of the Java desktop app. Built for authorized testing
(bug bounty, pentest engagements, your own apps).

- **[Features](docs/features.md)** — proxy, Site map, Repeater, Intruder,
  Active scanner, Toolbox, Crawler, passive scanner, Vulnerabilities,
  Notes, and more.
- **[Setup](docs/setup.md)** — get it running, intercept HTTPS traffic,
  custom headers, searchsploit/nuclei.
- **[Architecture](docs/architecture.md)** — services, ports, data flow.

## Quickstart

```bash
cp .env.example .env   # fill in DJANGO_SECRET_KEY, POSTGRES_PASSWORD, INGEST_TOKEN, ADMIN_USERNAME/PASSWORD
docker compose up -d --build
```

Open http://127.0.0.1:8000, log in, then add a scope entry (**Scope** in
the nav) — nothing can be sent until you do. See [docs/setup.md](docs/setup.md)
for the full walkthrough.

## Safety notes

- This tool captures live traffic, including credentials/tokens, and can
  send real requests to real hosts (Repeater, Intruder, Active Scanner,
  nmap/nuclei). Only use it against targets you're authorized to test.
- The scope allowlist is the safety gate for anything that sends traffic on
  your behalf — keep it accurate and specific to your current engagement.
