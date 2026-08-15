# Setup

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

## Intercepting HTTPS traffic

1. Configure your browser/OS to use `127.0.0.1:8080` as the HTTP **and**
   HTTPS proxy — or just run `./browse.sh` for a pre-configured isolated
   Chromium profile.
2. With the proxy active, visit `http://mitm.it` and install mitmproxy's
   generated CA certificate for your browser/OS — this is mitmproxy's
   standard flow, nothing custom here.
3. Browse to something in scope — it should show up in **Traffic** within a
   couple seconds.

Not just a browser — any tool that supports an HTTP(S) proxy (curl, a
custom scraper, another pentesting tool) works the same way: point it at
`127.0.0.1:8080` with the CA cert trusted, and its traffic gets captured,
scope-checked, and passively scanned exactly like proxied browser traffic:

```bash
docker compose cp proxy:/home/mitmproxy/.mitmproxy/mitmproxy-ca-cert.pem .
curl -x http://127.0.0.1:8080 --cacert mitmproxy-ca-cert.pem https://example.com/
```

## Custom headers (bug-bounty program identification, etc.)

Go to **Headers** in the nav, add a name/value, and choose whether it
applies to proxy traffic, the tool's own sends (Repeater etc.), or both. It
won't overwrite a header a request already explicitly sets.

## Toolbox: searchsploit and nuclei

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
