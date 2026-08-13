"""Rate-limited, concurrency-controlled link-following crawler.

Two independent knobs, same as the UI exposes:
- requests_per_second: a GLOBAL cap shared across every worker thread (via
  _RateLimiter below), not a per-thread rate — raising concurrency alone
  doesn't raise total throughput, both need to go up together.
- concurrency: how many worker threads pull from the shared URL queue.

GET requests only (link-following, not form-filling), stays within scope
via core.scope.is_in_scope, and captured pages are saved as ordinary Flow
rows so they go through the same passive-scan/JS-discovery pipeline as
proxied traffic and show up in Traffic history / Site map normally.
"""

import base64
import random
import threading
import time
from collections import deque
from html.parser import HTMLParser
from urllib.parse import urljoin, urlparse

from celery import shared_task
from django.utils import timezone

from core.scope import is_in_scope
from core.senders import send_request

from .models import CrawlJob, Flow
from .signals import flow_ingested

# One is picked per crawl job (not per request) — a real browser doesn't
# change its User-Agent mid-session, so rotating per-request would itself
# be an anomaly rather than cover.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:126.0) Gecko/20100101 Firefox/126.0",
]

LINK_ATTRS = {"a": "href", "link": "href", "script": "src", "img": "src", "form": "action", "iframe": "src"}


class _LinkExtractor(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links = set()

    def handle_starttag(self, tag, attrs):
        attr_name = LINK_ATTRS.get(tag)
        if not attr_name:
            return
        value = dict(attrs).get(attr_name)
        if value:
            self.links.add(urljoin(self.base_url, value))


def extract_links(html_text, base_url):
    parser = _LinkExtractor(base_url)
    try:
        parser.feed(html_text)
    except Exception:  # noqa: BLE001 — malformed HTML shouldn't kill the crawl
        pass
    return parser.links


def _safe_text(data: bytes):
    if not data:
        return "", False
    try:
        return data.decode("utf-8"), False
    except UnicodeDecodeError:
        return base64.b64encode(data).decode("ascii"), True


class _RateLimiter:
    """Caps the aggregate request rate across however many worker threads
    call wait() — a token-bucket-style gate under one lock, so "requests
    per second" means total throughput regardless of concurrency.

    Timing is randomized, not fixed, and deliberately wider than a tight
    band around the nominal rate: most gaps are 0.5x-1.5x the configured
    interval, and ~10% are a long 3x-6x "reading" pause — closer to how a
    real person actually browses (bursty, then a deliberate pause) than a
    narrow uniform jitter, which is itself a statistically recognizable
    pattern over many requests. One consequence: actual average throughput
    runs somewhat below the nominal requests_per_second once those reading
    pauses are factored in — same as it would for a real person, and the
    point of this knob is pace, not a hard throughput guarantee."""

    def __init__(self, requests_per_second):
        self.interval = 1.0 / requests_per_second if requests_per_second > 0 else 0
        self.lock = threading.Lock()
        self.next_time = time.monotonic()

    def wait(self):
        with self.lock:
            now = time.monotonic()
            sleep_for = max(0.0, self.next_time - now)
            if self.interval > 0 and random.random() < 0.10:
                multiplier = random.uniform(3.0, 6.0)  # occasional "reading" pause
            else:
                multiplier = random.uniform(0.5, 1.5) if self.interval > 0 else 1.0
            self.next_time = max(now, self.next_time) + self.interval * multiplier
        if sleep_for > 0:
            time.sleep(sleep_for)


@shared_task
def run_crawl(job_id):
    try:
        job = CrawlJob.objects.get(id=job_id)
    except CrawlJob.DoesNotExist:
        return

    if not is_in_scope(job.project, job.seed_url):
        job.status = "failed"
        job.save(update_fields=["status"])
        return

    job.status = "running"
    job.save(update_fields=["status"])

    # One User-Agent for the whole job, not per-request — see USER_AGENTS.
    request_headers = {"User-Agent": random.choice(USER_AGENTS)}

    limiter = _RateLimiter(job.requests_per_second)
    visited = set()
    state_lock = threading.Lock()
    queue = deque([job.seed_url])
    counter = {"pages": 0}

    def stop_requested():
        return CrawlJob.objects.filter(id=job.id, stop_requested=True).exists()

    def worker():
        while True:
            with state_lock:
                if not queue or counter["pages"] >= job.max_pages:
                    return
                url = queue.popleft()
                if url in visited:
                    continue
                visited.add(url)

            if not is_in_scope(job.project, url) or stop_requested():
                continue

            limiter.wait()

            try:
                response = send_request(job.project, "GET", url, headers=request_headers)
            except Exception:  # noqa: BLE001 — one bad page shouldn't stop the crawl
                continue

            with state_lock:
                counter["pages"] += 1
                current_count = counter["pages"]
            if current_count == 1 or current_count % 3 == 0:
                CrawlJob.objects.filter(id=job.id).update(pages_visited=current_count)

            body_text, body_is_b64 = _safe_text(response.content)
            flow = Flow.objects.create(
                project=job.project,
                method="GET",
                url=url,
                host=urlparse(url).hostname or "",
                request_headers=request_headers,
                status_code=response.status_code,
                response_headers=dict(response.headers),
                response_body=body_text,
                response_body_is_base64=body_is_b64,
            )
            flow_ingested.send(sender=Flow, flow_id=flow.id)

            content_type = response.headers.get("content-type", "")
            if "html" in content_type and not body_is_b64:
                for link in extract_links(body_text, url):
                    if urlparse(link).scheme not in ("http", "https"):
                        continue
                    with state_lock:
                        if link not in visited:
                            queue.append(link)

    threads = [threading.Thread(target=worker) for _ in range(max(1, job.concurrency))]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    job.refresh_from_db()
    job.status = "stopped" if job.stop_requested else "done"
    job.pages_visited = counter["pages"]
    job.finished_at = timezone.now()
    job.save(update_fields=["status", "pages_visited", "finished_at"])
