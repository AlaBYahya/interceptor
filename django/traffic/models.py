from django.db import models

from core.models import Project


class Flow(models.Model):
    """A single captured HTTP request/response pair from the proxy."""

    REVIEW_STATUS_CHOICES = [
        ("unreviewed", "Unreviewed"),
        ("tested", "Tested"),
        ("interesting", "Interesting"),
    ]

    project = models.ForeignKey(Project, related_name="flows", on_delete=models.CASCADE)

    method = models.CharField(max_length=10)
    url = models.TextField()
    host = models.CharField(max_length=255, db_index=True)
    request_headers = models.JSONField(default=dict)
    request_body = models.TextField(blank=True)
    request_body_is_base64 = models.BooleanField(default=False)

    status_code = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    response_body = models.TextField(blank=True)
    response_body_is_base64 = models.BooleanField(default=False)

    client_ip = models.GenericIPAddressField(null=True, blank=True)
    duration_ms = models.IntegerField(null=True, blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    note = models.TextField(blank=True)
    review_status = models.CharField(max_length=15, choices=REVIEW_STATUS_CHOICES, default="unreviewed")

    class Meta:
        ordering = ["-timestamp"]

    def __str__(self):
        return f"{self.method} {self.url} -> {self.status_code}"


class DiscoveredEndpoint(models.Model):
    """A host/path pair worth knowing about that wasn't necessarily ever
    directly requested — e.g. found by parsing a captured JavaScript file.
    Feeds the site map alongside paths actually observed in Flow traffic.
    """

    project = models.ForeignKey(Project, related_name="discovered_endpoints", on_delete=models.CASCADE)
    host = models.CharField(max_length=255, db_index=True)
    path = models.CharField(max_length=1000)
    source_flow = models.ForeignKey(
        Flow, null=True, blank=True, on_delete=models.SET_NULL, related_name="discovered_endpoints"
    )
    first_seen = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["host", "path"]
        constraints = [
            models.UniqueConstraint(fields=["project", "host", "path"], name="unique_discovered_endpoint")
        ]

    def __str__(self):
        return f"{self.host}{self.path}"


class CrawlJob(models.Model):
    """A rate-limited, concurrency-controlled link-following crawl from a
    seed URL, staying in scope. Captured pages are saved as ordinary Flow
    rows (same passive-scan/JS-discovery pipeline as proxied traffic)."""

    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("done", "Done"),
        ("failed", "Failed"),
        ("stopped", "Stopped"),
    ]

    project = models.ForeignKey(Project, related_name="crawl_jobs", on_delete=models.CASCADE)
    seed_url = models.TextField()
    max_pages = models.IntegerField(default=100)
    requests_per_second = models.FloatField(default=1.0)
    concurrency = models.IntegerField(default=1)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    pages_visited = models.IntegerField(default=0)
    stop_requested = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.seed_url} ({self.status})"
