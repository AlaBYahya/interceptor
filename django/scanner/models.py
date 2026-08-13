from django.db import models

from core.models import Project
from traffic.models import Flow

SEVERITY_CHOICES = [
    ("info", "Info"),
    ("low", "Low"),
    ("medium", "Medium"),
    ("high", "High"),
]

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3}

SOURCE_CHOICES = [
    ("passive", "Passive Scanner"),
    ("active", "Active Scanner"),
    ("nmap", "nmap"),
    ("searchsploit", "searchsploit"),
    ("nuclei", "nuclei"),
]

FINDING_REVIEW_STATUS_CHOICES = [
    ("unreviewed", "Unreviewed"),
    ("confirmed", "Confirmed"),
    ("false_positive", "False Positive"),
]


class Finding(models.Model):
    project = models.ForeignKey(Project, related_name="findings", on_delete=models.CASCADE)
    flow = models.ForeignKey(Flow, null=True, blank=True, on_delete=models.SET_NULL, related_name="findings")
    source = models.CharField(max_length=20, choices=SOURCE_CHOICES, default="passive")
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default="info")
    title = models.CharField(max_length=255)
    description = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    # Triage status, same idea as Flow.review_status — lets you mark a
    # finding as confirmed real or dismissed as a false positive without
    # deleting it.
    review_status = models.CharField(max_length=15, choices=FINDING_REVIEW_STATUS_CHOICES, default="unreviewed")

    # Denormalized from flow.host at creation time. is_structural marks
    # findings that describe a host-level property (e.g. a missing header)
    # rather than something specific to one request — the partial unique
    # constraint below dedupes those per (project, source, title, host) at
    # the database level, which is what actually makes the dedup atomic
    # under concurrent Celery workers; a plain "does this exist?" check
    # before create() races when multiple flows are processed in parallel.
    host = models.CharField(max_length=255, blank=True)
    is_structural = models.BooleanField(default=False)

    class Meta:
        ordering = ["-created_at"]
        constraints = [
            models.UniqueConstraint(
                fields=["project", "source", "title", "host"],
                condition=models.Q(is_structural=True),
                name="unique_structural_finding",
            )
        ]

    def __str__(self):
        return self.title


class ActiveScanJob(models.Model):
    STATUS_CHOICES = [
        ("pending", "Pending"),
        ("running", "Running"),
        ("done", "Done"),
        ("failed", "Failed"),
    ]

    project = models.ForeignKey(Project, related_name="active_scan_jobs", on_delete=models.CASCADE)
    target = models.CharField(max_length=255)
    checks = models.JSONField(default=list, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.target} ({self.status})"


class Vulnerability(models.Model):
    """A manually-curated, documented vulnerability — distinct from the
    automated Finding rows above (scanner signals/leads). This is what you
    actually confirmed/exploited: a name, a write-up, and the request(s)
    that demonstrate it, ready to export as a report."""

    project = models.ForeignKey(Project, related_name="vulnerabilities", on_delete=models.CASCADE)
    title = models.CharField(max_length=255)
    severity = models.CharField(max_length=10, choices=SEVERITY_CHOICES, default="medium")
    description = models.TextField(blank=True)
    flows = models.ManyToManyField(Flow, blank=True, related_name="vulnerabilities")
    created_at = models.DateTimeField(auto_now_add=True)
    updated_at = models.DateTimeField(auto_now=True)

    class Meta:
        ordering = ["-updated_at"]

    def __str__(self):
        return self.title


class Technology(models.Model):
    """A technology (server/framework/library) detected on a host from
    captured response headers/HTML — one row per (project, host, name),
    version updated in place as better evidence comes in."""

    project = models.ForeignKey(Project, related_name="technologies", on_delete=models.CASCADE)
    host = models.CharField(max_length=255, db_index=True)
    name = models.CharField(max_length=100)
    version = models.CharField(max_length=50, blank=True)
    source_flow = models.ForeignKey(Flow, null=True, blank=True, on_delete=models.SET_NULL)
    first_seen = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["host", "name"]
        constraints = [models.UniqueConstraint(fields=["project", "host", "name"], name="unique_technology")]

    def __str__(self):
        return f"{self.name} {self.version}".strip()
