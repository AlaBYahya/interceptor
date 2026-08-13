from django.db import models

from core.models import Project

TOOL_CHOICES = [
    ("nmap", "nmap"),
    ("searchsploit", "searchsploit"),
    ("nuclei", "nuclei"),
    ("nuclei_update", "nuclei template update"),
]

STATUS_CHOICES = [
    ("pending", "Pending"),
    ("running", "Running"),
    ("done", "Done"),
    ("failed", "Failed"),
]


class ScanJob(models.Model):
    """A single external-tool run.

    `target` is a host/IP/CIDR (scope-checked for nmap/nuclei); `query` is a
    free-text search term for searchsploit (service/version string — no
    network scope check needed, it's a local exploit-db lookup).

    Scaffolded — the tasks in tasks.py are not implemented yet.
    """

    project = models.ForeignKey(Project, related_name="scan_jobs", on_delete=models.CASCADE)
    tool = models.CharField(max_length=20, choices=TOOL_CHOICES)
    target = models.CharField(max_length=255, blank=True)
    query = models.CharField(max_length=255, blank=True)
    args = models.JSONField(default=list, blank=True)
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    raw_output = models.TextField(blank=True)
    created_at = models.DateTimeField(auto_now_add=True)
    finished_at = models.DateTimeField(null=True, blank=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return f"{self.tool}: {self.target or self.query} ({self.status})"
