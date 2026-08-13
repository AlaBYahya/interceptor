from django.db import models

from core.models import Project
from traffic.models import Flow


class RepeaterEntry(models.Model):
    project = models.ForeignKey(Project, related_name="repeater_entries", on_delete=models.CASCADE)
    source_flow = models.ForeignKey(Flow, null=True, blank=True, on_delete=models.SET_NULL)
    label = models.CharField(max_length=255, blank=True)

    method = models.CharField(max_length=10, default="GET")
    url = models.TextField()
    headers = models.JSONField(default=dict, blank=True)
    body = models.TextField(blank=True)

    response_status = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    response_body = models.TextField(blank=True)
    error = models.TextField(blank=True)

    sent_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.label or f"{self.method} {self.url}"
