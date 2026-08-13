from django.db import models

from core.models import Project
from traffic.models import Flow

ATTACK_TYPE_CHOICES = [
    ("sniper", "Sniper"),
]

STATUS_CHOICES = [
    ("pending", "Pending"),
    ("running", "Running"),
    ("done", "Done"),
    ("failed", "Failed"),
]


class IntruderAttack(models.Model):
    """A fuzzing job: a base request with §insertion-points§ marked
    Burp-style, and a payload set to substitute into them."""

    project = models.ForeignKey(Project, related_name="intruder_attacks", on_delete=models.CASCADE)
    source_flow = models.ForeignKey(Flow, null=True, blank=True, on_delete=models.SET_NULL)
    label = models.CharField(max_length=255, blank=True)

    method = models.CharField(max_length=10, default="GET")
    url = models.TextField()
    headers = models.JSONField(default=dict, blank=True)
    body = models.TextField(blank=True)

    attack_type = models.CharField(max_length=20, choices=ATTACK_TYPE_CHOICES, default="sniper")
    payload_set = models.TextField(blank=True, help_text="One payload per line.")
    status = models.CharField(max_length=10, choices=STATUS_CHOICES, default="pending")
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["-created_at"]

    def __str__(self):
        return self.label or f"{self.method} {self.url}"


class IntruderResult(models.Model):
    attack = models.ForeignKey(IntruderAttack, related_name="results", on_delete=models.CASCADE)
    payload = models.TextField()

    # The exact request that was sent for this payload (method is always
    # attack.method — sniper doesn't vary it), so clicking a result can show
    # the full request, not just the response.
    request_url = models.TextField(blank=True)
    request_headers = models.JSONField(default=dict, blank=True)
    request_body = models.TextField(blank=True)

    status_code = models.IntegerField(null=True, blank=True)
    length = models.IntegerField(null=True, blank=True)
    duration_ms = models.IntegerField(null=True, blank=True)
    response_headers = models.JSONField(default=dict, blank=True)
    response_body = models.TextField(blank=True)
    error = models.TextField(blank=True)

    is_anomaly = models.BooleanField(default=False)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["id"]
