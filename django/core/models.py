from django.db import models


class Project(models.Model):
    """A workspace. Captured traffic, findings, and jobs all belong to one.

    Exactly one project is "active" at a time — that's the project the
    mitmproxy ingest addon attaches newly captured flows to, since the addon
    has no concept of which project you're currently working in.
    """

    CAPTURE_ALL = "all"
    CAPTURE_IN_SCOPE_ONLY = "in_scope"
    CAPTURE_MODE_CHOICES = [
        (CAPTURE_ALL, "Save all proxied traffic"),
        (CAPTURE_IN_SCOPE_ONLY, "Save in-scope traffic only"),
    ]

    name = models.CharField(max_length=200, unique=True)
    description = models.TextField(blank=True)
    is_active = models.BooleanField(default=False)
    capture_mode = models.CharField(max_length=10, choices=CAPTURE_MODE_CHOICES, default=CAPTURE_ALL)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return self.name

    def save(self, *args, **kwargs):
        super().save(*args, **kwargs)
        if self.is_active:
            Project.objects.exclude(pk=self.pk).update(is_active=False)

    @classmethod
    def get_active(cls):
        project = cls.objects.filter(is_active=True).first()
        if project is None:
            project, _ = cls.objects.get_or_create(
                name="Default", defaults={"is_active": True}
            )
            if not project.is_active:
                project.is_active = True
                project.save()
        return project


class ScopeEntry(models.Model):
    """An authorized target pattern for a project.

    `pattern` is either a host glob (e.g. "*.example.com", "example.com")
    or a CIDR range (e.g. "10.0.0.0/8"). See core/scope.py for matching.
    """

    project = models.ForeignKey(Project, related_name="scope_entries", on_delete=models.CASCADE)
    pattern = models.CharField(max_length=255)
    note = models.CharField(max_length=255, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["pattern"]
        verbose_name_plural = "scope entries"

    def __str__(self):
        return self.pattern


class CustomHeader(models.Model):
    """A header to inject into outbound traffic for a project — most
    commonly a bug-bounty program's required identification header (e.g.
    "X-Bug-Bounty: your-handle"), but usable for anything (custom auth
    tokens, etc.).

    Only added when the target request doesn't already set that header name,
    so anything explicitly set on a given send always wins.
    """

    project = models.ForeignKey(Project, related_name="custom_headers", on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    value = models.CharField(max_length=1000)
    apply_to_proxy_traffic = models.BooleanField(
        default=True,
        help_text="Inject into every request passing through the intercepting proxy (real browsing/tool traffic).",
    )
    apply_to_tool_traffic = models.BooleanField(
        default=True,
        help_text="Inject when Repeater/Intruder/Active Scanner send a request directly.",
    )
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ["name"]

    def __str__(self):
        return f"{self.name}: {self.value}"
