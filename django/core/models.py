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
    rules = models.TextField(blank=True, help_text="Testing rules/policy: hours, rate limits, disallowed actions, disclosure terms, etc.")
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
    """An authorized target pattern for a project, or an explicit exclusion.

    `pattern` is either a host glob (e.g. "*.example.com", "example.com")
    or a CIDR range (e.g. "10.0.0.0/8"). See core/scope.py for matching.

    `exclude` entries take precedence over in-scope ones — this is how a
    program's "*.example.com, except www/support.example.com" carve-outs get
    expressed, since a plain allow-list of globs can't represent that on its
    own.
    """

    project = models.ForeignKey(Project, related_name="scope_entries", on_delete=models.CASCADE)
    pattern = models.CharField(max_length=255)
    note = models.CharField(max_length=255, blank=True)
    exclude = models.BooleanField(
        default=False,
        help_text="Explicitly out of scope, overriding any in-scope pattern above it also matches (e.g. a wildcard carve-out).",
    )
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

    By default only added when the target request doesn't already set that
    header name, so anything explicitly set on a given send always wins. Set
    `append_to_existing` for headers that need to be appended to an
    already-present value instead (e.g. a bug-bounty program that requires
    a suffix tacked onto the real User-Agent rather than replacing it —
    User-Agent is essentially always already set by the browser/tool, so
    "only add if missing" would never fire for it).
    """

    project = models.ForeignKey(Project, related_name="custom_headers", on_delete=models.CASCADE)
    name = models.CharField(max_length=255)
    value = models.CharField(max_length=1000)
    append_to_existing = models.BooleanField(
        default=False,
        help_text="Append this value to the header if it's already set, instead of only adding it when missing.",
    )
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
