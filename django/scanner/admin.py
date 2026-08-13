from django.contrib import admin

from .models import ActiveScanJob, Finding


@admin.register(Finding)
class FindingAdmin(admin.ModelAdmin):
    list_display = ("title", "severity", "source", "project", "created_at")
    list_filter = ("project", "severity", "source")
    search_fields = ("title", "description")


@admin.register(ActiveScanJob)
class ActiveScanJobAdmin(admin.ModelAdmin):
    list_display = ("target", "status", "project", "created_at")
    list_filter = ("project", "status")
