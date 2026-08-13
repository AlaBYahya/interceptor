from django.contrib import admin

from .models import ScanJob


@admin.register(ScanJob)
class ScanJobAdmin(admin.ModelAdmin):
    list_display = ("tool", "target", "query", "status", "project", "created_at")
    list_filter = ("project", "tool", "status")
