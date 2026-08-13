from django.contrib import admin

from .models import RepeaterEntry


@admin.register(RepeaterEntry)
class RepeaterEntryAdmin(admin.ModelAdmin):
    list_display = ("label", "method", "url", "response_status", "created_at", "project")
    list_filter = ("project", "method")
