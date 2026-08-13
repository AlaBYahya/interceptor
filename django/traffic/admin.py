from django.contrib import admin

from .models import Flow


@admin.register(Flow)
class FlowAdmin(admin.ModelAdmin):
    list_display = ("method", "host", "url", "status_code", "timestamp", "project")
    list_filter = ("project", "method", "status_code")
    search_fields = ("host", "url")
