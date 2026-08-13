from django.contrib import admin

from .models import CustomHeader, Project, ScopeEntry


class ScopeEntryInline(admin.TabularInline):
    model = ScopeEntry
    extra = 1


class CustomHeaderInline(admin.TabularInline):
    model = CustomHeader
    extra = 1


@admin.register(Project)
class ProjectAdmin(admin.ModelAdmin):
    list_display = ("name", "is_active", "created_at")
    inlines = [ScopeEntryInline, CustomHeaderInline]


@admin.register(ScopeEntry)
class ScopeEntryAdmin(admin.ModelAdmin):
    list_display = ("pattern", "project", "note", "created_at")
    list_filter = ("project",)


@admin.register(CustomHeader)
class CustomHeaderAdmin(admin.ModelAdmin):
    list_display = ("name", "value", "project", "apply_to_proxy_traffic", "apply_to_tool_traffic")
    list_filter = ("project",)
