from django.contrib import admin

from .models import IntruderAttack, IntruderResult


class IntruderResultInline(admin.TabularInline):
    model = IntruderResult
    extra = 0


@admin.register(IntruderAttack)
class IntruderAttackAdmin(admin.ModelAdmin):
    list_display = ("label", "method", "url", "attack_type", "status", "project", "created_at")
    list_filter = ("project", "status")
    inlines = [IntruderResultInline]
