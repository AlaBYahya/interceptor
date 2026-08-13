from django.contrib import admin
from django.contrib.auth import views as auth_views
from django.urls import include, path
from django.views.generic import RedirectView

from core.views import api_custom_headers
from traffic.views import ingest_flow

urlpatterns = [
    path("admin/", admin.site.urls),
    path("accounts/login/", auth_views.LoginView.as_view(template_name="registration/login.html"), name="login"),
    path("accounts/logout/", auth_views.LogoutView.as_view(), name="logout"),
    path("", RedirectView.as_view(pattern_name="traffic:history", permanent=False)),
    path("projects/", include(("core.urls", "core"), namespace="core")),
    path("traffic/", include(("traffic.urls", "traffic"), namespace="traffic")),
    path("api/flows/ingest/", ingest_flow, name="ingest_flow"),
    path("api/custom-headers/", api_custom_headers, name="api_custom_headers"),
    path("repeater/", include(("repeater.urls", "repeater"), namespace="repeater")),
    path("intruder/", include(("intruder.urls", "intruder"), namespace="intruder")),
    path("scanner/", include(("scanner.urls", "scanner"), namespace="scanner")),
    path("toolbox/", include(("toolbox.urls", "toolbox"), namespace="toolbox")),
    path("tools/", include(("utils.urls", "utils"), namespace="utils")),
]
