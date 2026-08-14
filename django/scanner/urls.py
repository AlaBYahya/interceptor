from django.urls import path

from . import views, vuln_views

urlpatterns = [
    path("", views.findings, name="findings"),
    path("<int:pk>/", views.finding_detail, name="finding_detail"),
    path("<int:pk>/update/", views.finding_update, name="finding_update"),
    path("export/", views.export_findings, name="export_findings"),
    path("technologies/", views.technologies, name="technologies"),
    path("active/", views.active_scan, name="active_scan"),
    path("vulnerabilities/", vuln_views.vulnerabilities_list, name="vulnerabilities"),
    path("vulnerabilities/export/", vuln_views.export_vulnerabilities, name="export_vulnerabilities"),
    path("vulnerabilities/<int:pk>/", vuln_views.vulnerability_detail, name="vulnerability_detail"),
    path("vulnerabilities/<int:pk>/delete/", vuln_views.vulnerability_delete, name="vulnerability_delete"),
    path(
        "vulnerabilities/<int:pk>/remove-flow/<int:flow_pk>/",
        vuln_views.vulnerability_remove_flow,
        name="vulnerability_remove_flow",
    ),
    path(
        "vulnerabilities/save-flow/<int:flow_pk>/",
        vuln_views.flow_save_to_vulnerability,
        name="flow_save_to_vulnerability",
    ),
]
