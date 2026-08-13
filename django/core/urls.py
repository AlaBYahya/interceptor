from django.urls import path

from . import views

urlpatterns = [
    path("", views.project_list, name="project_list"),
    path("new/", views.project_create, name="project_create"),
    path("<int:pk>/edit/", views.project_edit, name="project_edit"),
    path("<int:pk>/activate/", views.project_activate, name="project_activate"),
    path("<int:pk>/delete/", views.project_delete, name="project_delete"),
    path("<int:pk>/export/", views.project_export, name="project_export"),
    path("import/", views.project_import, name="project_import"),
    path("scope/", views.scope_list, name="scope_list"),
    path("scope/<int:pk>/delete/", views.scope_delete, name="scope_delete"),
    path("scope/capture-mode/", views.set_capture_mode, name="set_capture_mode"),
    path("headers/", views.header_list, name="header_list"),
    path("headers/<int:pk>/delete/", views.header_delete, name="header_delete"),
    path("notes/", views.notes_list, name="notes_list"),
    path("notes/<int:pk>/edit/", views.note_edit, name="note_edit"),
    path("notes/<int:pk>/delete/", views.note_delete, name="note_delete"),
]
