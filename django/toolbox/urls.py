from django.urls import path

from . import views

urlpatterns = [
    path("", views.list_view, name="list"),
    path("<int:pk>/", views.job_detail, name="job_detail"),
]
