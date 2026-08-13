from django.urls import path

from . import views

urlpatterns = [
    path("", views.list_view, name="list"),
    path("new/<int:flow_pk>/", views.new_from_flow, name="new"),
    path("<int:pk>/", views.detail, name="detail"),
]
