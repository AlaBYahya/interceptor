from django.urls import path

from . import views

urlpatterns = [
    path("decoder/", views.decoder, name="decoder"),
    path("comparer/", views.comparer, name="comparer"),
]
