from django.urls import path

from . import crawler_views, views

urlpatterns = [
    path("", views.history, name="history"),
    path("sitemap/", views.sitemap, name="sitemap"),
    path("clear/", views.history_clear, name="history_clear"),
    path("delete-selected/", views.flow_delete_selected, name="flow_delete_selected"),
    path("crawler/", crawler_views.crawler_list, name="crawler"),
    path("crawler/<int:pk>/stop/", crawler_views.crawler_stop, name="crawler_stop"),
    path("<int:pk>/", views.flow_detail, name="flow_detail"),
    path("<int:pk>/update/", views.flow_update, name="flow_update"),
    path("<int:pk>/delete/", views.flow_delete, name="flow_delete"),
]
