from django.urls import path

from . import views

urlpatterns = [
    path("authorize/", views.authorize),
    path("issue_token/", views.issue_token),
]
