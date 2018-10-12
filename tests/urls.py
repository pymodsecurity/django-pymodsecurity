from django.contrib import admin
from django.urls import path, re_path

from . import views

urlpatterns = [
    path('simple_test', views.simple_test),
    re_path(r'test_app/(?P<path>.*)$', views.test_app)
]
