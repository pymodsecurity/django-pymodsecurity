import os

import pytest

import ModSecurity

from django.conf import settings
from django.test import RequestFactory, override_settings

from django_pymodsecurity.middleware import PyModSecurityMiddleware

settings.configure()

class GetResponseMock(object):
    def __init__(self, mock_response=None):
        self.mock_response = mock_response

    def __call__(self, request):
        return self.mock_response

@pytest.fixture
def get_response():
    return GetResponseMock()

@pytest.fixture
def middleware(get_response):
    return PyModSecurityMiddleware(get_response)

@pytest.fixture
def request_factory():
    return RequestFactory()

