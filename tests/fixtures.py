import os

import pytest
from django.test import RequestFactory, override_settings

import ModSecurity
from django_pymodsecurity.middleware import PyModSecurityMiddleware


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
