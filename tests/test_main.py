import pytest

def test_load_rules(get_response, mocker):
    from django.conf import settings
    from django_pymodsecurity.middleware import PyModSecurityMiddleware
    from django_pymodsecurity.middleware import SETTINGS_NAMES

    setattr(settings, SETTINGS_NAMES['rule_files'], ['tests/data/*.conf'])

    mocker.spy(PyModSecurityMiddleware, 'load_rules')
    middleware = PyModSecurityMiddleware(get_response)

    PyModSecurityMiddleware.load_rules.assert_called_once_with(middleware, ['tests/data/*.conf'])
    assert middleware.rules_count == 6

def test_no_load_rules(get_response, mocker):
    from django.conf import settings
    from django_pymodsecurity.middleware import PyModSecurityMiddleware
    from django_pymodsecurity.middleware import SETTINGS_NAMES

    setattr(settings, SETTINGS_NAMES['rule_files'], None)

    mocker.spy(PyModSecurityMiddleware, 'load_rules')
    middleware = PyModSecurityMiddleware(get_response)

    assert not PyModSecurityMiddleware.load_rules.called

def test_str_load_rules(get_response, mocker):
    from django.conf import settings
    from django_pymodsecurity.middleware import PyModSecurityMiddleware
    from django_pymodsecurity.middleware import SETTINGS_NAMES

    setattr(settings, SETTINGS_NAMES['rule_files'], 'tests/data/basic_rules.conf')

    mocker.spy(PyModSecurityMiddleware, 'load_rules')
    middleware = PyModSecurityMiddleware(get_response)

    PyModSecurityMiddleware.load_rules.assert_called_once_with(middleware, ['tests/data/basic_rules.conf'])
    assert middleware.rules_count == 6

def test_no_intervention(middleware, get_response, request_factory):
    request = request_factory.get('/api/users')

    get_response.mock_response = 'Dummy value'

    obtained = middleware(request)

    assert obtained == get_response.mock_response
