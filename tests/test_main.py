import pytest
from django.http import HttpResponse


def test_load_rule_files(get_response, mocker, settings):
    from django_pymodsecurity.middleware import PyModSecurityMiddleware
    from django_pymodsecurity.middleware import SETTINGS_NAMES

    setattr(settings, SETTINGS_NAMES['rule_files'], ['tests/data/*.conf'])

    mocker.spy(PyModSecurityMiddleware, 'load_rule_files')
    middleware = PyModSecurityMiddleware(get_response)

    PyModSecurityMiddleware.load_rule_files.assert_called_once_with(
        middleware, ['tests/data/*.conf'])
    assert middleware.rules_count == 6


def test_no_load_rule_files(get_response, mocker, settings):
    from django_pymodsecurity.middleware import PyModSecurityMiddleware
    from django_pymodsecurity.middleware import SETTINGS_NAMES

    setattr(settings, SETTINGS_NAMES['rule_files'], None)

    mocker.spy(PyModSecurityMiddleware, 'load_rule_files')
    middleware = PyModSecurityMiddleware(get_response)

    assert not PyModSecurityMiddleware.load_rule_files.called


def test_str_load_rule_files(get_response, mocker):
    from django.conf import settings
    from django_pymodsecurity.middleware import PyModSecurityMiddleware
    from django_pymodsecurity.middleware import SETTINGS_NAMES

    setattr(settings, SETTINGS_NAMES['rule_files'],
            'tests/data/basic_rules.conf')

    mocker.spy(PyModSecurityMiddleware, 'load_rule_files')
    middleware = PyModSecurityMiddleware(get_response)

    PyModSecurityMiddleware.load_rule_files.assert_called_once_with(
        middleware, ['tests/data/basic_rules.conf'])
    assert middleware.rules_count == 6


def test_load_rules(get_response, mocker, settings):
    from django_pymodsecurity.middleware import PyModSecurityMiddleware
    from django_pymodsecurity.middleware import SETTINGS_NAMES

    setattr(settings, SETTINGS_NAMES['rule_lines'], [
        'SecRule REQUEST_HEADERS:USER_AGENT "nikto" "log,deny,id:107,msg:\'Nikto Scanners Identified\'"',
        'SecRule REQUEST_BODY "@contains attack" "id:43,phase:2,deny"'
    ])

    mocker.spy(PyModSecurityMiddleware, 'load_rules')
    middleware = PyModSecurityMiddleware(get_response)

    assert middleware.rules_count == 8


def test_str_load_rules(get_response, mocker, settings):
    from django_pymodsecurity.middleware import PyModSecurityMiddleware
    from django_pymodsecurity.middleware import SETTINGS_NAMES

    setattr(
        settings, SETTINGS_NAMES['rule_lines'], '''
        SecRule REQUEST_HEADERS:USER_AGENT "nikto" "log,deny,id:107,msg:'Nikto Scanners Identified'"
        SecRule REQUEST_BODY "@contains attack" "id:43,phase:2,deny"
        ''')

    mocker.spy(PyModSecurityMiddleware, 'load_rules')
    middleware = PyModSecurityMiddleware(get_response)

    assert middleware.rules_count == 8


def test_no_intervention(middleware, get_response, request_factory):
    request = request_factory.get('/api/users')

    get_response.mock_response = HttpResponse(
        'Dummy response', content_type='text/plain')

    obtained = middleware(request)

    assert obtained == get_response.mock_response


def test_log(get_response, request_factory, mocker):
    from django_pymodsecurity.middleware import PyModSecurityMiddleware

    request = request_factory.post(
        '/api/users', {
            'hello': 'world',
            'attack': True
        },
        content_type='application/json')

    get_response.mock_response = HttpResponse('Original response')

    rule = 'SecRuleEngine On\n'
    rule += 'SecRequestBodyAccess On\n'
    rule += 'SecRule REQUEST_BODY "@contains attack" "id:43,phase:2,allow,msg:\'log test ok\'"'

    mocker.spy(PyModSecurityMiddleware, 'modsecurity_log_callback')
    middleware = PyModSecurityMiddleware(get_response)
    assert middleware.rules.load(rule) > 0, \
        middleware.rules.getParserError() or 'Failed to load rule'

    response = middleware(request)

    assert response == get_response.mock_response
    assert response.status_code == 200

    assert middleware.modsecurity_log_callback.call_count == 1
    obj, data, msg = middleware.modsecurity_log_callback.call_args_list[0][0]
    assert obj == middleware
    assert data is None
    assert 'log test ok' in msg
