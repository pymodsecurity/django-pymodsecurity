import pytest
from django.http import HttpResponse


def test_intervention_response_headers(middleware, get_response,
                                       request_factory):
    request = request_factory.get('/api/users')

    get_response.mock_response = HttpResponse(
        'Hello world', content_type='text/plain')
    get_response.mock_response['X-Cache'] = 'MISS'

    rule = 'SecRuleEngine On\n'
    rule += 'SecRule RESPONSE_HEADERS:X-Cache "MISS" "phase:3,id:55,deny"'

    assert middleware.rules.load(rule) > 0, \
        middleware.rules.getParserError() or 'Failed to load rule'

    response = middleware(request)

    assert not response == get_response.mock_response
    assert response.status_code == 403


def test_intervention_response_status_code(middleware, get_response,
                                           request_factory):
    request = request_factory.get('/api/users')

    get_response.mock_response = HttpResponse(
        'Hello world', content_type='text/plain', status=503)

    rule = 'SecRuleEngine On\n'
    rule += 'SecRule RESPONSE_STATUS "@streq 503" "phase:3,id:58,deny"'

    assert middleware.rules.load(rule) > 0, \
        middleware.rules.getParserError() or 'Failed to load rule'

    response = middleware(request)

    assert not response == get_response.mock_response
    assert response.status_code == 403


def test_intervention_response_body(middleware, get_response, request_factory):
    request = request_factory.get('/api/users')

    get_response.mock_response = HttpResponse(
        'Hello world + Leaked data', content_type='text/plain')

    rule = 'SecRuleEngine On\n'
    rule += 'SecResponseBodyAccess On\n'
    rule += 'SecRule RESPONSE_BODY "Leaked data" "deny,phase:4,id:54"'

    assert middleware.rules.load(rule) > 0, \
        middleware.rules.getParserError() or 'Failed to load rule'

    response = middleware(request)

    assert not response == get_response.mock_response
    assert response.status_code == 403


def test_intervention_response_redirect(middleware, get_response,
                                        request_factory):
    request = request_factory.get('/api/users')

    get_response.mock_response = HttpResponse(
        'Hello world', content_type='text/plain')
    get_response.mock_response['X-Cache'] = 'MISS'

    rule = 'SecRuleEngine On\n'
    rule += 'SecRule RESPONSE_HEADERS:X-Cache "MISS" "phase:3,redirect:http://www.example.com/failed.html,id:161"'

    assert middleware.rules.load(rule) > 0, \
        middleware.rules.getParserError() or 'Failed to load rule'

    response = middleware(request)

    assert not response == get_response.mock_response
    assert response.status_code == 302
    assert response.url == 'http://www.example.com/failed.html'
