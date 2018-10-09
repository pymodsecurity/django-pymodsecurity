import pytest


def test_intervention_request_processConnection(middleware, get_response,
                                                request_factory):
    request = request_factory.get('/api/users')
    addr = request.META['REMOTE_ADDR']

    get_response.mock_response = 'Original response'

    rule = 'SecRuleEngine On\n'
    rule += 'SecRule REMOTE_ADDR "@ipMatch %s" "phase:0,deny,id:161"' % addr

    assert middleware.rules.load(rule) > 0, \
        middleware.rules.getParserError() or 'Failed to load rule'

    response = middleware(request)

    assert not response == get_response.mock_response
    assert response.status_code == 403


def test_intervention_request_redirect(middleware, get_response,
                                       request_factory):
    request = request_factory.get('/api/users')
    addr = request.META['REMOTE_ADDR']

    get_response.mock_response = 'Original response'

    rule = 'SecRuleEngine On\n'
    rule += 'SecRule REMOTE_ADDR "@ipMatch %s" "phase:0,redirect:http://www.example.com/failed.html,id:161"' % addr

    assert middleware.rules.load(rule) > 0, \
        middleware.rules.getParserError() or 'Failed to load rule'

    response = middleware(request)

    assert not response == get_response.mock_response
    assert response.status_code == 302
    assert response.url == 'http://www.example.com/failed.html'


def test_intervention_request_uri(middleware, get_response, request_factory):
    request = request_factory.get('/attack.php')

    get_response.mock_response = 'Original response'

    rule = 'SecRuleEngine On\n'
    rule += 'SecRule REQUEST_URI "@streq /attack.php" "id:1,phase:1,t:lowercase,deny"'

    assert middleware.rules.load(rule) > 0, \
        middleware.rules.getParserError() or 'Failed to load rule'

    response = middleware(request)

    assert not response == get_response.mock_response
    assert response.status_code == 403


def test_intervention_request_headers(middleware, get_response,
                                      request_factory):
    request = request_factory.get('/api/users', HTTP_USER_AGENT='nikto')

    get_response.mock_response = 'Original response'

    rule = 'SecRuleEngine On\n'
    rule += 'SecRule REQUEST_HEADERS:USER_AGENT "nikto" "log,deny,id:107,msg:\'Nikto Scanners Identified\'"'

    assert middleware.rules.load(rule) > 0, \
        middleware.rules.getParserError() or 'Failed to load rule'

    response = middleware(request)

    assert not response == get_response.mock_response
    assert response.status_code == 403


def test_intervention_request_body(middleware, get_response, request_factory):
    request = request_factory.post(
        '/api/users', {
            'hello': 'world',
            'attack': True
        },
        content_type='application/json')

    get_response.mock_response = 'Original response'

    rule = 'SecRuleEngine On\n'
    rule += 'SecRequestBodyAccess On\n'
    rule += 'SecRule REQUEST_BODY "@contains attack" "id:43,phase:2,deny"'

    assert middleware.rules.load(rule) > 0, \
        middleware.rules.getParserError() or 'Failed to load rule'

    response = middleware(request)

    assert not response == get_response.mock_response
    assert response.status_code == 403
