import pytest

from django_pymodsecurity import middleware


def test_request_no_intervention(client):
    response = client.get('/test_app/a')

    assert response.status_code == 200
    assert response.content == b'Path: a'


def test_request_intervention(client, settings):
    setattr(
        settings, middleware.SETTINGS_NAMES['rule_lines'], '''
    SecRuleEngine On

    SecRule REQUEST_HEADERS:USER_AGENT "nikto" "log,deny,id:107,msg:'Nikto Scanners Identified'"
    ''')

    response = client.get('/test_app/url', HTTP_USER_AGENT='nikto')

    assert response.status_code == 403
    assert not response.content == b'Path: url'
