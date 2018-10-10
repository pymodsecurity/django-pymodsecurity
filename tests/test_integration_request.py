import pytest


@pytest.mark.wip
@pytest.mark.timeout(-1)
def test_request(client):
    response = client.get('/')

    print(response)
