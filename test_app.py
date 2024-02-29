#ZAHID JAMAL
import pytest
import json
from app import app

@pytest.fixture
def client():
    # Set the Flask app in testing mode
    app.config['TESTING'] = True
    with app.test_client() as client:
        # Provide a test client to use in tests
        yield client

def test_auth(client):
    # Send a POST request to the /auth endpoint
    response = client.post('/auth')
    # Check if the response status code is 200
    assert response.status_code == 200
    # Load the response data as JSON
    data = json.loads(response.data)
    # Check if the response contains a 'token' key
    assert 'token' in data

def test_jwks(client):
    # Send a GET request to the /.well-known/jwks.json endpoint
    response = client.get('/.well-known/jwks.json')
    # Check if the response status code is 200
    assert response.status_code == 200
    # Load the response data as JSON
    data = json.loads(response.data)
    # Check if the response contains a 'keys' key
    assert 'keys' in data
