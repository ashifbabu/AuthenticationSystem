import pytest
from fastapi.testclient import TestClient
from app.main import app


def test_api_root():
    """Test that the API root endpoint returns a 404."""
    client = TestClient(app)
    response = client.get("/")
    assert response.status_code == 404


def test_api_v1():
    """Test that the API v1 endpoint returns a 404."""
    client = TestClient(app)
    response = client.get("/api/v1")
    assert response.status_code == 404 