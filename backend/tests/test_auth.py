"""Authentication tests"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


def test_register_user():
    """Test user registration"""
    response = client.post(
        "/api/v1/auth/register",
        json={
            "email": "test@example.com",
            "password": "testpass123",
        },
    )
    assert response.status_code in [200, 400]  # 400 if user exists


def test_login():
    """Test user login"""
    # First register
    client.post(
        "/api/v1/auth/register",
        json={
            "email": "testlogin@example.com",
            "password": "testpass123",
        },
    )
    
    # Then login
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "testlogin@example.com",
            "password": "testpass123",
        },
    )
    assert response.status_code == 200
    assert "access_token" in response.json()

