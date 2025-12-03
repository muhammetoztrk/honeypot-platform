"""Health check tests"""
import pytest
from fastapi.testclient import TestClient
from app.main import app


def test_health_check(client):
    """Test health check endpoint"""
    response = client.get("/health")
    assert response.status_code in [200, 503]  # Can be healthy or unhealthy
    assert "status" in response.json()


def test_metrics_endpoint(client, db):
    """Test metrics endpoint"""
    # Tables are already created by the client fixture
    response = client.get("/metrics")
    # Metrics endpoint should work with tables created
    assert response.status_code == 200
    assert "honeypot_events_total" in response.text

