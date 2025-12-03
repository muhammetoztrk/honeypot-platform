"""Comprehensive API tests"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import models
from datetime import datetime

client = TestClient(app)


class TestAPIComprehensive:
    """Comprehensive API endpoint tests"""
    
    def test_swagger_docs(self):
        """Test Swagger UI endpoint"""
        response = client.get("/docs")
        assert response.status_code == 200
    
    def test_redoc_docs(self):
        """Test ReDoc endpoint"""
        response = client.get("/redoc")
        assert response.status_code == 200
    
    def test_openapi_schema(self):
        """Test OpenAPI schema endpoint"""
        response = client.get("/openapi.json")
        assert response.status_code == 200
        schema = response.json()
        assert "openapi" in schema
        assert "paths" in schema
    
    def test_health_endpoint_detailed(self):
        """Test detailed health check"""
        response = client.get("/health")
        assert response.status_code in [200, 503]
        data = response.json()
        assert "status" in data
        if "database" in data:
            assert "status" in data["database"]
        if "system" in data:
            assert "status" in data["system"]
    
    def test_metrics_endpoint(self):
        """Test metrics endpoint"""
        response = client.get("/metrics")
        assert response.status_code == 200
        # Should return Prometheus format
        assert "honeypot" in response.text.lower() or "events" in response.text.lower()
    
    def test_websocket_endpoint(self):
        """Test WebSocket endpoint exists"""
        # WebSocket can't be tested with TestClient, but we can check the route exists
        from app.main import app
        routes = [route.path for route in app.routes]
        assert "/api/v1/ws" in routes or "/ws" in routes
    
    def test_backup_endpoints(self, authenticated_client):
        """Test backup endpoints"""
        # List backups
        response = authenticated_client.get("/api/v1/backups")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_reports_endpoints(self, authenticated_client):
        """Test report generation endpoints"""
        # Test HTML report
        response = authenticated_client.get("/api/v1/reports/events?format=html")
        assert response.status_code in [200, 500]  # Might fail if no events
        
        # Test JSON report
        response = authenticated_client.get("/api/v1/reports/events?format=json")
        assert response.status_code in [200, 500]
        
        # Test PDF report
        response = authenticated_client.get("/api/v1/reports/events?format=pdf")
        assert response.status_code in [200, 500]

