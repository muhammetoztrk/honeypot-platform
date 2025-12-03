"""Event management tests"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import models
from datetime import datetime


class TestEvents:
    """Test event management"""
    
    def test_list_events_unauthorized(self, client):
        """Test listing events without authentication"""
        response = client.get("/api/v1/events")
        assert response.status_code == 401
    
    def test_list_events(self, authenticated_client):
        """Test listing events"""
        response = authenticated_client.get("/api/v1/events")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_list_events_with_pagination(self, authenticated_client):
        """Test listing events with pagination"""
        response = authenticated_client.get("/api/v1/events?skip=0&limit=10")
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data, list)
        assert len(data) <= 10
    
    def test_list_events_filter_by_ip(self, authenticated_client):
        """Test filtering events by IP"""
        response = authenticated_client.get("/api/v1/events?ip=1.2.3.4")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_list_events_filter_by_type(self, authenticated_client):
        """Test filtering events by type"""
        response = authenticated_client.get("/api/v1/events?event_type=ssh_login")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_export_events_csv(self, authenticated_client):
        """Test exporting events as CSV"""
        response = authenticated_client.get("/api/v1/events?format=csv")
        assert response.status_code == 200
        # CSV export might return JSON if no events, or CSV if events exist
        content_type = response.headers.get("content-type", "")
        assert "text/csv" in content_type or "application/json" in content_type
    
    def test_export_events_json(self, authenticated_client):
        """Test exporting events as JSON"""
        response = authenticated_client.get("/api/v1/events?format=json")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")
    
    def test_agent_submit_event(self, client, test_node, test_honeypot):
        """Test agent event submission"""
        # Get API key from node
        api_key = test_node.api_key
        
        from datetime import datetime
        response = client.post(
            "/api/v1/agent/event",
            json={
                "api_key": api_key,
                "honeypot_id": test_honeypot.id,
                "event_type": "ssh_login",
                "src_ip": "1.2.3.4",
                "src_port": 12345,
                "protocol": "tcp",
                "timestamp": datetime.utcnow().isoformat(),
                "payload": {"username": "test", "password": "test123"}
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert "status" in data or "event_id" in data
    
    def test_agent_submit_event_invalid_key(self, client):
        """Test agent event submission with invalid API key"""
        from datetime import datetime
        response = client.post(
            "/api/v1/agent/event",
            json={
                "api_key": "invalid_key",
                "honeypot_id": 1,
                "event_type": "ssh_login",
                "src_ip": "1.2.3.4",
                "src_port": 12345,
                "protocol": "tcp",
                "timestamp": datetime.utcnow().isoformat(),
                "payload": {}
            }
        )
        # Should return 401 for invalid API key
        assert response.status_code == 401

