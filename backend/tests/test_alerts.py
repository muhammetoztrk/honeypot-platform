"""Alert system tests"""
import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from app.main import app
from app import models

client = TestClient(app)


class TestAlerts:
    """Test alert system"""
    
    def test_list_alerts_unauthorized(self):
        """Test listing alerts without authentication"""
        response = client.get("/api/v1/alerts")
        assert response.status_code == 401
    
    def test_list_alerts(self, authenticated_client):
        """Test listing alerts"""
        response = authenticated_client.get("/api/v1/alerts")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_list_unread_alerts(self, authenticated_client):
        """Test listing only unread alerts"""
        response = authenticated_client.get("/api/v1/alerts?unread_only=true")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_create_alert(self, authenticated_client, db, test_honeypot):
        """Test creating an alert"""
        # Create a test event first
        event = models.Event(
            honeypot_id=test_honeypot.id,
            event_type="ssh_login",
            source_ip="1.2.3.4",
            details={"username": "test"},
            timestamp=datetime.utcnow()
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        
        response = authenticated_client.post(
            "/api/v1/alerts",
            json={
                "event_id": event.id,
                "honeypot_id": test_honeypot.id,
                "message": "Test alert",
                "severity": "high"
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["message"] == "Test alert"
        assert data["severity"] == "high"
    
    def test_mark_alert_as_read(self, authenticated_client, db):
        """Test marking alert as read"""
        # Create a test alert
        alert = models.Alert(
            event_id=1,
            honeypot_id=1,
            message="Test alert",
            severity="high",
            status="unread",
            timestamp=datetime.utcnow()
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        
        response = authenticated_client.put(f"/api/v1/alerts/{alert.id}/read")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "read"

