"""Alert system tests"""
import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from app.main import app
from app import models

client = TestClient(app)


class TestAlerts:
    """Test alert system"""
    
    def test_list_alerts_unauthorized(self, client):
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
        # Create a session first
        session = models.Session(
            honeypot_id=test_honeypot.id,
            src_ip="1.2.3.4",
            src_port=12345,
            protocol="tcp",
            started_at=datetime.utcnow()
        )
        db.add(session)
        db.commit()
        db.refresh(session)
        
        event = models.Event(
            session_id=session.id,
            honeypot_id=test_honeypot.id,
            event_type="ssh_login",
            src_ip="1.2.3.4",
            dst_port=2222,
            payload={"username": "test"}
        )
        db.add(event)
        db.commit()
        db.refresh(event)
        
        # Alerts are typically created automatically, but we can test creating one directly
        alert = models.Alert(
            event_id=event.id,
            title="Test Alert",
            message="Test alert message",
            severity="high"
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        assert alert is not None
        assert alert.message == "Test alert message"
        assert alert.severity == "high"
    
    def test_mark_alert_as_read(self, authenticated_client, db):
        """Test marking alert as read"""
        # Create a test alert
        alert = models.Alert(
            event_id=1,
            title="Test Alert",
            message="Test alert message",
            severity="high",
            read=False
        )
        db.add(alert)
        db.commit()
        db.refresh(alert)
        
        response = authenticated_client.post(f"/api/v1/alerts/{alert.id}/read")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] == "ok"
        
        # Verify alert is marked as read
        db.refresh(alert)
        assert alert.read is True

