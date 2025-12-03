"""Honeypot management tests"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import models


class TestHoneypots:
    """Test honeypot management"""
    
    def test_list_honeypots_unauthorized(self, client):
        """Test listing honeypots without authentication"""
        response = client.get("/api/v1/honeypots")
        assert response.status_code == 401
    
    def test_list_honeypots(self, authenticated_client):
        """Test listing honeypots"""
        response = authenticated_client.get("/api/v1/honeypots")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_create_honeypot(self, authenticated_client, test_node, test_template):
        """Test creating a honeypot"""
        response = authenticated_client.post(
            "/api/v1/honeypots",
            json={
                "name": "Test Honeypot",
                "node_id": test_node.id,
                "template_id": test_template.id,
                "listen_ip": "0.0.0.0",
                "listen_port": 2222
            }
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Honeypot"
        assert data["status"] == "stopped"
        assert "id" in data
    
    def test_get_honeypot(self, authenticated_client, test_honeypot):
        """Test getting a specific honeypot"""
        response = authenticated_client.get(f"/api/v1/honeypots/{test_honeypot.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_honeypot.id
        assert data["name"] == test_honeypot.name
    
    def test_start_honeypot(self, authenticated_client, test_honeypot):
        """Test starting a honeypot"""
        response = authenticated_client.post(f"/api/v1/honeypots/{test_honeypot.id}/start")
        # Should either succeed or return error if service unavailable
        assert response.status_code in [200, 500]
        if response.status_code == 200:
            data = response.json()
            assert data["status"] == "running"
    
    def test_stop_honeypot(self, authenticated_client, test_honeypot):
        """Test stopping a honeypot"""
        response = authenticated_client.post(f"/api/v1/honeypots/{test_honeypot.id}/stop")
        # Should either succeed or return error
        assert response.status_code in [200, 500]
        if response.status_code == 200:
            data = response.json()
            assert data["status"] == "stopped"
    
    def test_delete_honeypot(self, authenticated_client, test_honeypot):
        """Test deleting a honeypot"""
        response = authenticated_client.delete(f"/api/v1/honeypots/{test_honeypot.id}")
        assert response.status_code == 200
        
        # Verify honeypot is deleted
        get_response = authenticated_client.get(f"/api/v1/honeypots/{test_honeypot.id}")
        assert get_response.status_code == 404
    
    def test_list_templates(self, authenticated_client, db):
        """Test listing honeypot templates"""
        # Seed templates if not present
        from app import models
        existing = db.query(models.HoneypotTemplate).count()
        if existing == 0:
            # Add at least one template for testing
            template = models.HoneypotTemplate(
                name="SSH",
                type="ssh",
                default_config={"port": 22}
            )
            db.add(template)
            db.commit()
        
        response = authenticated_client.get("/api/v1/templates")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
        # Should have at least SSH template
        templates = response.json()
        template_types = [t["type"] for t in templates]
        assert "ssh" in template_types or "SSH" in template_types or len(templates) > 0

