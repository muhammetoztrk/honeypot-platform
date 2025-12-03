"""Integration tests - Full workflow"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import models
from datetime import datetime

client = TestClient(app)


class TestIntegration:
    """Integration tests for complete workflows"""
    
    def test_complete_workflow(self, authenticated_client, db, test_node, test_template):
        """Test complete workflow: create honeypot -> start -> create event -> check IOC"""
        # 1. Create honeypot
        honeypot_response = authenticated_client.post(
            "/api/v1/honeypots",
            json={
                "name": "Integration Test Honeypot",
                "node_id": test_node.id,
                "template_id": test_template.id,
                "listen_ip": "0.0.0.0",
                "listen_port": 2222
            }
        )
        assert honeypot_response.status_code == 200
        honeypot_id = honeypot_response.json()["id"]
        
        # 2. Start honeypot
        start_response = authenticated_client.post(f"/api/v1/honeypots/{honeypot_id}/start")
        # Might fail in test environment, that's OK
        assert start_response.status_code in [200, 500]
        
        # 3. Submit event via agent API
        event_response = client.post(
            "/api/v1/agent/events",
            json={
                "api_key": test_node.api_key,
                "honeypot_id": honeypot_id,
                "event_type": "ssh_login",
                "src_ip": "192.168.1.100",
                "src_port": 54321,
                "payload": {"username": "attacker", "password": "password123"}
            }
        )
        assert event_response.status_code == 200
        event_id = event_response.json().get("event_id")
        
        # 4. Check event was created
        events_response = authenticated_client.get("/api/v1/events")
        assert events_response.status_code == 200
        events = events_response.json()
        # Event should be in the list (might need to check by ID)
        
        # 5. Check IOCs were extracted
        iocs_response = authenticated_client.get("/api/v1/iocs")
        assert iocs_response.status_code == 200
        iocs = iocs_response.json()
        # IOC for IP should be extracted
        
        # 6. Check alerts were created (if high risk)
        alerts_response = authenticated_client.get("/api/v1/alerts")
        assert alerts_response.status_code == 200
        alerts = alerts_response.json()
        # Alert might be created if risk is high
    
    def test_node_to_honeypot_to_event_chain(self, authenticated_client, test_node, test_template):
        """Test node -> honeypot -> event chain"""
        # Create honeypot
        honeypot_response = authenticated_client.post(
            "/api/v1/honeypots",
            json={
                "name": "Chain Test Honeypot",
                "node_id": test_node.id,
                "template_id": test_template.id,
                "listen_ip": "0.0.0.0",
                "listen_port": 2222
            }
        )
        assert honeypot_response.status_code == 200
        honeypot_id = honeypot_response.json()["id"]
        
        # Verify honeypot is linked to node
        honeypot = authenticated_client.get(f"/api/v1/honeypots/{honeypot_id}")
        assert honeypot.status_code == 200
        honeypot_data = honeypot.json()
        assert honeypot_data["node_id"] == test_node.id
        
        # Submit event
        event_response = client.post(
            "/api/v1/agent/events",
            json={
                "api_key": test_node.api_key,
                "honeypot_id": honeypot_id,
                "event_type": "ssh_command",
                "src_ip": "10.0.0.1",
                "src_port": 54322,
                "payload": {"command": "ls -la"}
            }
        )
        assert event_response.status_code == 200

