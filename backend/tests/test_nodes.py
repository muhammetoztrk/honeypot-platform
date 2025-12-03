"""Node management tests"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app import models


class TestNodes:
    """Test node management"""
    
    def test_list_nodes_unauthorized(self, client):
        """Test listing nodes without authentication"""
        response = client.get("/api/v1/nodes")
        assert response.status_code == 401
    
    def test_list_nodes(self, authenticated_client):
        """Test listing nodes"""
        response = authenticated_client.get("/api/v1/nodes")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_create_node(self, authenticated_client):
        """Test creating a node"""
        response = authenticated_client.post(
            "/api/v1/nodes",
            json={"name": "Test Node"}
        )
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Test Node"
        assert "api_key" in data
        assert "id" in data
    
    def test_create_node_duplicate_name(self, authenticated_client):
        """Test creating node with duplicate name"""
        # Create first node
        authenticated_client.post(
            "/api/v1/nodes",
            json={"name": "Duplicate Node"}
        )
        
        # Try to create duplicate
        response = authenticated_client.post(
            "/api/v1/nodes",
            json={"name": "Duplicate Node"}
        )
        # Should either succeed or return 400
        assert response.status_code in [200, 400]
    
    def test_get_node(self, authenticated_client, test_node):
        """Test getting a specific node"""
        response = authenticated_client.get(f"/api/v1/nodes/{test_node.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == test_node.id
        assert data["name"] == test_node.name
    
    def test_get_node_not_found(self, authenticated_client):
        """Test getting non-existent node"""
        response = authenticated_client.get("/api/v1/nodes/99999")
        assert response.status_code == 404
    
    def test_delete_node(self, authenticated_client, test_node):
        """Test deleting a node"""
        response = authenticated_client.delete(f"/api/v1/nodes/{test_node.id}")
        assert response.status_code == 200
        
        # Verify node is deleted
        get_response = authenticated_client.get(f"/api/v1/nodes/{test_node.id}")
        assert get_response.status_code == 404
    
    def test_delete_node_with_honeypots(self, authenticated_client, test_node, test_honeypot):
        """Test deleting node with associated honeypots"""
        response = authenticated_client.delete(f"/api/v1/nodes/{test_node.id}")
        # Should either succeed (cascade delete) or return 400
        assert response.status_code in [200, 400]

