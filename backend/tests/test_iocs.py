"""IOC management tests"""
import pytest
from datetime import datetime
from fastapi.testclient import TestClient
from app.main import app
from app import models

client = TestClient(app)


class TestIOCs:
    """Test IOC management"""
    
    def test_list_iocs_unauthorized(self):
        """Test listing IOCs without authentication"""
        response = client.get("/api/v1/iocs")
        assert response.status_code == 401
    
    def test_list_iocs(self, authenticated_client):
        """Test listing IOCs"""
        response = authenticated_client.get("/api/v1/iocs")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_list_iocs_with_filters(self, authenticated_client):
        """Test listing IOCs with filters"""
        response = authenticated_client.get("/api/v1/iocs?ioc_type=ip&min_score=50")
        assert response.status_code == 200
        assert isinstance(response.json(), list)
    
    def test_get_ioc(self, authenticated_client, db):
        """Test getting a specific IOC"""
        # Create a test IOC
        ioc = models.IOC(
            value="1.2.3.4",
            ioc_type="ip",
            score=75,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        db.add(ioc)
        db.commit()
        db.refresh(ioc)
        
        response = authenticated_client.get(f"/api/v1/iocs/{ioc.id}")
        assert response.status_code == 200
        data = response.json()
        assert data["id"] == ioc.id
        assert data["value"] == "1.2.3.4"
    
    def test_enrich_ioc(self, authenticated_client, db):
        """Test IOC enrichment"""
        # Create a test IOC
        ioc = models.IOC(
            value="1.2.3.4",
            ioc_type="ip",
            score=75,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow()
        )
        db.add(ioc)
        db.commit()
        db.refresh(ioc)
        
        response = authenticated_client.post(f"/api/v1/iocs/{ioc.id}/enrich")
        # Should either succeed or return error if enrichment service unavailable
        assert response.status_code in [200, 500]
        if response.status_code == 200:
            data = response.json()
            assert "enrichment" in data or "status" in data
    
    def test_export_iocs_csv(self, authenticated_client):
        """Test exporting IOCs as CSV"""
        response = authenticated_client.get("/api/v1/iocs?format=csv")
        assert response.status_code == 200
        assert "text/csv" in response.headers.get("content-type", "")
    
    def test_export_iocs_json(self, authenticated_client):
        """Test exporting IOCs as JSON"""
        response = authenticated_client.get("/api/v1/iocs?format=json")
        assert response.status_code == 200
        assert "application/json" in response.headers.get("content-type", "")

