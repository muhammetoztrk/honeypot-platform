"""Setup wizard tests"""
import pytest
from fastapi.testclient import TestClient
from app.main import app
from app.database import SessionLocal
from app import models
from app.setup import SetupWizard

client = TestClient(app)


class TestSetupWizard:
    """Test setup wizard functionality"""
    
    def test_setup_check_not_complete(self, db):
        """Test setup check when not complete"""
        # Clear any existing users
        db.query(models.User).delete()
        db.commit()
        
        result = SetupWizard.is_setup_complete(db)
        assert result is False
    
    def test_setup_check_complete(self, db, admin_user):
        """Test setup check when complete"""
        result = SetupWizard.is_setup_complete(db)
        assert result is True
    
    def test_database_connection_test(self, db):
        """Test database connection test"""
        result = SetupWizard.test_database_connection(db)
        assert result["status"] == "success"
        assert "message" in result
    
    def test_get_database_info(self, db):
        """Test get database info"""
        result = SetupWizard.get_database_info(db)
        assert result["status"] == "success"
        assert "version" in result
        assert "table_count" in result
    
    def test_create_admin_user(self, db):
        """Test admin user creation"""
        # Clear existing users
        db.query(models.User).delete()
        db.commit()
        
        user = SetupWizard.create_admin_user(
            db=db,
            email="testadmin@test.com",
            password="testpass123"
        )
        assert user.email == "testadmin@test.com"
        assert user.role == "admin"
        assert user.id is not None
    
    def test_create_admin_user_duplicate(self, db, admin_user):
        """Test admin user creation with duplicate email"""
        with pytest.raises(ValueError, match="User already exists"):
            SetupWizard.create_admin_user(
                db=db,
                email="admin@test.com",
                password="testpass123"
            )
    
    def test_create_default_organization(self, db):
        """Test default organization creation"""
        org = SetupWizard.create_default_organization(db, "Test Org")
        assert org.name == "Test Org"
        assert org.id is not None
    
    def test_complete_setup(self, db):
        """Test complete setup"""
        # Clear existing data
        db.query(models.UserOrganization).delete()
        db.query(models.User).delete()
        db.query(models.Organization).delete()
        db.query(models.Node).delete()
        db.commit()
        
        result = SetupWizard.complete_setup(
            db=db,
            admin_email="setup@test.com",
            admin_password="setup123",
            organization_name="Test Organization"
        )
        
        assert result["status"] == "success"
        assert "admin_user_id" in result
        assert "organization_id" in result
        assert "node_id" in result
        
        # Verify user was created
        user = db.query(models.User).filter_by(email="setup@test.com").first()
        assert user is not None
        assert user.role == "admin"
    
    def test_setup_api_check_endpoint(self):
        """Test setup check API endpoint"""
        response = client.get("/api/v1/setup/check")
        assert response.status_code == 200
        assert "setup_complete" in response.json()
    
    def test_setup_api_database_info(self):
        """Test setup database info API endpoint"""
        response = client.get("/api/v1/setup/database/info")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data
    
    def test_setup_api_database_test(self):
        """Test setup database test API endpoint"""
        response = client.get("/api/v1/setup/database/test")
        assert response.status_code == 200
        data = response.json()
        assert "status" in data

