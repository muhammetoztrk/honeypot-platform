"""Test configuration and fixtures"""
import pytest
import os
import sys
from fastapi.testclient import TestClient
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

# Set test environment variables BEFORE importing app modules
os.environ["DATABASE_URL"] = "sqlite:///:memory:"
os.environ["JWT_SECRET"] = "test-secret-key-for-testing-only"
os.environ["SKIP_INDEX_CREATION"] = "1"  # Skip index creation in tests

# Now import app modules
from app.database import Base, get_db
from app import models
from app.auth import hash_password

# Import app after setting environment
from app.main import app


# In-memory SQLite database for testing
SQLALCHEMY_DATABASE_URL = "sqlite:///:memory:"

engine = create_engine(
    SQLALCHEMY_DATABASE_URL,
    connect_args={"check_same_thread": False},
    poolclass=StaticPool,
)
TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


@pytest.fixture(scope="function")
def db():
    """Create a fresh database for each test"""
    # Drop all tables and indexes first to ensure clean state
    try:
        with engine.connect() as conn:
            # Drop all indexes manually for SQLite
            result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"))
            index_names = [row[0] for row in result]
            for idx_name in index_names:
                try:
                    conn.execute(text(f"DROP INDEX IF EXISTS {idx_name}"))
                except:
                    pass
            conn.commit()
    except:
        pass
    
    # Drop all tables
    Base.metadata.drop_all(bind=engine)
    
    # Create all tables fresh (indexes from models will be created automatically)
    Base.metadata.create_all(bind=engine)
    
    db = TestingSessionLocal()
    try:
        yield db
    finally:
        db.close()
        # Clean up after test
        try:
            with engine.connect() as conn:
                result = conn.execute(text("SELECT name FROM sqlite_master WHERE type='index' AND name NOT LIKE 'sqlite_%'"))
                index_names = [row[0] for row in result]
                for idx_name in index_names:
                    try:
                        conn.execute(text(f"DROP INDEX IF EXISTS {idx_name}"))
                    except:
                        pass
                conn.commit()
        except:
            pass
        Base.metadata.drop_all(bind=engine)


@pytest.fixture(scope="function")
def client(db):
    """Create a test client with database override"""
    def override_get_db():
        try:
            yield db
        finally:
            pass
    
    # Override database dependency
    app.dependency_overrides[get_db] = override_get_db
    
    with TestClient(app) as test_client:
        yield test_client
    
    # Cleanup
    app.dependency_overrides.clear()


@pytest.fixture(scope="function")
def admin_user(db):
    """Create an admin user for testing"""
    user = models.User(
        email="admin@test.com",
        password_hash=hash_password("admin123"),
        role="admin"
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    return user


@pytest.fixture(scope="function")
def auth_token(client, admin_user):
    """Get authentication token"""
    response = client.post(
        "/api/v1/auth/login",
        json={
            "email": "admin@test.com",
            "password": "admin123"
        }
    )
    if response.status_code == 200:
        return response.json()["access_token"]
    return None


@pytest.fixture(scope="function")
def authenticated_client(client, auth_token):
    """Create authenticated test client"""
    client.headers.update({"Authorization": f"Bearer {auth_token}"})
    return client


@pytest.fixture(scope="function")
def test_node(db, admin_user):
    """Create a test node"""
    import secrets
    node = models.Node(
        name="Test Node",
        api_key=secrets.token_urlsafe(24)  # Reduced from 32 to 24
    )
    db.add(node)
    db.commit()
    db.refresh(node)
    return node


@pytest.fixture(scope="function")
def test_template(db):
    """Create a test honeypot template"""
    template = models.HoneypotTemplate(
        name="SSH",
        type="ssh",
        default_config={"port": 22}
    )
    db.add(template)
    db.commit()
    db.refresh(template)
    return template


@pytest.fixture(scope="function")
def test_honeypot(db, test_node, test_template):
    """Create a test honeypot"""
    honeypot = models.Honeypot(
        node_id=test_node.id,
        template_id=test_template.id,
        name="Test Honeypot",
        listen_ip="0.0.0.0",
        listen_port=2222,
        status="stopped"
    )
    db.add(honeypot)
    db.commit()
    db.refresh(honeypot)
    return honeypot
