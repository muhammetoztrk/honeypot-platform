# Test Suite Documentation

This directory contains comprehensive automated tests for the Honeypot Platform.

## Test Structure

- `conftest.py` - Test fixtures and configuration
- `test_auth.py` - Authentication tests
- `test_health.py` - Health check tests
- `test_setup.py` - Setup wizard tests
- `test_nodes.py` - Node management tests
- `test_honeypots.py` - Honeypot management tests
- `test_events.py` - Event management tests
- `test_iocs.py` - IOC management tests
- `test_alerts.py` - Alert system tests
- `test_security.py` - Security tests
- `test_api_comprehensive.py` - Comprehensive API tests
- `test_integration.py` - Integration tests

## Running Tests

### Run all tests
```bash
cd backend
pytest tests/ -v
```

### Run specific test file
```bash
pytest tests/test_auth.py -v
```

### Run specific test class
```bash
pytest tests/test_nodes.py::TestNodes -v
```

### Run specific test function
```bash
pytest tests/test_auth.py::test_login -v
```

### Run with coverage
```bash
pytest tests/ -v --cov=app --cov-report=html
```

### Run in parallel (if pytest-xdist is installed)
```bash
pytest tests/ -v -n auto
```

## Test Coverage

The test suite covers:
- ✅ Setup wizard functionality
- ✅ Authentication and authorization
- ✅ Node management (CRUD operations)
- ✅ Honeypot management (CRUD, start/stop)
- ✅ Event creation and listing
- ✅ IOC extraction and management
- ✅ Alert creation and management
- ✅ Security features (authentication, input validation)
- ✅ API endpoints
- ✅ Integration workflows

## Test Database

Tests use an in-memory SQLite database (`sqlite:///:memory:`) to ensure:
- Fast test execution
- Isolation between tests
- No side effects on development database

## Fixtures

Common fixtures available:
- `db` - Database session
- `client` - Test client
- `admin_user` - Admin user
- `auth_token` - Authentication token
- `authenticated_client` - Authenticated test client
- `test_node` - Test node
- `test_template` - Test honeypot template
- `test_honeypot` - Test honeypot

## Writing New Tests

1. Create test file: `test_feature.py`
2. Import necessary fixtures from `conftest.py`
3. Write test functions starting with `test_`
4. Use `authenticated_client` for protected endpoints
5. Use `db` fixture for database operations

Example:
```python
def test_my_feature(authenticated_client, db):
    """Test my feature"""
    response = authenticated_client.get("/api/v1/my-endpoint")
    assert response.status_code == 200
```

## Continuous Integration

Tests can be run in CI/CD pipelines:
```yaml
- name: Run tests
  run: |
    cd backend
    pytest tests/ -v
```

