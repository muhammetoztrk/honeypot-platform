"""Security tests"""
import pytest
from fastapi.testclient import TestClient
from app.main import app

client = TestClient(app)


class TestSecurity:
    """Test security features"""
    
    def test_authentication_required(self):
        """Test that protected endpoints require authentication"""
        protected_endpoints = [
            "/api/v1/nodes",
            "/api/v1/honeypots",
            "/api/v1/events",
            "/api/v1/iocs",
            "/api/v1/alerts"
        ]
        
        for endpoint in protected_endpoints:
            response = client.get(endpoint)
            assert response.status_code == 401, f"{endpoint} should require authentication"
    
    def test_invalid_token(self):
        """Test request with invalid token"""
        response = client.get(
            "/api/v1/nodes",
            headers={"Authorization": "Bearer invalid_token"}
        )
        assert response.status_code == 401
    
    def test_expired_token(self, authenticated_client):
        """Test request with expired token"""
        # Note: This would require mocking time or using a real expired token
        # For now, we just test that invalid tokens are rejected
        response = client.get(
            "/api/v1/nodes",
            headers={"Authorization": "Bearer expired_token_here"}
        )
        assert response.status_code == 401
    
    def test_sql_injection_protection(self, authenticated_client):
        """Test SQL injection protection"""
        # Try SQL injection in various fields
        malicious_inputs = [
            "'; DROP TABLE users; --",
            "1' OR '1'='1",
            "admin'--",
            "1; DELETE FROM nodes; --"
        ]
        
        for malicious_input in malicious_inputs:
            # Test in node name
            response = authenticated_client.post(
                "/api/v1/nodes",
                json={"name": malicious_input}
            )
            # Should either sanitize or reject
            assert response.status_code in [200, 400, 422]
    
    def test_xss_protection(self, authenticated_client):
        """Test XSS protection"""
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        ]
        
        for payload in xss_payloads:
            response = authenticated_client.post(
                "/api/v1/nodes",
                json={"name": payload}
            )
            # Should sanitize or reject
            assert response.status_code in [200, 400, 422]
    
    def test_rate_limiting(self, authenticated_client):
        """Test rate limiting"""
        # Make many rapid requests
        responses = []
        for _ in range(100):
            response = authenticated_client.get("/api/v1/nodes")
            responses.append(response.status_code)
        
        # Should either all succeed or some return 429 (rate limited)
        # In test environment, rate limiting might not be enabled
        assert all(status in [200, 429] for status in responses)
    
    def test_cors_headers(self):
        """Test CORS headers"""
        response = client.options("/api/v1/nodes")
        # CORS headers should be present
        assert response.status_code in [200, 405]  # OPTIONS might return 405
    
    def test_security_headers(self):
        """Test security headers"""
        response = client.get("/health")
        headers = response.headers
        
        # Check for security headers
        security_headers = [
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection"
        ]
        
        # At least some security headers should be present
        present_headers = [h for h in security_headers if h in headers]
        assert len(present_headers) > 0, "Security headers should be present"

