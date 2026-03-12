"""
VulnScope - Passive Proxy Tests
Tests for passive scanning proxy functionality
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime

from src.discovery.passive_proxy import (
    PassiveProxy, ProxyConfig, InterceptedRequest,
    SecurityHeadersChecker, SensitiveDataDetector
)


class TestProxyConfig:
    """Test proxy configuration"""
    
    def test_default_config(self):
        config = ProxyConfig()
        
        assert config.listen_port == 8080
        assert config.upstream_proxy is None
        assert config.intercept_ssl is True
    
    def test_custom_config(self):
        config = ProxyConfig(
            listen_port=9090,
            upstream_proxy="http://upstream:8080",
            intercept_ssl=False
        )
        
        assert config.listen_port == 9090
        assert config.upstream_proxy == "http://upstream:8080"


class TestInterceptedRequest:
    """Test intercepted request model"""
    
    def test_create_request(self):
        request = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users",
            headers={"Authorization": "Bearer token"},
            body=None
        )
        
        assert request.method == "GET"
        assert request.url == "https://example.com/api/users"
        assert "Authorization" in request.headers
    
    def test_request_with_body(self):
        request = InterceptedRequest(
            method="POST",
            url="https://example.com/api/login",
            headers={"Content-Type": "application/json"},
            body='{"username": "test", "password": "secret"}'
        )
        
        assert request.method == "POST"
        assert request.body is not None


class TestSecurityHeadersChecker:
    """Test security headers checker"""
    
    def test_check_missing_headers(self):
        checker = SecurityHeadersChecker()
        headers = {
            "Content-Type": "text/html"
        }
        
        missing = checker.check(headers)
        
        assert "Strict-Transport-Security" in missing
        assert "Content-Security-Policy" in missing
        assert "X-Frame-Options" in missing
    
    def test_check_present_headers(self):
        checker = SecurityHeadersChecker()
        headers = {
            "Content-Type": "text/html",
            "Strict-Transport-Security": "max-age=31536000",
            "Content-Security-Policy": "default-src 'self'",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff"
        }
        
        missing = checker.check(headers)
        
        assert len(missing) == 0
    
    def test_check_partial_headers(self):
        checker = SecurityHeadersChecker()
        headers = {
            "Strict-Transport-Security": "max-age=31536000",
            "X-Frame-Options": "SAMEORIGIN"
        }
        
        missing = checker.check(headers)
        
        assert "Content-Security-Policy" in missing
        assert "X-Frame-Options" not in missing


class TestSensitiveDataDetector:
    """Test sensitive data detector"""
    
    def test_detect_email(self):
        detector = SensitiveDataDetector()
        content = "Contact us at admin@example.com for support"
        
        findings = detector.detect(content)
        
        assert "email" in findings
    
    def test_detect_ssn(self):
        detector = SensitiveDataDetector()
        content = "SSN: 123-45-6789"
        
        findings = detector.detect(content)
        
        assert "ssn" in findings
    
    def test_detect_credit_card(self):
        detector = SensitiveDataDetector()
        content = "Card: 4111-1111-1111-1111"
        
        findings = detector.detect(content)
        
        assert "credit_card" in findings
    
    def test_detect_api_key(self):
        detector = SensitiveDataDetector()
        content = "api_key=sk-1234567890abcdef"
        
        findings = detector.detect(content)
        
        assert "api_key" in findings
    
    def test_detect_multiple_types(self):
        detector = SensitiveDataDetector()
        content = "Email: test@example.com, SSN: 123-45-6789"
        
        findings = detector.detect(content)
        
        assert "email" in findings
        assert "ssn" in findings
    
    def test_no_sensitive_data(self):
        detector = SensitiveDataDetector()
        content = "This is a normal text without sensitive data"
        
        findings = detector.detect(content)
        
        assert len(findings) == 0


class TestPassiveProxy:
    """Test passive proxy"""
    
    @pytest.fixture
    def proxy(self):
        config = ProxyConfig(listen_port=8080)
        return PassiveProxy(config)
    
    def test_init(self, proxy):
        assert proxy.config.listen_port == 8080
        assert proxy.intercepted_requests == []
    
    def test_intercept_request(self, proxy):
        request = InterceptedRequest(
            method="GET",
            url="https://example.com/api/data",
            headers={}
        )
        
        proxy.intercept(request)
        
        assert len(proxy.intercepted_requests) == 1
    
    def test_get_intercepted_requests(self, proxy):
        request1 = InterceptedRequest(method="GET", url="https://example.com/1", headers={})
        request2 = InterceptedRequest(method="POST", url="https://example.com/2", headers={})
        
        proxy.intercept(request1)
        proxy.intercept(request2)
        
        requests = proxy.get_intercepted_requests()
        
        assert len(requests) == 2
    
    def test_clear_intercepted_requests(self, proxy):
        request = InterceptedRequest(method="GET", url="https://example.com", headers={})
        proxy.intercept(request)
        
        proxy.clear()
        
        assert len(proxy.intercepted_requests) == 0
    
    def test_analyze_request(self, proxy):
        request = InterceptedRequest(
            method="GET",
            url="https://example.com/api/users",
            headers={
                "Authorization": "Bearer secret-token",
                "Content-Type": "application/json"
            }
        )
        
        analysis = proxy.analyze(request)
        
        assert analysis["has_auth"] is True
        assert analysis["auth_type"] == "Bearer"
    
    def test_analyze_response_headers(self, proxy):
        response_headers = {
            "Content-Type": "text/html",
            "Server": "Apache/2.4.41"
        }
        
        analysis = proxy.analyze_response_headers(response_headers)
        
        assert "missing_security_headers" in analysis
        assert "Server" in analysis["exposed_headers"]


if __name__ == "__main__":
    pytest.main([__file__, "-v"])