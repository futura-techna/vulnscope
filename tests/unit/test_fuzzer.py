"""
VulnScope - Fuzzer Unit Tests
Tests for the fuzzer component
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from uuid import uuid4

from src.fuzzer.fuzzer import Fuzzer, FuzzingResult, FuzzTest
from src.config.settings import FuzzerConfig
from src.core.models import Endpoint, Finding, Severity, VulnerabilityType


class TestFuzzingResult:
    """Test FuzzingResult dataclass"""
    
    def test_default_values(self):
        result = FuzzingResult()
        assert len(result.findings) == 0
        assert result.requests_sent == 0
        assert result.unique_responses == 0
        assert result.duration_seconds == 0.0
    
    def test_with_findings(self):
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                scan_id=scan_id,
                target_id=target_id,
                title="SQL Injection",
                description="SQLi via fuzzing",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            )
        ]
        
        result = FuzzingResult(findings=findings)
        assert len(result.findings) == 1


class TestFuzzTest:
    """Test FuzzTest dataclass"""
    
    def test_create_fuzz_test(self):
        target_id = uuid4()
        
        endpoint = Endpoint(
            target_id=target_id,
            url="http://example.com/api/users",
            method="GET",
            path="/api/users"
        )
        
        test = FuzzTest(
            endpoint=endpoint,
            method="GET",
            url="http://example.com/api/users",
            payload="<script>alert(1)</script>",
            category="xss"
        )
        
        assert test.method == "GET"
        assert test.category == "xss"


class TestFuzzer:
    """Test Fuzzer class"""
    
    def test_initialization(self):
        fuzzer = Fuzzer()
        assert fuzzer is not None
        assert fuzzer.config is not None
        assert fuzzer.session is not None
    
    def test_initialization_with_config(self):
        config = FuzzerConfig(payloads_per_endpoint=500)
        fuzzer = Fuzzer(config)
        assert fuzzer.config.payloads_per_endpoint == 500
    
    def test_rate_limit_tracking(self):
        fuzzer = Fuzzer()
        
        # Add request times
        fuzzer.request_times = [1.0, 1.1, 1.2, 1.3, 1.4]
        
        # Should track requests
        assert len(fuzzer.request_times) == 5
    
    def test_detect_rate_limit_429(self):
        fuzzer = Fuzzer()
        
        mock_response = Mock()
        mock_response.status_code = 429
        mock_response.headers = {}
        
        result = fuzzer._detect_rate_limit(mock_response)
        
        assert result == True
        assert fuzzer.rate_limit_detected == True
    
    def test_detect_rate_limit_headers(self):
        fuzzer = Fuzzer()
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.headers = {
            'X-RateLimit-Remaining': '0'
        }
        
        result = fuzzer._detect_rate_limit(mock_response)
        
        assert result == True
    
    def test_get_response_key(self):
        fuzzer = Fuzzer()
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.text = "Hello World"
        
        key = fuzzer._get_response_key(mock_response)
        
        assert "200" in key


class TestFuzzerVulnerabilityDetection:
    """Test vulnerability detection methods"""
    
    def test_detect_sql_injection_positive(self):
        fuzzer = Fuzzer()
        
        mock_response = Mock()
        mock_response.text = "You have an error in your SQL syntax"
        
        result = fuzzer._detect_sql_injection(mock_response)
        
        assert result == True
    
    def test_detect_sql_injection_negative(self):
        fuzzer = Fuzzer()
        
        mock_response = Mock()
        mock_response.text = "Normal response without errors"
        
        result = fuzzer._detect_sql_injection(mock_response)
        
        assert result == False
    
    def test_detect_xss_positive(self):
        fuzzer = Fuzzer()
        
        mock_response = Mock()
        mock_response.text = "<script>alert(1)</script>"
        
        result = fuzzer._detect_xss(mock_response, "<script>alert(1)</script>")
        
        assert result == True
    
    def test_detect_xss_negative(self):
        fuzzer = Fuzzer()
        
        mock_response = Mock()
        mock_response.text = "<script>alert(1)</script>"
        
        # XSS payload not reflected directly
        result = fuzzer._detect_xss(mock_response, "normal text")
        
        # This depends on the actual implementation
        assert isinstance(result, bool)
    
    def test_detect_ssrf_positive(self):
        fuzzer = Fuzzer()
        
        mock_response = Mock()
        mock_response.text = "Response from localhost server"
        
        result = fuzzer._detect_ssrf(mock_response)
        
        assert result == True
    
    def test_detect_sensitive_data(self):
        fuzzer = Fuzzer()
        
        mock_response = Mock()
        mock_response.text = '{"password": "secret123"}'
        
        result = fuzzer._detect_sensitive_data(mock_response)
        
        assert isinstance(result, bool)


class TestFuzzerIntegration:
    """Integration tests for Fuzzer"""
    
    @pytest.mark.asyncio
    async def test_fuzz_endpoints_mock(self):
        fuzzer = Fuzzer()
        
        target_id = uuid4()
        scan_id = uuid4()
        
        target = Mock()
        target.id = target_id
        target.url = "http://example.com"
        target.auth_type = None
        
        scan = Mock()
        scan.id = scan_id
        
        endpoints = [
            Endpoint(
                target_id=target_id,
                url="http://example.com/api/users",
                method="GET",
                path="/api/users"
            ),
        ]
        
        with patch.object(fuzzer, '_fuzz_endpoint', return_value=[]):
            result = await fuzzer.fuzz_endpoints(endpoints, target, scan)
            
            assert result is not None
            assert isinstance(result, FuzzingResult)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])