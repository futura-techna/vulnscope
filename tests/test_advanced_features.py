"""
VulnScope - Integration Tests
Tests for integrated components and workflows
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
from uuid import uuid4

from src.scanner.advanced_scanner import (
    TimeoutHandler, EndpointTimeoutConfig,
    RecursiveScanner, RecursiveScanConfig,
    AsyncScanOptimizer, FuzzingWordlistManager
)

from src.discovery.advanced_discovery import (
    WebSocketDiscovery, WebSocketDiscoveryConfig,
    PassiveScanner, JavaScriptParser,
    APIVersionDetector, APIVersionConfig
)

from src.evidence.advanced_reporting import (
    TrendAnalyzer, VulnerabilityCorrelator,
    ExecutiveReportGenerator
)

from src.api.security import (
    JWTHandler, RateLimiter, InputValidator,
    AuthorizationHandler
)

from src.utils.infrastructure import (
    CacheManager, MessageQueue, BackupManager,
    TaskScheduler
)


# ============================================
# SCANNER TESTS
# ============================================
class TestTimeoutHandler:
    """Test timeout handling"""
    
    def test_default_timeout(self):
        config = EndpointTimeoutConfig(default_timeout=30)
        handler = TimeoutHandler(config)
        
        assert handler.get_timeout("http://example.com") == 30
    
    def test_slow_endpoint_adaptation(self):
        config = EndpointTimeoutConfig(
            default_timeout=30,
            slow_endpoint_threshold=5.0
        )
        handler = TimeoutHandler(config)
        
        # Record slow response
        handler.record_response_time("http://example.com", 10.0)
        
        # Should get increased timeout (10.0 * 1.5 = 15.0)
        timeout = handler.get_timeout("http://example.com")
        assert timeout == 15.0
    
    def test_failure_tracking(self):
        config = EndpointTimeoutConfig(max_retries=3)
        handler = TimeoutHandler(config)
        
        # Record failures
        handler.record_failure("http://example.com")
        handler.record_failure("http://example.com")
        
        assert not handler.should_skip("http://example.com")
        
        # Record one more
        handler.record_failure("http://example.com")
        
        # Should skip now
        assert handler.should_skip("http://example.com")


class TestFuzzingWordlistManager:
    """Test wordlist management"""
    
    def test_default_wordlists(self):
        manager = FuzzingWordlistManager()
        
        assert "parameters" in manager.get_all_wordlists()
        assert "paths" in manager.get_all_wordlists()
        assert "values" in manager.get_all_wordlists()
    
    def test_add_word(self):
        manager = FuzzingWordlistManager()
        
        manager.add_word("custom", "test_word")
        
        assert "test_word" in manager.get_wordlist("custom")
    
    def test_generate_fuzz_payloads(self):
        manager = FuzzingWordlistManager()
        
        payloads = manager.generate_fuzz_payloads("test", "values")
        
        assert len(payloads) > 0
        assert all("test" in p for p in payloads)


class TestAsyncScanOptimizer:
    """Test async scan optimization"""
    
    @pytest.mark.asyncio
    async def test_scan_with_backpressure(self):
        optimizer = AsyncScanOptimizer(max_concurrent=2)
        
        async def mock_scan(endpoint):
            await asyncio.sleep(0.01)
            return {"endpoint": endpoint}
        
        endpoints = ["ep1", "ep2", "ep3", "ep4"]
        
        results = await optimizer.scan_with_backpressure(endpoints, mock_scan)
        
        stats = optimizer.get_stats()
        
        assert stats["completed_scans"] == 4


# ============================================
# DISCOVERY TESTS
# ============================================
class TestWebSocketDiscovery:
    """Test WebSocket discovery"""
    
    def test_discover_from_html(self):
        config = WebSocketDiscoveryConfig()
        discovery = WebSocketDiscovery(config)
        
        html = '''
        <html>
        <script>
        var ws = new WebSocket("ws://example.com/socket");
        </script>
        </html>
        '''
        
        endpoints = discovery.discover_from_html(html, "http://example.com")
        
        assert "ws://example.com/socket" in endpoints
    
    def test_discover_from_js(self):
        config = WebSocketDiscoveryConfig()
        discovery = WebSocketDiscovery(config)
        
        js = 'new WebSocket("wss://api.example.com/ws")'
        
        endpoints = discovery.discover_from_js(js, "http://example.com")
        
        assert len(endpoints) > 0


class TestPassiveScanner:
    """Test passive scanning"""
    
    def test_security_headers_check(self):
        scanner = PassiveScanner()
        
        headers = {
            "content-type": "text/html",
            # Missing security headers
        }
        
        missing = scanner._check_security_headers(headers)
        
        assert "Strict-Transport-Security" in missing
        assert "Content-Security-Policy" in missing
    
    def test_sensitive_data_detection(self):
        scanner = PassiveScanner()
        
        body = "Contact: admin@example.com, SSN: 123-45-6789"
        
        found = scanner._check_sensitive_data(body)
        
        assert "email" in found
        assert "ssn" in found


class TestJavaScriptParser:
    """Test JavaScript parsing"""
    
    def test_extract_api_endpoints(self):
        parser = JavaScriptParser()
        
        js = '''
        axios.get("/api/v1/users");
        fetch("/api/v2/products");
        baseURL = "https://api.example.com";
        '''
        
        endpoints = parser._extract_api_endpoints(js, "http://example.com")
        
        assert len(endpoints) > 0
    
    def test_extract_spa_routes(self):
        parser = JavaScriptParser()
        
        js = '''
        router.push("/dashboard");
        router.add("/settings");
        '''
        
        routes = parser._extract_spa_routes(js)
        
        assert len(routes) > 0


class TestAPIVersionDetector:
    """Test API versioning"""
    
    def test_detect_versions(self):
        config = APIVersionConfig()
        detector = APIVersionDetector(config)
        
        # Mock endpoints - need target_id
        from src.core.models import Endpoint
        
        target_id = uuid4()
        endpoints = [
            Endpoint(target_id=target_id, url="http://api.example.com/v1/users", method="GET", path="/v1/users"),
            Endpoint(target_id=target_id, url="http://api.example.com/v2/users", method="GET", path="/v2/users"),
            Endpoint(target_id=target_id, url="http://api.example.com/v1/products", method="GET", path="/v1/products"),
        ]
        
        result = detector.detect_versions(endpoints)
        
        assert result["version_count"] == 2
        assert "v1" in result["versions"]
        assert "v2" in result["versions"]


# ============================================
# REPORTING TESTS
# ============================================
class TestTrendAnalyzer:
    """Test trend analysis"""
    
    def test_add_scan_results(self):
        analyzer = TrendAnalyzer()
        
        # Mock findings - need scan_id, target_id, description
        from src.core.models import Finding, Severity, VulnerabilityType
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(), scan_id=scan_id, target_id=target_id,
                title="Test 1", description="Test 1 desc",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.XSS
            ),
            Finding(
                id=uuid4(), scan_id=scan_id, target_id=target_id,
                title="Test 2", description="Test 2 desc",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
        ]
        
        analyzer.add_scan_results(findings, datetime.utcnow())
        
        assert len(analyzer.historical_data) == 2
    
    def test_get_trend(self):
        analyzer = TrendAnalyzer()
        
        # Add data from different dates
        from datetime import timedelta
        
        now = datetime.utcnow()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        for i in range(5):
            from src.core.models import Finding, Severity, VulnerabilityType
            
            findings = [
                Finding(
                    id=uuid4(), scan_id=scan_id, target_id=target_id,
                    title=f"Test {i}", description="Test desc",
                    severity=Severity.MEDIUM,
                    vulnerability_type=VulnerabilityType.XSS
                ),
            ]
            analyzer.add_scan_results(findings, now - timedelta(days=i))
        
        trend = analyzer.get_trend(days=30)
        
        assert "total_findings" in trend


class TestVulnerabilityCorrelator:
    """Test vulnerability correlation"""
    
    def test_correlate_findings(self):
        from src.core.models import Finding, Severity, VulnerabilityType
        
        correlator = VulnerabilityCorrelator()
        
        scan_id = uuid4()
        target_id = uuid4()
        endpoint_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(), scan_id=scan_id, target_id=target_id,
                title="XSS in search", description="XSS",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS,
                endpoint_id=endpoint_id
            ),
            Finding(
                id=uuid4(), scan_id=scan_id, target_id=target_id,
                title="XSS in search 2", description="XSS",
                severity=Severity.MEDIUM,
                vulnerability_type=VulnerabilityType.XSS,
                endpoint_id=endpoint_id
            ),
            Finding(
                id=uuid4(), scan_id=scan_id, target_id=target_id,
                title="SQL Injection", description="SQLi",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                endpoint_id=uuid4()
            ),
        ]
        
        result = correlator.correlate(findings)
        
        assert "similar" in result
        assert "chained" in result
        assert "by_component" in result


class TestExecutiveReportGenerator:
    """Test executive report generation"""
    
    def test_risk_score_calculation(self):
        from src.core.models import Finding, Severity, VulnerabilityType, Scan, Target, Status
        
        generator = ExecutiveReportGenerator()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(), scan_id=scan_id, target_id=target_id,
                title="Test 1", description="Test 1 desc",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.XSS
            ),
            Finding(
                id=uuid4(), scan_id=scan_id, target_id=target_id,
                title="Test 2", description="Test 2 desc",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
            Finding(
                id=uuid4(), scan_id=scan_id, target_id=target_id,
                title="Test 3", description="Test 3 desc",
                severity=Severity.MEDIUM,
                vulnerability_type=VulnerabilityType.IDOR
            ),
        ]
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test Scan",
            scan_type="full",
            status=Status.COMPLETED,
            started_at=datetime.utcnow()
        )
        
        target = Target(
            id=target_id,
            name="Test Target",
            url="http://example.com"
        )
        
        report = generator.generate(findings, scan, target)
        
        assert report["executive_summary"]["risk_score"] > 0
        assert report["executive_summary"]["critical_issues"] == 1
        assert report["executive_summary"]["high_issues"] == 1


# ============================================
# SECURITY TESTS
# ============================================
class TestJWTHandler:
    """Test JWT handling"""
    
    def test_create_access_token(self):
        handler = JWTHandler(secret_key="test-secret")
        
        token = handler.create_access_token({"sub": "testuser"})
        
        assert token is not None
        assert isinstance(token, str)
    
    def test_verify_token(self):
        handler = JWTHandler(secret_key="test-secret")
        
        token = handler.create_access_token({"sub": "testuser", "user_id": "1"})
        
        payload = handler.verify_token(token)
        
        assert payload["sub"] == "testuser"
        assert payload["user_id"] == "1"


class TestInputValidator:
    """Test input validation"""
    
    def test_validate_url(self):
        assert InputValidator.validate_url("http://example.com")
        assert InputValidator.validate_url("https://api.example.com/path")
        assert not InputValidator.validate_url("not-a-url")
    
    def test_validate_email(self):
        assert InputValidator.validate_email("user@example.com")
        assert InputValidator.validate_email("admin@test.org")
        assert not InputValidator.validate_email("invalid-email")
    
    def test_validate_target_url(self):
        is_valid, error = InputValidator.validate_target_url("http://example.com")
        assert is_valid
        
        is_valid, error = InputValidator.validate_target_url("ftp://example.com")
        assert not is_valid
        assert "HTTP" in error
    
    def test_sanitize_input(self):
        sanitized = InputValidator.sanitize_input("  test input  ")
        assert sanitized == "test input"
        
        # Test truncation
        long_input = "a" * 2000
        sanitized = InputValidator.sanitize_input(long_input)
        assert len(sanitized) == 1000


class TestAuthorizationHandler:
    """Test authorization"""
    
    def test_check_permission(self):
        assert AuthorizationHandler.check_permission(["admin"], "scan:create")
        assert AuthorizationHandler.check_permission(["developer"], "scan:read")
        assert not AuthorizationHandler.check_permission(["viewer"], "scan:create")
    
    def test_admin_has_all_permissions(self):
        permissions = [
            "scan:create", "scan:read", "scan:delete",
            "target:create", "target:delete",
            "report:export"
        ]
        
        for perm in permissions:
            assert AuthorizationHandler.check_permission(["admin"], perm)


# ============================================
# INFRASTRUCTURE TESTS
# ============================================
class TestCacheManager:
    """Test caching"""
    
    @patch('src.utils.infrastructure.redis.Redis')
    def test_cache_operations(self, mock_redis):
        mock_client = Mock()
        mock_redis.return_value = mock_client
        
        manager = CacheManager(mock_client)
        
        # Test set and get
        mock_client.get.return_value = None
        manager.set("test_key", {"data": "value"})
        
        mock_client.setex.assert_called_once()


class TestMessageQueue:
    """Test message queue"""
    
    @patch('src.utils.infrastructure.redis.Redis')
    def test_enqueue_dequeue(self, mock_redis):
        mock_client = Mock()
        mock_redis.return_value = mock_client
        
        queue = MessageQueue(mock_client)
        
        task_id = queue.enqueue("test_task", {"data": "value"})
        
        assert task_id is not None
        mock_client.zadd.assert_called_once()


class TestTaskScheduler:
    """Test task scheduler"""
    
    def test_schedule_interval(self):
        scheduler = TaskScheduler()
        
        call_count = 0
        
        def test_task():
            nonlocal call_count
            call_count += 1
        
        scheduler.schedule_interval("test_task", test_task, 1)
        
        # Run pending tasks
        scheduler.run_pending()
        
        assert call_count == 1


# Run tests
if __name__ == "__main__":
    pytest.main([__file__, "-v"])
