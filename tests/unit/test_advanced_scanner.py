"""
VulnScope - Advanced Scanner Unit Tests
Tests for RecursiveScanner, TimeoutHandler, AsyncScanOptimizer
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
from uuid import uuid4
from concurrent.futures import TimeoutError as FuturesTimeoutError

from src.scanner.advanced_scanner import (
    TimeoutHandler, EndpointTimeoutConfig,
    RecursiveScanner, RecursiveScanConfig,
    AsyncScanOptimizer, FuzzingWordlistManager
)
from src.core.models import (
    Endpoint, Finding, Scan, Target, Severity,
    VulnerabilityType, Status
)
from src.config.settings import ScannerConfig


class TestEndpointTimeoutConfig:
    """Test endpoint timeout configuration"""
    
    def test_default_values(self):
        """Test default config values"""
        config = EndpointTimeoutConfig()
        
        assert config.default_timeout == 30
        assert config.slow_endpoint_threshold == 10.0
        assert config.max_retries == 3
        assert config.retry_delay == 1.0
    
    def test_custom_values(self):
        """Test custom config values"""
        config = EndpointTimeoutConfig(
            default_timeout=60,
            slow_endpoint_threshold=20.0,
            max_retries=5,
            retry_delay=2.0
        )
        
        assert config.default_timeout == 60
        assert config.slow_endpoint_threshold == 20.0
        assert config.max_retries == 5
        assert config.retry_delay == 2.0


class TestTimeoutHandler:
    """Test timeout handling for endpoints"""
    
    def test_initialization(self):
        """Test handler initialization"""
        config = EndpointTimeoutConfig()
        handler = TimeoutHandler(config)
        
        assert len(handler.slow_endpoints) == 0
        assert len(handler.failed_endpoints) == 0
    
    def test_get_timeout_default(self):
        """Test getting default timeout"""
        handler = TimeoutHandler(EndpointTimeoutConfig())
        
        timeout = handler.get_timeout("http://example.com/api")
        
        assert timeout == 30
    
    def test_get_timeout_slow_endpoint(self):
        """Test timeout for known slow endpoint"""
        handler = TimeoutHandler(EndpointTimeoutConfig())
        handler.slow_endpoints["http://example.com/slow"] = 15.0
        
        timeout = handler.get_timeout("http://example.com/slow")
        
        # Should be 15.0 * 1.5 = 22.5, capped at 60
        assert timeout == 22.5
    
    def test_get_timeout_capped(self):
        """Test timeout is capped at 2x default"""
        handler = TimeoutHandler(EndpointTimeoutConfig())
        handler.slow_endpoints["http://example.com/very-slow"] = 100.0
        
        timeout = handler.get_timeout("http://example.com/very-slow")
        
        # Should be capped at 30 * 2 = 60
        assert timeout == 60
    
    def test_record_response_time(self):
        """Test recording response time"""
        handler = TimeoutHandler(EndpointTimeoutConfig())
        
        handler.record_response_time("http://example.com/api", 15.0)
        
        assert "http://example.com/api" in handler.slow_endpoints
        assert handler.slow_endpoints["http://example.com/api"] == 15.0
    
    def test_record_response_time_fast(self):
        """Test recording fast response"""
        handler = TimeoutHandler(EndpointTimeoutConfig())
        
        handler.record_response_time("http://example.com/fast", 2.0)
        
        # Fast responses should not be recorded as slow
        assert "http://example.com/fast" not in handler.slow_endpoints
    
    def test_record_failure(self):
        """Test recording endpoint failure"""
        handler = TimeoutHandler(EndpointTimeoutConfig())
        
        handler.record_failure("http://example.com/failing")
        handler.record_failure("http://example.com/failing")
        
        assert handler.failed_endpoints["http://example.com/failing"] == 2
    
    def test_should_skip(self):
        """Test skip decision"""
        handler = TimeoutHandler(EndpointTimeoutConfig(max_retries=3))
        
        # Under threshold
        handler.record_failure("http://example.com/ok")
        assert handler.should_skip("http://example.com/ok") is False
        
        # At threshold
        handler.record_failure("http://example.com/ok")
        handler.record_failure("http://example.com/ok")
        assert handler.should_skip("http://example.com/ok") is True
    
    def test_get_endpoint_stats(self):
        """Test getting endpoint statistics"""
        handler = TimeoutHandler(EndpointTimeoutConfig())
        handler.record_response_time("http://example.com/api", 15.0)
        handler.record_failure("http://example.com/api")
        
        stats = handler.get_endpoint_stats("http://example.com/api")
        
        assert stats["response_time"] == 15.0
        assert stats["failure_count"] == 1
        assert stats["should_skip"] is False


class TestRecursiveScanConfig:
    """Test recursive scan configuration"""
    
    def test_default_values(self):
        """Test default config values"""
        config = RecursiveScanConfig()
        
        assert config.max_depth == 3
        assert config.follow_links is True
        assert config.discover_params is True
        assert config.test_authenticated is True
    
    def test_custom_values(self):
        """Test custom config values"""
        config = RecursiveScanConfig(
            max_depth=5,
            follow_links=False,
            discover_params=False
        )
        
        assert config.max_depth == 5
        assert config.follow_links is False
        assert config.discover_params is False


class TestRecursiveScanner:
    """Test recursive scanner"""
    
    def test_initialization(self):
        """Test scanner initialization"""
        scanner = RecursiveScanner()
        
        assert scanner.recursive_config is not None
        assert scanner.timeout_handler is not None
        assert len(scanner.discovered_during_scan) == 0
    
    def test_initialization_with_config(self):
        """Test initialization with custom config"""
        scanner_config = ScannerConfig()
        recursive_config = RecursiveScanConfig(max_depth=5)
        
        scanner = RecursiveScanner(
            config=scanner_config,
            recursive_config=recursive_config
        )
        
        assert scanner.recursive_config.max_depth == 5
    
    def test_scanned_urls_tracking(self):
        """Test tracking of scanned URLs"""
        scanner = RecursiveScanner()
        
        scanner.scanned_urls.add("http://example.com/page1")
        scanner.scanned_urls.add("http://example.com/page2")
        
        assert len(scanner.scanned_urls) == 2
        assert "http://example.com/page1" in scanner.scanned_urls
    
    @pytest.mark.asyncio
    async def test_scan_recursive(self):
        """Test recursive scanning"""
        scanner = RecursiveScanner()
        
        target_id = uuid4()
        scan_id = uuid4()
        
        target = Target(
            id=target_id,
            name="Test",
            url="http://example.com"
        )
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test Scan"
        )
        
        endpoints = [
            Endpoint(
                target_id=target_id,
                url="http://example.com/api",
                method="GET",
                path="/api"
            )
        ]
        
        # Mock the parent class method
        with patch.object(scanner, 'scan_endpoints_async') as mock_scan:
            mock_scan.return_value = Mock(
                findings=[],
                progress=Mock(scanned_endpoints=1)
            )
            
            result = await scanner.scan_recursive(endpoints, target, scan, max_depth=1)
            
            assert result is not None
    
    def test_extract_new_endpoints_from_responses(self):
        """Test extracting new endpoints"""
        scanner = RecursiveScanner()
        
        new_endpoints = scanner._extract_new_endpoints_from_responses()
        
        assert isinstance(new_endpoints, list)


class TestAsyncScanOptimizer:
    """Test async scan optimizer"""
    
    def test_initialization(self):
        """Test optimizer initialization"""
        optimizer = AsyncScanOptimizer()
        
        assert optimizer.max_concurrent == 50
        assert optimizer.active_scans == 0
        assert optimizer.completed_scans == 0
        assert optimizer.failed_scans == 0
    
    def test_initialization_custom_concurrent(self):
        """Test initialization with custom concurrency"""
        optimizer = AsyncScanOptimizer(max_concurrent=100)
        
        assert optimizer.max_concurrent == 100
    
    def test_get_stats(self):
        """Test getting stats"""
        optimizer = AsyncScanOptimizer()
        optimizer.completed_scans = 10
        optimizer.failed_scans = 2
        
        stats = optimizer.get_stats()
        
        assert stats["completed_scans"] == 10
        assert stats["failed_scans"] == 2
        assert stats["success_rate"] == pytest.approx(83.33, rel=0.01)  # 10/12 * 100
    
    def test_get_stats_no_scans(self):
        """Test stats with no scans"""
        optimizer = AsyncScanOptimizer()
        
        stats = optimizer.get_stats()
        
        assert stats["success_rate"] == 0
    
    @pytest.mark.asyncio
    async def test_scan_with_backpressure(self):
        """Test scanning with backpressure"""
        optimizer = AsyncScanOptimizer(max_concurrent=5)
        
        scan_count = 0
        
        async def mock_scan(endpoint):
            nonlocal scan_count
            scan_count += 1
            await asyncio.sleep(0.01)
            return {"endpoint": endpoint}
        
        endpoints = [f"http://example.com/api/{i}" for i in range(10)]
        
        results = await optimizer.scan_with_backpressure(endpoints, mock_scan)
        
        assert scan_count == 10
        assert optimizer.completed_scans == 10
    
    @pytest.mark.asyncio
    async def test_scan_with_backpressure_error_handling(self):
        """Test error handling in backpressure scan"""
        optimizer = AsyncScanOptimizer(max_concurrent=5)
        
        async def failing_scan(endpoint):
            if "fail" in endpoint:
                raise Exception("Scan failed")
            return {"endpoint": endpoint}
        
        endpoints = [
            "http://example.com/ok1",
            "http://example.com/fail1",
            "http://example.com/ok2"
        ]
        
        results = await optimizer.scan_with_backpressure(endpoints, failing_scan)
        
        # Should complete even with errors
        assert optimizer.completed_scans > 0 or optimizer.failed_scans > 0


class TestFuzzingWordlistManager:
    """Test fuzzing wordlist manager"""
    
    def test_initialization(self):
        """Test manager initialization"""
        manager = FuzzingWordlistManager()
        
        assert "parameters" in manager.custom_wordlists
        assert "paths" in manager.custom_wordlists
        assert "values" in manager.custom_wordlists
    
    def test_default_wordlists_loaded(self):
        """Test default wordlists are loaded"""
        manager = FuzzingWordlistManager()
        
        params = manager.get_wordlist("parameters")
        assert "id" in params
        assert "user" in params
        
        paths = manager.get_wordlist("paths")
        assert "admin" in paths
        assert "api" in paths
    
    def test_get_wordlist_not_found(self):
        """Test getting non-existent wordlist"""
        manager = FuzzingWordlistManager()
        
        result = manager.get_wordlist("nonexistent")
        assert result == []
    
    def test_add_word(self):
        """Test adding word to wordlist"""
        manager = FuzzingWordlistManager()
        
        manager.add_word("parameters", "custom_param")
        
        params = manager.get_wordlist("parameters")
        assert "custom_param" in params
    
    def test_add_word_no_duplicate(self):
        """Test adding duplicate word"""
        manager = FuzzingWordlistManager()
        
        manager.add_word("parameters", "id")  # Already exists
        params = manager.get_wordlist("parameters")
        
        # Should not have duplicate
        count = params.count("id")
        assert count == 1
    
    def test_add_word_new_wordlist(self):
        """Test adding word to new wordlist"""
        manager = FuzzingWordlistManager()
        
        manager.add_word("custom_list", "word1")
        
        custom = manager.get_wordlist("custom_list")
        assert "word1" in custom
    
    def test_load_wordlist_file_not_found(self):
        """Test loading wordlist from non-existent file"""
        manager = FuzzingWordlistManager()
        
        result = manager.load_wordlist("test", "/nonexistent/file.txt")
        
        assert result is False
    
    def test_generate_fuzz_payloads(self):
        """Test generating fuzzing payloads"""
        manager = FuzzingWordlistManager()
        
        payloads = manager.generate_fuzz_payloads("test_", "values")
        
        assert len(payloads) > 0
        assert any("test_" in p for p in payloads)
    
    def test_get_all_wordlists(self):
        """Test getting all wordlists"""
        manager = FuzzingWordlistManager()
        
        all_lists = manager.get_all_wordlists()
        
        assert "parameters" in all_lists
        assert "paths" in all_lists
        assert "values" in all_lists


class TestIntegration:
    """Integration tests for advanced scanner components"""
    
    def test_timeout_handler_with_scanner(self):
        """Test timeout handler integration with scanner"""
        config = EndpointTimeoutConfig(default_timeout=60)
        handler = TimeoutHandler(config)
        
        scanner = RecursiveScanner()
        scanner.timeout_handler = handler
        
        # Simulate slow endpoint
        handler.record_response_time("http://slow.example.com", 45.0)
        
        timeout = scanner.timeout_handler.get_timeout("http://slow.example.com")
        
        assert timeout > 60  # Should be adjusted
    
    def test_wordlist_with_scanner(self):
        """Test wordlist manager integration"""
        manager = FuzzingWordlistManager()
        
        # Add custom parameters
        manager.add_word("api_params", "user_id")
        manager.add_word("api_params", "session_token")
        
        payloads = manager.generate_fuzz_payloads("fuzz_", "api_params")
        
        assert "fuzz_user_id" in payloads
        assert "fuzz_session_token" in payloads
    
    @pytest.mark.asyncio
    async def test_full_scan_workflow(self):
        """Test complete scan workflow with all components"""
        optimizer = AsyncScanOptimizer(max_concurrent=10)
        wordlist = FuzzingWordlistManager()
        
        # Generate test parameters
        params = wordlist.get_wordlist("parameters")[:5]
        
        scan_results = []
        
        async def test_endpoint(param):
            await asyncio.sleep(0.01)
            return {"param": param, "found": True}
        
        results = await optimizer.scan_with_backpressure(params, test_endpoint)
        
        stats = optimizer.get_stats()
        assert stats["completed_scans"] > 0


if __name__ == "__main__":
    pytest.main([__file__, "-v"])