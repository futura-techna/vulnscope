"""
VulnScope - Utils Security Unit Tests
Tests for Kill Switch, IP Blacklist, Sandbox, and Scan Monitor
"""

import pytest
import time
from unittest.mock import Mock, patch, MagicMock
from threading import Thread

from src.utils.security import (
    KillSwitch, IPBlacklist, RateLimitByIP,
    SandboxEnvironment, ScanMonitor, ScanLimits,
    GlobalKillSwitch
)


class TestKillSwitch:
    """Test Kill Switch functionality"""
    
    def test_initialization(self):
        """Test kill switch initialization"""
        ks = KillSwitch()
        assert ks.is_active is True
        assert ks._shutdown_requested is False
    
    def test_stop(self):
        """Test stopping kill switch"""
        ks = KillSwitch()
        ks.stop()
        
        assert ks.is_active is False
        assert ks._shutdown_requested is True
    
    def test_resume(self):
        """Test resuming kill switch"""
        ks = KillSwitch()
        ks.stop()
        assert ks.is_active is False
        
        ks.resume()
        assert ks.is_active is True
    
    def test_request_shutdown(self):
        """Test requesting shutdown"""
        ks = KillSwitch()
        ks.request_shutdown()
        
        assert ks._shutdown_requested is True
        assert ks.is_active is False
    
    def test_check(self):
        """Test check method"""
        ks = KillSwitch()
        assert ks.check() is True
        
        ks.stop()
        assert ks.check() is False
    
    def test_thread_safety(self):
        """Test thread safety of kill switch"""
        ks = KillSwitch()
        results = []
        
        def toggle_switch():
            for _ in range(100):
                ks.stop()
                results.append(ks.is_active)
                ks.resume()
                results.append(ks.is_active)
        
        threads = [Thread(target=toggle_switch) for _ in range(5)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        
        # Should complete without deadlock
        assert len(results) == 1000


class TestIPBlacklist:
    """Test IP Blacklist functionality"""
    
    def test_initialization_empty(self):
        """Test initialization with no lists"""
        blacklist = IPBlacklist()
        assert len(blacklist.allowed_networks) == 0
        assert len(blacklist.blocked_networks) == 0
    
    def test_initialization_with_blocked(self):
        """Test initialization with blocked IPs"""
        blacklist = IPBlacklist(blocked_ips=["192.168.1.1", "10.0.0.0/8"])
        
        assert len(blacklist.blocked_networks) == 2
    
    def test_initialization_with_allowed(self):
        """Test initialization with allowed IPs"""
        blacklist = IPBlacklist(allowed_ips=["192.168.1.0/24"])
        
        assert len(blacklist.allowed_networks) == 1
    
    def test_is_allowed_no_lists(self):
        """Test allow all when no lists configured"""
        blacklist = IPBlacklist()
        
        assert blacklist.is_allowed("192.168.1.1")
        assert blacklist.is_allowed("10.0.0.1")
        assert blacklist.is_allowed("8.8.8.8")
    
    def test_is_allowed_blocked_single_ip(self):
        """Test blocking single IP"""
        blacklist = IPBlacklist(blocked_ips=["192.168.1.100"])
        
        assert blacklist.is_allowed("192.168.1.100") is False
        assert blacklist.is_allowed("192.168.1.101")
    
    def test_is_allowed_blocked_cidr(self):
        """Test blocking CIDR range"""
        blacklist = IPBlacklist(blocked_ips=["10.0.0.0/8"])
        
        assert blacklist.is_allowed("10.0.0.1") is False
        assert blacklist.is_allowed("10.255.255.255") is False
        assert blacklist.is_allowed("192.168.1.1")
    
    def test_is_allowed_whitelist(self):
        """Test whitelist mode"""
        blacklist = IPBlacklist(allowed_ips=["192.168.1.0/24"])
        
        assert blacklist.is_allowed("192.168.1.100")
        assert blacklist.is_allowed("192.168.1.200")
        assert blacklist.is_allowed("10.0.0.1") is False
    
    def test_is_allowed_whitelist_and_blacklist(self):
        """Test combined whitelist and blacklist"""
        blacklist = IPBlacklist(
            allowed_ips=["192.168.1.0/24"],
            blocked_ips=["192.168.1.100"]
        )
        
        # Blocked IP should be blocked even in whitelist
        assert blacklist.is_allowed("192.168.1.100") is False
        # Other IPs in whitelist should be allowed
        assert blacklist.is_allowed("192.168.1.101")
    
    def test_is_allowed_invalid_ip(self):
        """Test invalid IP handling"""
        blacklist = IPBlacklist()
        
        assert blacklist.is_allowed("not-an-ip") is False
        assert blacklist.is_allowed("") is False
        assert blacklist.is_allowed("256.256.256.256") is False
    
    def test_invalid_cidr_handling(self):
        """Test invalid CIDR handling"""
        # Should not crash on invalid CIDR
        blacklist = IPBlacklist(blocked_ips=["invalid-cidr", "also-invalid"])
        
        assert len(blacklist.blocked_networks) == 0


class TestRateLimitByIP:
    """Test per-IP rate limiting"""
    
    def test_initialization(self):
        """Test rate limiter initialization"""
        limiter = RateLimitByIP(requests_per_minute=60)
        
        assert limiter.requests_per_minute == 60
        assert len(limiter.ip_requests) == 0
    
    def test_check_first_request(self):
        """Test first request from IP"""
        limiter = RateLimitByIP(requests_per_minute=60)
        
        assert limiter.check("192.168.1.1") is True
    
    def test_check_multiple_requests(self):
        """Test multiple requests from same IP"""
        limiter = RateLimitByIP(requests_per_minute=5)
        
        for i in range(5):
            assert limiter.check("192.168.1.1") is True
        
        # 6th request should be blocked
        assert limiter.check("192.168.1.1") is False
    
    def test_check_different_ips(self):
        """Test requests from different IPs"""
        limiter = RateLimitByIP(requests_per_minute=5)
        
        # Use up limit for IP1
        for _ in range(5):
            limiter.check("192.168.1.1")
        
        # IP2 should still be allowed
        assert limiter.check("192.168.1.2") is True
    
    def test_get_remaining(self):
        """Test getting remaining requests"""
        limiter = RateLimitByIP(requests_per_minute=60)
        
        assert limiter.get_remaining("192.168.1.1") == 60
        
        limiter.check("192.168.1.1")
        assert limiter.get_remaining("192.168.1.1") == 59
        
        limiter.check("192.168.1.1")
        assert limiter.get_remaining("192.168.1.1") == 58
    
    def test_get_remaining_new_ip(self):
        """Test remaining requests for new IP"""
        limiter = RateLimitByIP(requests_per_minute=30)
        
        assert limiter.get_remaining("new.ip.address") == 30
    
    def test_sliding_window(self):
        """Test sliding window cleanup"""
        limiter = RateLimitByIP(requests_per_minute=3)
        
        # Make 3 requests
        for _ in range(3):
            limiter.check("192.168.1.1")
        
        # Should be blocked
        assert limiter.check("192.168.1.1") is False
        
        # Simulate time passing by cleaning old entries
        # (In real usage, time.time() would advance)
        limiter.ip_requests["192.168.1.1"] = [time.time() - 120]  # 2 minutes ago
        
        # Should be allowed now (old requests expired)
        assert limiter.check("192.168.1.1") is True


class TestSandboxEnvironment:
    """Test sandbox environment"""
    
    def test_initialization(self):
        """Test sandbox initialization"""
        sandbox = SandboxEnvironment()
        
        assert sandbox.timeout_seconds == 30
        assert sandbox.max_memory_mb == 512
    
    def test_initialization_custom(self):
        """Test sandbox with custom settings"""
        sandbox = SandboxEnvironment(timeout_seconds=60, max_memory_mb=1024)
        
        assert sandbox.timeout_seconds == 60
        assert sandbox.max_memory_mb == 1024
    
    def test_execute_safe_success(self):
        """Test successful execution in sandbox"""
        sandbox = SandboxEnvironment(timeout_seconds=5)
        
        def simple_func():
            return "success"
        
        result = sandbox.execute_safe(simple_func)
        assert result == "success"
    
    def test_execute_safe_with_args(self):
        """Test execution with arguments"""
        sandbox = SandboxEnvironment(timeout_seconds=5)
        
        def add_func(a, b):
            return a + b
        
        result = sandbox.execute_safe(add_func, 2, 3)
        assert result == 5
    
    def test_execute_safe_with_kwargs(self):
        """Test execution with keyword arguments"""
        sandbox = SandboxEnvironment(timeout_seconds=5)
        
        def greet_func(name, greeting="Hello"):
            return f"{greeting}, {name}!"
        
        result = sandbox.execute_safe(greet_func, "World", greeting="Hi")
        assert result == "Hi, World!"
    
    @patch('src.utils.security.PSUTIL_AVAILABLE', True)
    @patch('src.utils.security.psutil')
    def test_check_resources(self, mock_psutil):
        """Test resource checking"""
        mock_process = Mock()
        mock_process.memory_info.return_value = Mock(rss=256 * 1024 * 1024)  # 256 MB
        mock_psutil.Process.return_value = mock_process
        
        sandbox = SandboxEnvironment(max_memory_mb=512)
        resources = sandbox.check_resources()
        
        assert resources['memory_limit_mb'] == 512
        assert resources['within_limits'] is True
    
    @patch('src.utils.security.PSUTIL_AVAILABLE', True)
    @patch('src.utils.security.psutil')
    def test_check_resources_exceeded(self, mock_psutil):
        """Test resource limit exceeded"""
        mock_process = Mock()
        mock_process.memory_info.return_value = Mock(rss=1024 * 1024 * 1024)  # 1 GB
        mock_psutil.Process.return_value = mock_process
        
        sandbox = SandboxEnvironment(max_memory_mb=512)
        resources = sandbox.check_resources()
        
        assert resources['within_limits'] is False


class TestScanMonitor:
    """Test scan monitoring"""
    
    def test_initialization(self):
        """Test monitor initialization"""
        limits = ScanLimits()
        monitor = ScanMonitor(limits)
        
        assert monitor.request_count == 0
        assert monitor.start_time == 0.0
    
    def test_start(self):
        """Test starting monitor"""
        limits = ScanLimits()
        monitor = ScanMonitor(limits)
        
        monitor.start()
        
        assert monitor.start_time > 0
        assert monitor.request_count == 0
    
    def test_increment(self):
        """Test incrementing request count"""
        limits = ScanLimits()
        monitor = ScanMonitor(limits)
        monitor.start()
        
        monitor.increment()
        assert monitor.request_count == 1
        
        monitor.increment()
        assert monitor.request_count == 2
    
    def test_can_continue_under_limits(self):
        """Test can continue under limits"""
        limits = ScanLimits(max_requests_per_scan=100, max_scan_duration_seconds=3600)
        monitor = ScanMonitor(limits)
        monitor.start()
        
        assert monitor.can_continue() is True
    
    def test_can_continue_request_limit_exceeded(self):
        """Test cannot continue when request limit exceeded"""
        limits = ScanLimits(max_requests_per_scan=5)
        monitor = ScanMonitor(limits)
        monitor.start()
        
        for _ in range(5):
            monitor.increment()
        
        assert monitor.can_continue() is False
    
    def test_can_continue_duration_exceeded(self):
        """Test cannot continue when duration exceeded"""
        limits = ScanLimits(max_scan_duration_seconds=1)
        monitor = ScanMonitor(limits)
        monitor.start()
        
        # Simulate time passing
        monitor.start_time = time.time() - 10  # 10 seconds ago
        
        assert monitor.can_continue() is False
    
    def test_get_stats(self):
        """Test getting statistics"""
        limits = ScanLimits(
            max_requests_per_scan=100,
            max_scan_duration_seconds=3600
        )
        monitor = ScanMonitor(limits)
        monitor.start()
        
        for _ in range(10):
            monitor.increment()
        
        stats = monitor.get_stats()
        
        assert stats['requests'] == 10
        assert stats['max_requests'] == 100
        assert stats['elapsed_seconds'] >= 0
        assert stats['max_duration_seconds'] == 3600


class TestScanLimits:
    """Test scan limits dataclass"""
    
    def test_default_values(self):
        """Test default values"""
        limits = ScanLimits()
        
        assert limits.max_requests_per_scan == 10000
        assert limits.max_scan_duration_seconds == 3600
        assert limits.max_concurrent_scans == 5
        assert limits.allowed_ips is None
        assert limits.blocked_ips is None
    
    def test_custom_values(self):
        """Test custom values"""
        limits = ScanLimits(
            max_requests_per_scan=5000,
            max_scan_duration_seconds=7200,
            max_concurrent_scans=10,
            allowed_ips=["192.168.1.0/24"],
            blocked_ips=["10.0.0.0/8"]
        )
        
        assert limits.max_requests_per_scan == 5000
        assert limits.max_scan_duration_seconds == 7200
        assert limits.max_concurrent_scans == 10
        assert len(limits.allowed_ips) == 1
        assert len(limits.blocked_ips) == 1


class TestGlobalKillSwitch:
    """Test global kill switch singleton"""
    
    def test_get_instance(self):
        """Test getting singleton instance"""
        ks = GlobalKillSwitch.get_instance()
        
        assert ks is not None
        assert isinstance(ks, KillSwitch)
    
    def test_stop_all(self):
        """Test stopping all scans globally"""
        GlobalKillSwitch.resume()  # Ensure active first
        
        GlobalKillSwitch.stop_all()
        
        assert GlobalKillSwitch.is_active() is False
    
    def test_resume(self):
        """Test resuming globally"""
        GlobalKillSwitch.stop_all()
        assert GlobalKillSwitch.is_active() is False
        
        GlobalKillSwitch.resume()
        assert GlobalKillSwitch.is_active() is True
    
    def test_singleton_behavior(self):
        """Test that singleton returns same instance"""
        ks1 = GlobalKillSwitch.get_instance()
        ks2 = GlobalKillSwitch.get_instance()
        
        assert ks1 is ks2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])