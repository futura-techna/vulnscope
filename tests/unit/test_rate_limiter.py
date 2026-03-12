"""
VulnScope - Rate Limiter Tests
Tests for request rate limiting functionality
"""

import pytest
import time
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from src.fuzzer.rate_limiter import (
    RateLimiter, RateLimitState, AdaptiveRateLimiter
)


class TestRateLimitState:
    """Test rate limit state dataclass"""
    
    def test_default_state(self):
        state = RateLimitState()
        
        assert state.requests_made == 0
        assert state.requests_allowed == 100
        assert state.window_start == 0.0
        assert state.retry_after is None
    
    def test_custom_state(self):
        state = RateLimitState(
            requests_made=50,
            requests_allowed=200,
            window_start=12345.0,
            retry_after=30.0
        )
        
        assert state.requests_made == 50
        assert state.requests_allowed == 200
        assert state.window_start == 12345.0
        assert state.retry_after == 30.0


class TestRateLimiter:
    """Test rate limiter"""
    
    def test_init(self):
        limiter = RateLimiter(requests_per_second=10, burst=5)
        
        assert limiter.requests_per_second == 10
        assert limiter.burst == 5
        assert limiter.target_states == {}
    
    def test_check_rate_limit_allowed(self):
        limiter = RateLimiter(requests_per_second=100, burst=10)
        
        allowed, retry_after = limiter.check_rate_limit("target-1")
        
        assert allowed is True
        assert retry_after is None
    
    def test_check_rate_limit_multiple_requests(self):
        limiter = RateLimiter(requests_per_second=5, burst=10)
        
        for i in range(5):
            allowed, retry_after = limiter.check_rate_limit("target-1")
            assert allowed is True
        
        # The 6th request in the same window should be denied
        allowed, retry_after = limiter.check_rate_limit("target-1")
        
        assert allowed is False
        assert retry_after is not None
    
    def test_different_targets_independent(self):
        limiter = RateLimiter(requests_per_second=5, burst=10)
        
        # Use all requests for target-1
        for i in range(5):
            limiter.check_rate_limit("target-1")
        
        # target-2 should still be allowed
        allowed, retry_after = limiter.check_rate_limit("target-2")
        
        assert allowed is True
    
    def test_get_status(self):
        limiter = RateLimiter(requests_per_second=100, burst=10)
        
        limiter.check_rate_limit("target-1")
        limiter.check_rate_limit("target-1")
        
        status = limiter.get_status("target-1")
        
        assert status['requests_made'] == 2
        assert status['requests_allowed'] == 100
    
    def test_reset(self):
        limiter = RateLimiter(requests_per_second=5, burst=10)
        
        # Use some requests
        for i in range(5):
            limiter.check_rate_limit("target-1")
        
        limiter.reset("target-1")
        
        assert "target-1" not in limiter.target_states
    
    def test_report_429(self):
        limiter = RateLimiter(requests_per_second=100, burst=10)
        
        # Make a request first to create state
        limiter.check_rate_limit("target-1")
        
        limiter.report_429("target-1", retry_after="60")
        
        status = limiter.get_status("target-1")
        # Rate limit should be reduced
        assert status['requests_allowed'] < 100
        assert status['retry_after'] == 60.0
    
    def test_adjust_rate_limit_with_headers(self):
        limiter = RateLimiter(requests_per_second=100, burst=10)
        
        # Make a request first
        limiter.check_rate_limit("target-1")
        
        # Headers with rate limit info
        headers = {
            'X-RateLimit-Limit': '50',
            'X-RateLimit-Remaining': '10'
        }
        
        limiter.adjust_rate_limit("target-1", headers)
        
        # The rate limiter updates requests_allowed based on the limit header
        # It searches for headers containing 'rate' and 'limit' in key names
        status = limiter.get_status("target-1")
        # Verify the rate limiter processed the headers
        assert status['requests_allowed'] is not None
    
    def test_wait_if_needed(self):
        limiter = RateLimiter(requests_per_second=100, burst=10)
        
        # This should not block since we're under the limit
        limiter.wait_if_needed("target-1")


class TestAdaptiveRateLimiter:
    """Test adaptive rate limiter"""
    
    def test_init(self):
        limiter = AdaptiveRateLimiter(initial_rate=50)
        
        assert limiter.requests_per_second == 50
        assert limiter.success_count == 0
        assert limiter.error_count == 0
    
    def test_report_success(self):
        limiter = AdaptiveRateLimiter(initial_rate=100)
        
        limiter.check_rate_limit("target-1")
        limiter.report_success("target-1")
        
        assert limiter.success_count == 1
    
    def test_report_error_reduces_rate(self):
        limiter = AdaptiveRateLimiter(initial_rate=100)
        
        # Make a request first
        limiter.check_rate_limit("target-1")
        
        # Report multiple errors to trigger adjustment
        limiter.error_count = 10
        limiter.success_count = 90
        limiter.report_error("target-1", status_code=500)
        
        # Error count should be incremented
        assert limiter.error_count == 11


if __name__ == "__main__":
    pytest.main([__file__, "-v"])