"""
VulnScope - Rate Limiter Tests
Tests for request rate limiting functionality
"""

import pytest
import time
from unittest.mock import Mock, patch
from datetime import datetime, timedelta

from src.fuzzer.rate_limiter import (
    RateLimiter, TokenBucket, SlidingWindowLimiter,
    RateLimitConfig, RateLimitExceeded
)


class TestTokenBucket:
    """Test token bucket algorithm"""
    
    def test_init(self):
        bucket = TokenBucket(capacity=10, refill_rate=2)
        
        assert bucket.capacity == 10
        assert bucket.refill_rate == 2
        assert bucket.tokens == 10
    
    def test_consume_token(self):
        bucket = TokenBucket(capacity=10, refill_rate=2)
        
        result = bucket.consume(1)
        
        assert result is True
        assert bucket.tokens == 9
    
    def test_consume_multiple_tokens(self):
        bucket = TokenBucket(capacity=10, refill_rate=2)
        
        result = bucket.consume(5)
        
        assert result is True
        assert bucket.tokens == 5
    
    def test_consume_more_than_available(self):
        bucket = TokenBucket(capacity=10, refill_rate=2)
        
        result = bucket.consume(15)
        
        assert result is False
        assert bucket.tokens == 10  # Should not change
    
    def test_refill_tokens(self):
        bucket = TokenBucket(capacity=10, refill_rate=2)
        bucket.tokens = 5
        bucket.last_refill = datetime.utcnow() - timedelta(seconds=2)
        
        bucket._refill()
        
        # Should add 2 * 2 = 4 tokens (but capped at capacity)
        assert bucket.tokens == 9
    
    def test_refill_capped_at_capacity(self):
        bucket = TokenBucket(capacity=10, refill_rate=5)
        bucket.tokens = 8
        bucket.last_refill = datetime.utcnow() - timedelta(seconds=1)
        
        bucket._refill()
        
        # Should not exceed capacity
        assert bucket.tokens == 10


class TestSlidingWindowLimiter:
    """Test sliding window rate limiter"""
    
    def test_init(self):
        limiter = SlidingWindowLimiter(max_requests=100, window_seconds=60)
        
        assert limiter.max_requests == 100
        assert limiter.window_seconds == 60
    
    def test_allow_request(self):
        limiter = SlidingWindowLimiter(max_requests=10, window_seconds=60)
        
        result = limiter.is_allowed("client-1")
        
        assert result is True
    
    def test_allow_multiple_requests(self):
        limiter = SlidingWindowLimiter(max_requests=10, window_seconds=60)
        
        for i in range(10):
            result = limiter.is_allowed("client-1")
            assert result is True
    
    def test_deny_over_limit(self):
        limiter = SlidingWindowLimiter(max_requests=5, window_seconds=60)
        
        # Make 5 requests (allowed)
        for i in range(5):
            limiter.is_allowed("client-1")
        
        # 6th request should be denied
        result = limiter.is_allowed("client-1")
        
        assert result is False
    
    def test_different_clients_independent(self):
        limiter = SlidingWindowLimiter(max_requests=5, window_seconds=60)
        
        # Client 1 uses all requests
        for i in range(5):
            limiter.is_allowed("client-1")
        
        # Client 2 should still be allowed
        result = limiter.is_allowed("client-2")
        
        assert result is True
    
    def test_window_expiry(self):
        limiter = SlidingWindowLimiter(max_requests=5, window_seconds=1)
        
        # Use all requests
        for i in range(5):
            limiter.is_allowed("client-1")
        
        # Wait for window to expire
        time.sleep(1.1)
        
        # Should be allowed again
        result = limiter.is_allowed("client-1")
        
        assert result is True


class TestRateLimiter:
    """Test rate limiter facade"""
    
    def test_init(self):
        config = RateLimitConfig(
            requests_per_second=10,
            burst_size=20
        )
        limiter = RateLimiter(config)
        
        assert limiter.config.requests_per_second == 10
    
    def test_check_rate_limit_allowed(self):
        config = RateLimitConfig(requests_per_second=10, burst_size=20)
        limiter = RateLimiter(config)
        
        result = limiter.check("client-1")
        
        assert result.allowed is True
    
    def test_check_rate_limit_exceeded(self):
        config = RateLimitConfig(requests_per_second=2, burst_size=2)
        limiter = RateLimiter(config)
        
        # Use all tokens
        limiter.check("client-1")
        limiter.check("client-1")
        
        # Should be denied
        result = limiter.check("client-1")
        
        assert result.allowed is False
    
    def test_get_remaining_requests(self):
        config = RateLimitConfig(requests_per_second=10, burst_size=10)
        limiter = RateLimiter(config)
        
        limiter.check("client-1")
        limiter.check("client-1")
        
        remaining = limiter.get_remaining("client-1")
        
        assert remaining == 8
    
    def test_reset_client(self):
        config = RateLimitConfig(requests_per_second=10, burst_size=10)
        limiter = RateLimiter(config)
        
        # Use all tokens
        for i in range(10):
            limiter.check("client-1")
        
        limiter.reset("client-1")
        
        remaining = limiter.get_remaining("client-1")
        assert remaining == 10
    
    def test_wait_time_calculation(self):
        config = RateLimitConfig(requests_per_second=10, burst_size=10)
        limiter = RateLimiter(config)
        
        # Use all tokens
        for i in range(10):
            limiter.check("client-1")
        
        result = limiter.check("client-1")
        
        assert result.allowed is False
        assert result.wait_time > 0


class TestRateLimitConfig:
    """Test rate limit configuration"""
    
    def test_default_config(self):
        config = RateLimitConfig()
        
        assert config.requests_per_second == 10
        assert config.burst_size == 20
    
    def test_custom_config(self):
        config = RateLimitConfig(
            requests_per_second=100,
            burst_size=200,
            cooldown_seconds=30
        )
        
        assert config.requests_per_second == 100
        assert config.burst_size == 200
        assert config.cooldown_seconds == 30


class TestRateLimitExceeded:
    """Test rate limit exceeded exception"""
    
    def test_exception_message(self):
        error = RateLimitExceeded(retry_after=5)
        
        assert "5" in str(error)
        assert error.retry_after == 5
    
    def test_exception_with_details(self):
        error = RateLimitExceeded(
            retry_after=10,
            message="Rate limit exceeded for client"
        )
        
        assert error.retry_after == 10
        assert "exceeded" in str(error).lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])