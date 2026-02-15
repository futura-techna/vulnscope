"""
VulnScope - Rate Limiter
Intelligent rate limiting for API fuzzing
"""

import time
from typing import Optional, Dict, Any
from threading import Lock
from dataclasses import dataclass


@dataclass
class RateLimitState:
    """Rate limit state for a target"""
    requests_made: int = 0
    requests_allowed: int = 100
    window_start: float = 0.0
    retry_after: Optional[float] = None


class RateLimiter:
    """
    Intelligent rate limiter with dynamic adjustment
    
    Features:
    - Token bucket algorithm
    - Adaptive rate limiting based on server responses
    - Per-target rate limiting
    - Retry handling
    """
    
    def __init__(self, requests_per_second: int = 100, burst: int = 10):
        self.requests_per_second = requests_per_second
        self.burst = burst
        
        # Per-target state
        self.target_states: Dict[str, RateLimitState] = {}
        self.lock = Lock()
        
        # Timing
        self.min_request_interval = 1.0 / requests_per_second
    
    def _get_state(self, target: str) -> RateLimitState:
        """Get or create rate limit state for target"""
        with self.lock:
            if target not in self.target_states:
                self.target_states[target] = RateLimitState(
                    requests_allowed=self.requests_per_second,
                    window_start=time.time()
                )
            return self.target_states[target]
    
    def _update_state(self, target: str, state: RateLimitState):
        """Update rate limit state"""
        with self.lock:
            self.target_states[target] = state
    
    def check_rate_limit(self, target: str) -> tuple[bool, Optional[float]]:
        """
        Check if request is allowed
        
        Returns:
            Tuple of (allowed, retry_after)
        """
        state = self._get_state(target)
        now = time.time()
        
        # Check if we need to reset the window
        if now - state.window_start >= 1.0:
            state.requests_made = 0
            state.window_start = now
            state.retry_after = None
        
        # Check if we can make a request
        if state.requests_made < state.requests_allowed:
            state.requests_made += 1
            self._update_state(target, state)
            return True, None
        
        # Rate limited
        retry_after = 1.0 - (now - state.window_start)
        state.retry_after = retry_after
        self._update_state(target, state)
        
        return False, retry_after
    
    def wait_if_needed(self, target: str):
        """Wait if rate limited"""
        allowed, retry_after = self.check_rate_limit(target)
        
        if not allowed and retry_after:
            time.sleep(retry_after)
    
    def adjust_rate_limit(self, target: str, response_headers: Dict[str, str]):
        """
        Adjust rate limit based on server response
        
        Args:
            target: Target URL
            response_headers: Response headers from server
        """
        state = self._get_state(target)
        
        # Check for rate limit headers
        limit_header = None
        remaining_header = None
        reset_header = None
        
        for key in response_headers:
            key_lower = key.lower()
            if 'rate' in key_lower and 'limit' in key_lower:
                limit_header = key
            if 'rate' in key_lower and 'remaining' in key_lower:
                remaining_header = key
            if 'rate' in key_lower and 'reset' in key_lower:
                reset_header = key
        
        if limit_header:
            try:
                state.requests_allowed = int(response_headers[limit_header])
            except (ValueError, TypeError):
                pass
        
        if remaining_header:
            try:
                remaining = int(response_headers[remaining_header])
                if remaining < 5:
                    # Reduce rate limit
                    state.requests_allowed = max(10, state.requests_allowed // 2)
            except (ValueError, TypeError):
                pass
        
        if reset_header:
            try:
                reset_time = int(response_headers[reset_header])
                state.retry_after = max(0, reset_time - time.time())
            except (ValueError, TypeError):
                pass
        
        self._update_state(target, state)
    
    def report_429(self, target: str, retry_after: Optional[str] = None):
        """
        Report 429 Too Many Requests response
        
        Args:
            target: Target URL
            retry_after: Retry-After header value
        """
        state = self._get_state(target)
        
        # Reduce rate limit significantly
        state.requests_allowed = max(1, state.requests_allowed // 4)
        
        # Set retry time
        if retry_after:
            try:
                state.retry_after = float(retry_after)
            except (ValueError, TypeError):
                state.retry_after = 60.0
        else:
            state.retry_after = 60.0
        
        self._update_state(target, state)
    
    def reset(self, target: str):
        """Reset rate limit for target"""
        with self.lock:
            if target in self.target_states:
                del self.target_states[target]
    
    def get_status(self, target: str) -> Dict[str, Any]:
        """Get rate limit status for target"""
        state = self._get_state(target)
        
        return {
            'requests_made': state.requests_made,
            'requests_allowed': state.requests_allowed,
            'window_seconds': time.time() - state.window_start,
            'retry_after': state.retry_after,
        }


class AdaptiveRateLimiter(RateLimiter):
    """
    Adaptive rate limiter that automatically adjusts based on server behavior
    """
    
    def __init__(self, initial_rate: int = 100):
        super().__init__(requests_per_second=initial_rate)
        self.success_count = 0
        self.error_count = 0
        self.last_adjustment = time.time()
        self.adjustment_interval = 10  # seconds
    
    def report_success(self, target: str):
        """Report successful request"""
        self.success_count += 1
        self._maybe_adjust(target)
    
    def report_error(self, target: str, status_code: int):
        """Report error response"""
        if status_code == 429:
            self.report_429(target)
        else:
            self.error_count += 1
        
        self._maybe_adjust(target)
    
    def _maybe_adjust(self, target: str):
        """Maybe adjust rate limit"""
        now = time.time()
        
        if now - self.last_adjustment < self.adjustment_interval:
            return
        
        total = self.success_count + self.error_count
        if total == 0:
            return
        
        error_rate = self.error_count / total
        
        state = self._get_state(target)
        
        # Adjust based on error rate
        if error_rate > 0.1:  # >10% errors
            state.requests_allowed = max(10, int(state.requests_allowed * 0.5))
        elif error_rate < 0.01:  # <1% errors
            state.requests_allowed = min(1000, int(state.requests_allowed * 1.2))
        
        self._update_state(target, state)
        
        # Reset counters
        self.success_count = 0
        self.error_count = 0
        self.last_adjustment = now
