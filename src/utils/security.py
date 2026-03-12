"""
VulnScope - Security Features
Sandbox, Kill Switch, IP Limiting for safe scanning
"""

import os
import time
import signal
from typing import Dict, Any, Optional, List
from dataclasses import dataclass
from threading import Lock
import ipaddress

# Try to import psutil for resource monitoring
try:
    import psutil
    PSUTIL_AVAILABLE = True
except ImportError:
    psutil = None
    PSUTIL_AVAILABLE = False


@dataclass
class ScanLimits:
    """Scan limits configuration"""
    max_requests_per_scan: int = 10000
    max_scan_duration_seconds: int = 3600
    max_concurrent_scans: int = 5
    allowed_ips: Optional[List[str]] = None
    blocked_ips: Optional[List[str]] = None


class KillSwitch:
    """
    Global kill switch for emergency scan termination
    
    Features:
    - Emergency stop all scans
    - Graceful shutdown
    - Status tracking
    """
    
    def __init__(self):
        self._active = True
        self._lock = Lock()
        self._shutdown_requested = False
    
    @property
    def is_active(self) -> bool:
        """Check if scanner is active"""
        with self._lock:
            return self._active and not self._shutdown_requested
    
    def stop(self):
        """Stop all scans"""
        with self._lock:
            self._active = False
            self._shutdown_requested = True
    
    def resume(self):
        """Resume scanning"""
        with self._lock:
            self._active = True
            self._shutdown_requested = False
    
    def request_shutdown(self):
        """Request graceful shutdown"""
        with self._lock:
            self._shutdown_requested = True
    
    def check(self) -> bool:
        """Check if should continue"""
        return self.is_active


class IPBlacklist:
    """
    IP blacklist/whitelist for target filtering
    
    Features:
    - IP range support
    - CIDR notation
    - Whitelist mode
    """
    
    def __init__(self, allowed_ips: Optional[List[str]] = None, 
                 blocked_ips: Optional[List[str]] = None):
        self.allowed_networks = []
        self.blocked_networks = []
        
        if allowed_ips:
            for ip in allowed_ips:
                try:
                    self.allowed_networks.append(ipaddress.ip_network(ip, strict=False))
                except ValueError:
                    pass
        
        if blocked_ips:
            for ip in blocked_ips:
                try:
                    self.blocked_networks.append(ipaddress.ip_network(ip, strict=False))
                except ValueError:
                    pass
    
    def is_allowed(self, ip: str) -> bool:
        """Check if IP is allowed"""
        try:
            ip_obj = ipaddress.ip_address(ip)
        except ValueError:
            return False
        
        # Check blacklist first
        for network in self.blocked_networks:
            if ip_obj in network:
                return False
        
        # If whitelist is empty, allow all
        if not self.allowed_networks:
            return True
        
        # Check whitelist
        for network in self.allowed_networks:
            if ip_obj in network:
                return True
        
        return False


class RateLimitByIP:
    """
    Per-IP rate limiting
    
    Features:
    - Track requests per IP
    - Sliding window
    - Configurable limits
    """
    
    def __init__(self, requests_per_minute: int = 60):
        self.requests_per_minute = requests_per_minute
        self.ip_requests: Dict[str, List[float]] = {}
        self._lock = Lock()
    
    def check(self, ip: str) -> bool:
        """Check if request is allowed"""
        with self._lock:
            now = time.time()
            window_start = now - 60
            
            if ip not in self.ip_requests:
                self.ip_requests[ip] = []
            
            # Clean old requests
            self.ip_requests[ip] = [
                t for t in self.ip_requests[ip] 
                if t > window_start
            ]
            
            # Check limit
            if len(self.ip_requests[ip]) >= self.requests_per_minute:
                return False
            
            # Add current request
            self.ip_requests[ip].append(now)
            return True
    
    def get_remaining(self, ip: str) -> int:
        """Get remaining requests for IP"""
        with self._lock:
            now = time.time()
            window_start = now - 60
            
            if ip not in self.ip_requests:
                return self.requests_per_minute
            
            recent = [t for t in self.ip_requests[ip] if t > window_start]
            return max(0, self.requests_per_minute - len(recent))


class SandboxEnvironment:
    """
    Sandbox environment for safe payload execution
    
    Features:
    - Resource limits
    - Timeout enforcement
    - Memory limits
    """
    
    def __init__(self, timeout_seconds: int = 30, max_memory_mb: int = 512):
        self.timeout_seconds = timeout_seconds
        self.max_memory_mb = max_memory_mb
    
    def execute_safe(self, func, *args, **kwargs):
        """Execute function in sandbox"""
        import signal
        
        def timeout_handler(signum, frame):
            raise TimeoutError("Execution timed out")
        
        # Set timeout
        old_handler = signal.signal(signal.SIGALRM, timeout_handler)
        signal.alarm(self.timeout_seconds)
        
        try:
            result = func(*args, **kwargs)
        finally:
            # Restore handler
            signal.alarm(0)
            signal.signal(signal.SIGALRM, old_handler)
        
        return result
    
    def check_resources(self) -> Dict[str, Any]:
        """Check resource usage"""
        if not PSUTIL_AVAILABLE or psutil is None:
            return {
                'memory_mb': 0,
                'memory_limit_mb': self.max_memory_mb,
                'within_limits': True,
                'error': 'psutil not available'
            }
        
        process = psutil.Process()
        
        memory_mb = process.memory_info().rss / 1024 / 1024
        
        return {
            'memory_mb': memory_mb,
            'memory_limit_mb': self.max_memory_mb,
            'within_limits': memory_mb < self.max_memory_mb,
        }


class ScanMonitor:
    """
    Monitor scan progress and resources
    
    Features:
    - Request counting
    - Duration tracking
    - Resource monitoring
    """
    
    def __init__(self, limits: ScanLimits):
        self.limits = limits
        self.request_count = 0
        self.start_time = 0.0
        self._lock = Lock()
    
    def start(self):
        """Start monitoring"""
        with self._lock:
            self.request_count = 0
            self.start_time = time.time()
    
    def increment(self):
        """Increment request count"""
        with self._lock:
            self.request_count += 1
    
    def can_continue(self) -> bool:
        """Check if scan can continue"""
        with self._lock:
            # Check request limit
            if self.request_count >= self.limits.max_requests_per_scan:
                return False
            
            # Check duration
            elapsed = time.time() - self.start_time
            if elapsed >= self.limits.max_scan_duration_seconds:
                return False
            
            return True
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scan statistics"""
        with self._lock:
            elapsed = time.time() - self.start_time
            return {
                'requests': self.request_count,
                'max_requests': self.limits.max_requests_per_scan,
                'elapsed_seconds': elapsed,
                'max_duration_seconds': self.limits.max_scan_duration_seconds,
            }


class GlobalKillSwitch:
    """Global kill switch singleton"""
    _instance = None
    _switch = None
    
    @classmethod
    def get_instance(cls):
        if cls._instance is None:
            cls._instance = cls()
            cls._switch = KillSwitch()
        return cls._switch
    
    @classmethod
    def stop_all(cls):
        """Stop all scans globally"""
        cls.get_instance().stop()
    
    @classmethod
    def resume(cls):
        """Resume scanning"""
        cls.get_instance().resume()
    
    @classmethod
    def is_active(cls) -> bool:
        """Check if active"""
        return cls.get_instance().is_active
