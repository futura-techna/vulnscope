"""
VulnScope - Advanced Scanner Features
Advanced scanning capabilities: recursive scanning, timeout handling, async improvements
"""

import asyncio
import time
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urljoin
import requests
from concurrent.futures import ThreadPoolExecutor, TimeoutError as FuturesTimeoutError

from ..core.models import (
    Endpoint, Finding, Scan, Target, Severity, 
    VulnerabilityType, Status
)
from ..config.settings import ScannerConfig
from .scanner import Scanner, ScanResult, ScanProgress


@dataclass
class EndpointTimeoutConfig:
    """Configuration for endpoint timeout handling"""
    default_timeout: int = 30
    slow_endpoint_threshold: float = 10.0  # seconds
    max_retries: int = 3
    retry_delay: float = 1.0


@dataclass
class RecursiveScanConfig:
    """Configuration for recursive scanning"""
    max_depth: int = 3
    follow_links: bool = True
    discover_params: bool = True
    test_authenticated: bool = True


class TimeoutHandler:
    """Handle timeouts for slow endpoints"""
    
    def __init__(self, config: EndpointTimeoutConfig):
        self.config = config
        self.slow_endpoints: Dict[str, float] = {}
        self.failed_endpoints: Dict[str, int] = {}
    
    def get_timeout(self, endpoint: str) -> float:
        """Get timeout for endpoint, adjusted based on history"""
        base_timeout = self.config.default_timeout
        
        # Check if endpoint is known to be slow
        if endpoint in self.slow_endpoints:
            # Use the recorded slow response time, capped at 2x default
            return min(self.slow_endpoints[endpoint] * 1.5, base_timeout * 2)
        
        return base_timeout
    
    def record_response_time(self, endpoint: str, duration: float):
        """Record response time for endpoint"""
        if duration > self.config.slow_endpoint_threshold:
            self.slow_endpoints[endpoint] = duration
    
    def record_failure(self, endpoint: str):
        """Record endpoint failure"""
        self.failed_endpoints[endpoint] = self.failed_endpoints.get(endpoint, 0) + 1
    
    def should_skip(self, endpoint: str) -> bool:
        """Check if endpoint should be skipped due to repeated failures"""
        return self.failed_endpoints.get(endpoint, 0) >= self.config.max_retries
    
    def get_endpoint_stats(self, endpoint: str) -> Dict[str, Any]:
        """Get statistics for an endpoint"""
        return {
            "response_time": self.slow_endpoints.get(endpoint, 0),
            "failure_count": self.failed_endpoints.get(endpoint, 0),
            "should_skip": self.should_skip(endpoint)
        }


class RecursiveScanner(Scanner):
    """
    Scanner with recursive endpoint discovery
    
    Features:
    - Recursively discover and test new endpoints
    - Parameter fuzzing for discovered endpoints
    - Depth-limited crawling during scan
    """
    
    def __init__(self, config: Optional[ScannerConfig] = None,
                 recursive_config: Optional[RecursiveScanConfig] = None):
        super().__init__(config)
        self.recursive_config = recursive_config or RecursiveScanConfig()
        self.timeout_handler = TimeoutHandler(EndpointTimeoutConfig())
        self.discovered_during_scan: List[Endpoint] = []
        self.scanned_urls: Set[str] = set()
    
    async def scan_recursive(self, endpoints: List[Endpoint],
                            target: Target, scan: Scan,
                            max_depth: int = None) -> ScanResult:
        """
        Recursively scan endpoints, discovering new ones during the scan
        
        Args:
            endpoints: Initial endpoints to scan
            target: Target application
            scan: Scan configuration
            max_depth: Maximum recursion depth
            
        Returns:
            ScanResult with all findings
        """
        max_depth = max_depth or self.recursive_config.max_depth
        result = await self.scan_endpoints_async(endpoints, target, scan)
        
        # Recursively scan discovered endpoints if depth allows
        for depth in range(1, max_depth):
            new_endpoints = self._extract_new_endpoints_from_responses()
            
            if not new_endpoints:
                break
            
            # Filter and dedupe
            new_endpoints = [e for e in new_endpoints 
                           if e.url not in self.scanned_urls]
            
            if not new_endpoints:
                break
            
            # Add new endpoints to discovered list
            self.discovered_during_scan.extend(new_endpoints)
            
            # Scan new endpoints
            depth_result = await self.scan_endpoints_async(
                new_endpoints, target, scan
            )
            
            # Merge results
            result.findings.extend(depth_result.findings)
            result.progress.scanned_endpoints += depth_result.progress.scanned_endpoints
        
        return result
    
    def _extract_new_endpoints_from_responses(self) -> List[Endpoint]:
        """Extract new endpoints from scan responses"""
        new_endpoints = []
        
        # This would analyze response content to find new endpoints
        # Implementation would parse HTML/JSON responses
        return new_endpoints
    
    def scan_with_timeout(self, endpoint: Endpoint) -> List[Finding]:
        """
        Scan endpoint with timeout handling
        
        Args:
            endpoint: Endpoint to scan
            
        Returns:
            List of findings
        """
        timeout = self.timeout_handler.get_timeout(endpoint.url)
        
        if self.timeout_handler.should_skip(endpoint.url):
            return []
        
        try:
            # Run scan in thread pool with timeout
            with ThreadPoolExecutor(max_workers=1) as executor:
                future = executor.submit(self._test_endpoint, endpoint)
                findings = future.result(timeout=timeout)
                
                # Record successful response time
                self.timeout_handler.record_response_time(endpoint.url, timeout)
                
                return findings
                
        except FuturesTimeoutError:
            self.timeout_handler.record_failure(endpoint.url)
            self.progress.errors.append(
                f"Timeout scanning {endpoint.url} after {timeout}s"
            )
            return []
        except Exception as e:
            self.timeout_handler.record_failure(endpoint.url)
            self.progress.errors.append(
                f"Error scanning {endpoint.url}: {str(e)}"
            )
            return []


class AsyncScanOptimizer:
    """Optimize async scanning performance"""
    
    def __init__(self, max_concurrent: int = 50):
        self.max_concurrent = max_concurrent
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.active_scans = 0
        self.completed_scans = 0
        self.failed_scans = 0
    
    async def scan_with_backpressure(self, endpoints: List[Endpoint],
                                     scan_func) -> List[Any]:
        """
        Scan endpoints with backpressure to avoid overwhelming the target
        
        Args:
            endpoints: Endpoints to scan
            scan_func: Async function to call for scanning
            
        Returns:
            List of results
        """
        self.semaphore = asyncio.Semaphore(self.max_concurrent)
        results = []
        
        async def limited_scan(endpoint):
            async with self.semaphore:
                self.active_scans += 1
                try:
                    result = await scan_func(endpoint)
                    self.completed_scans += 1
                    return result
                except Exception as e:
                    self.failed_scans += 1
                    return None
                finally:
                    self.active_scans -= 1
        
        # Create all scan tasks
        tasks = [limited_scan(ep) for ep in endpoints]
        
        # Run with gather for efficiency
        results = await asyncio.gather(*tasks, return_exceptions=True)
        
        return results
    
    def get_stats(self) -> Dict[str, Any]:
        """Get scan statistics"""
        return {
            "max_concurrent": self.max_concurrent,
            "active_scans": self.active_scans,
            "completed_scans": self.completed_scans,
            "failed_scans": self.failed_scans,
            "success_rate": (
                self.completed_scans / 
                (self.completed_scans + self.failed_scans) * 100
                if (self.completed_scans + self.failed_scans) > 0 else 0
            )
        }


class FuzzingWordlistManager:
    """Manage custom wordlists for fuzzing"""
    
    DEFAULT_WORDLISTS = {
        "parameters": [
            "id", "user", "username", "password", "email", "token",
            "search", "query", "page", "limit", "sort", "order",
            "filter", "category", "status", "action", "file", "path"
        ],
        "paths": [
            "admin", "api", "v1", "v2", "v3", "graphql", "rest",
            "internal", "private", "dev", "staging", "test",
            "backup", "config", "debug", "health", "status"
        ],
        "values": [
            "1", "0", "true", "false", "null", "none", "admin",
            "root", "test", "demo", "guest"
        ]
    }
    
    def __init__(self, wordlists_dir: str = None):
        self.wordlists_dir = wordlists_dir
        self.custom_wordlists: Dict[str, List[str]] = {}
        self._load_default_wordlists()
    
    def _load_default_wordlists(self):
        """Load default wordlists"""
        self.custom_wordlists = self.DEFAULT_WORDLISTS.copy()
    
    def load_wordlist(self, name: str, filepath: str) -> bool:
        """
        Load custom wordlist from file
        
        Args:
            name: Name for the wordlist
            filepath: Path to wordlist file
            
        Returns:
            True if loaded successfully
        """
        try:
            with open(filepath, 'r') as f:
                words = [line.strip() for line in f if line.strip()]
                self.custom_wordlists[name] = words
            return True
        except Exception:
            return False
    
    def add_word(self, wordlist_name: str, word: str):
        """Add word to wordlist"""
        if wordlist_name not in self.custom_wordlists:
            self.custom_wordlists[wordlist_name] = []
        if word not in self.custom_wordlists[wordlist_name]:
            self.custom_wordlists[wordlist_name].append(word)
    
    def get_wordlist(self, name: str) -> List[str]:
        """Get wordlist by name"""
        return self.custom_wordlists.get(name, [])
    
    def generate_fuzz_payloads(self, base_value: str, 
                              wordlist: str = "values") -> List[str]:
        """Generate fuzzing payloads from wordlist"""
        words = self.get_wordlist(wordlist)
        return [f"{base_value}{w}" for w in words]
    
    def get_all_wordlists(self) -> Dict[str, List[str]]:
        """Get all loaded wordlists"""
        return self.custom_wordlists.copy()
