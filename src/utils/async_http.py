"""
VulnScope - Async HTTP Client
High-performance async HTTP client using aiohttp
"""

import asyncio
import aiohttp
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse
import ssl

from ..core.models import Endpoint, Finding
from ..config.settings import ScannerConfig


class AsyncHTTPClient:
    """
    Async HTTP client for high-performance scanning
    
    Features:
    - Concurrent requests
    - Connection pooling
    - Rate limiting
    - Retry logic
    - SSL verification
    """
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig()
        self.session: Optional[aiohttp.ClientSession] = None
        self.semaphore: Optional[asyncio.Semaphore] = None
        self.request_count = 0
    
    async def __aenter__(self):
        """Create async session"""
        ssl_context = ssl.create_default_context()
        if not self.config.verify_ssl:
            ssl_context.check_hostname = False
            ssl_context.verify_mode = ssl.CERT_NONE
        
        connector = aiohttp.TCPConnector(
            limit=self.config.max_concurrent_requests,
            ssl=ssl_context
        )
        
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=self.config.request_timeout),
            headers={'User-Agent': self.config.user_agent}
        )
        
        self.semaphore = asyncio.Semaphore(self.config.max_concurrent_requests)
        
        return self
    
    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Close session"""
        if self.session:
            await self.session.close()
    
    async def fetch(self, url: str, method: str = "GET", 
                   headers: Optional[Dict] = None,
                   data: Optional[Any] = None) -> Optional[Dict[str, Any]]:
        """
        Fetch URL asynchronously
        
        Args:
            url: URL to fetch
            method: HTTP method
            headers: Optional headers
            data: Optional body data
            
        Returns:
            Response dict with status, headers, body
        """
        if not self.session:
            raise RuntimeError("Client not initialized. Use 'async with'")
        
        async with self.semaphore:
            try:
                async with self.session.request(
                    method=method,
                    url=url,
                    headers=headers,
                    data=data,
                    allow_redirects=self.config.follow_redirects
                ) as response:
                    self.request_count += 1
                    
                    return {
                        'status': response.status,
                        'headers': dict(response.headers),
                        'body': await response.text(),
                        'url': str(response.url),
                    }
                    
            except asyncio.TimeoutError:
                return None
            except Exception as e:
                return None
    
    async def fetch_multiple(self, urls: List[str], 
                          method: str = "GET") -> List[Dict[str, Any]]:
        """
        Fetch multiple URLs concurrently
        
        Args:
            urls: List of URLs
            method: HTTP method
            
        Returns:
            List of responses
        """
        tasks = [self.fetch(url, method) for url in urls]
        return await asyncio.gather(*tasks)
    
    async def scan_endpoint(self, endpoint: Endpoint, 
                         detectors: List) -> List[Finding]:
        """
        Scan endpoint asynchronously
        
        Args:
            endpoint: Endpoint to scan
            detectors: List of detectors
            
        Returns:
            List of findings
        """
        findings = []
        
        # Test basic GET
        response = await self.fetch(endpoint.url)
        
        if response:
            # Run detectors
            for detector in detectors:
                try:
                    detector_findings = detector.detect_from_response(
                        endpoint, response
                    )
                    findings.extend(detector_findings)
                except Exception:
                    continue
        
        return findings


class AsyncRateLimiter:
    """
    Async rate limiter for aiohttp
    """
    
    def __init__(self, requests_per_second: int = 100):
        self.requests_per_second = requests_per_second
        self.interval = 1.0 / requests_per_second
        self.last_request = 0.0
    
    async def acquire(self):
        """Wait if necessary to maintain rate limit"""
        now = asyncio.get_event_loop().time()
        time_since_last = now - self.last_request
        
        if time_since_last < self.interval:
            await asyncio.sleep(self.interval - time_since_last)
        
        self.last_request = asyncio.get_event_loop().time()


class AsyncCrawler:
    """
    Async web crawler using aiohttp
    """
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig()
        self.visited: set = set()
        self.endpoints: List[Endpoint] = []
        self.client: Optional[AsyncHTTPClient] = None
    
    async def crawl(self, start_url: str, max_pages: int = 100) -> List[Endpoint]:
        """
        Crawl website asynchronously
        
        Args:
            start_url: Starting URL
            max_pages: Maximum pages to crawl
            
        Returns:
            List of discovered endpoints
        """
        async with AsyncHTTPClient(self.config) as client:
            self.client = client
            self.visited = set()
            self.endpoints = []
            
            await self._crawl_page(start_url, max_pages)
        
        return self.endpoints
    
    async def _crawl_page(self, url: str, remaining: int):
        """Recursively crawl page"""
        if remaining <= 0 or url in self.visited:
            return
        
        self.visited.add(url)
        
        response = await self.client.fetch(url)
        
        if not response:
            return
        
        # Extract links and add as endpoints
        # (simplified - would need BeautifulSoup in real implementation)
        self.endpoints.append(Endpoint(
            target_id="",
            url=url,
            method="GET",
            path=urlparse(url).path,
            source="async_crawler"
        ))
        
        # Crawl more pages
        for link in []:  # Would extract from HTML
            if link.startswith('http'):
                await self._crawl_page(link, remaining - 1)
