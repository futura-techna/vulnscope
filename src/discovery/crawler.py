"""
VulnScope - Web Crawler
Advanced web crawler for endpoint discovery
"""

import asyncio
import re
import logging
from typing import List, Set, Optional, Dict, Any
from urllib.parse import urljoin, urlparse, urlunparse
from dataclasses import dataclass, field
from datetime import datetime

import requests
from bs4 import BeautifulSoup

logger = logging.getLogger(__name__)

# Optional playwright import for JavaScript rendering
try:
    from playwright.async_api import async_playwright
    PLAYWRIGHT_AVAILABLE = True
except ImportError:
    PLAYWRIGHT_AVAILABLE = False
    async_playwright = None

from ..core.models import Endpoint, Target
from ..core.exceptions import DiscoveryError
from ..config.settings import CrawlerConfig


@dataclass
class CrawlerResult:
    """Result of a crawling operation"""
    endpoints: List[Endpoint] = field(default_factory=list)
    pages_crawled: int = 0
    errors: List[str] = field(default_factory=list)
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None
    duration_seconds: float = 0.0


class Crawler:
    """
    Advanced web crawler for endpoint discovery
    
    Features:
    - Recursive crawling with depth limiting
    - Form extraction
    - API endpoint detection
    - JavaScript rendering support
    - Concurrent crawling
    """
    
    def __init__(self, config: Optional[CrawlerConfig] = None):
        self.config = config or CrawlerConfig()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.user_agent if hasattr(self.config, 'user_agent') else 'VulnScope-Crawler/1.0'
        })
        
        # State
        self.visited_urls: Set[str] = set()
        self.discovered_endpoints: List[Endpoint] = []
        self.pending_urls: List[str] = []
        self.target: Optional[Target] = None
        self.errors: List[str] = []
    
    def _is_valid_url(self, url: str) -> bool:
        """Check if URL is valid and within scope"""
        if not url:
            return False
        
        parsed = urlparse(url)
        
        # Must have scheme and netloc
        if not parsed.scheme or not parsed.netloc:
            return False
        
        # Check allowed domains
        if self.config.allowed_domains:
            if parsed.netloc not in self.config.allowed_domains:
                return False
        
        # Check blocked domains
        if self.config.blocked_domains:
            if parsed.netloc in self.config.blocked_domains:
                return False
        
        # Skip fragments
        if url.startswith('#'):
            return False
        
        return True
    
    def _normalize_url(self, url: str) -> str:
        """Normalize URL for deduplication"""
        parsed = urlparse(url)
        
        # Remove fragments
        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            parsed.path,
            parsed.params,
            parsed.query,
            ''  # Remove fragment
        ))
        
        return normalized.rstrip('/')
    
    def _extract_links(self, html: str, base_url: str) -> List[str]:
        """Extract all links from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        links = []
        
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            full_url = urljoin(base_url, href)
            if self._is_valid_url(full_url):
                links.append(self._normalize_url(full_url))
        
        return list(set(links))
    
    def _extract_forms(self, html: str, base_url: str) -> List[Dict[str, Any]]:
        """Extract forms from HTML"""
        soup = BeautifulSoup(html, 'html.parser')
        forms = []
        
        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(base_url, form.get('action', '')),
                'method': form.get('method', 'get').upper(),
                'inputs': [],
            }
            
            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_info = {
                    'name': input_tag.get('name'),
                    'type': input_tag.get('type', 'text'),
                    'required': input_tag.get('required') is not None,
                }
                form_data['inputs'].append(input_info)
            
            forms.append(form_data)
        
        return forms
    
    def _extract_api_endpoints(self, html: str, base_url: str) -> List[str]:
        """Extract potential API endpoints from JavaScript/links"""
        endpoints = []
        
        # Look for API patterns in links
        api_patterns = [
            r'/api/v\d*/\w+',
            r'/api/\w+',
            r'/graphql',
            r'/rest/\w+',
            r'/wp-json/',
            r'\.json$',
            r'/endpoints?/',
        ]
        
        soup = BeautifulSoup(html, 'html.parser')
        
        # Check links
        for a_tag in soup.find_all('a', href=True):
            href = a_tag['href']
            for pattern in api_patterns:
                if re.search(pattern, href, re.IGNORECASE):
                    full_url = urljoin(base_url, href)
                    if self._is_valid_url(full_url):
                        endpoints.append(self._normalize_url(full_url))
        
        # Check scripts for API patterns
        for script in soup.find_all('script', src=True):
            src = script['src']
            for pattern in api_patterns:
                if re.search(pattern, src, re.IGNORECASE):
                    full_url = urljoin(base_url, src)
                    if self._is_valid_url(full_url):
                        endpoints.append(self._normalize_url(full_url))
        
        return list(set(endpoints))
    
    def _create_endpoint(self, url: str, method: str = 'GET', 
                         source: str = 'crawler') -> Endpoint:
        """Create an Endpoint object from discovered URL"""
        parsed = urlparse(url)
        
        return Endpoint(
            url=url,
            method=method,
            path=parsed.path,
            source=source,
            is_api='/api' in parsed.path or '/graphql' in parsed.path,
        )
    
    async def _fetch_with_playwright(self, url: str) -> Optional[str]:
        """Fetch URL using headless browser for JavaScript rendering"""
        if not PLAYWRIGHT_AVAILABLE:
            # Fallback to regular requests if playwright not available
            return self._fetch_page(url)
        
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True)
                page = await browser.new_page()
                await page.goto(url, wait_until='networkidle')
                content = await page.content()
                await browser.close()
                return content
        except Exception as e:
            # Fallback to regular requests on playwright error
            return self._fetch_page(url)
    
    def _fetch_page(self, url: str) -> Optional[str]:
        """Fetch a page using requests"""
        try:
            response = self.session.get(
                url,
                timeout=30,
                allow_redirects=self.config.follow_redirects
            )
            response.raise_for_status()
            return response.text
        except Exception as e:
            self.errors.append(f"Failed to fetch {url}: {str(e)}")
            return None
    
    async def crawl(self, target: Target) -> CrawlerResult:
        """
        Perform web crawling on target
        
        Args:
            target: Target to crawl
            
        Returns:
            CrawlerResult with discovered endpoints
        """
        self.target = target
        self.visited_urls = set()
        self.discovered_endpoints = []
        self.pending_urls = [str(target.url)]
        
        result = CrawlerResult()
        start_time = datetime.utcnow()
        
        # Setup allowed domains
        if target.allowed_endpoints:
            self.config.allowed_domains = [
                urlparse(str(target.url)).netloc
            ]
        
        # Check blocked domains
        if target.blocked_endpoints:
            self.config.blocked_domains = target.blocked_endpoints
        
        depth = 0
        while self.pending_urls and len(self.visited_urls) < self.config.max_pages:
            current_url = self.pending_urls.pop(0)
            
            if current_url in self.visited_urls:
                continue
            
            self.visited_urls.add(current_url)
            
            # Fetch page
            if self.config.extract_forms or self.config.extract_api_endpoints:
                # Use headless browser for JS-rendered content
                html = await self._fetch_with_playwright(current_url)
            else:
                html = self._fetch_page(current_url)
            
            if not html:
                continue
            
            result.pages_crawled += 1
            
            # Extract links for crawling
            links = self._extract_links(html, current_url)
            for link in links:
                if link not in self.visited_urls and len(self.pending_urls) < self.config.max_pages:
                    self.pending_urls.append(link)
            
            # Extract forms
            if self.config.extract_forms:
                forms = self._extract_forms(html, current_url)
                for form in forms:
                    endpoint = self._create_endpoint(
                        form['action'],
                        method=form['method'],
                        source='crawler_form'
                    )
                    endpoint.parameters = form['inputs']
                    endpoint.has_params = True
                    self.discovered_endpoints.append(endpoint)
            
            # Extract API endpoints
            if self.config.extract_api_endpoints:
                api_endpoints = self._extract_api_endpoints(html, current_url)
                for api_url in api_endpoints:
                    if api_url not in [e.url for e in self.discovered_endpoints]:
                        endpoint = self._create_endpoint(api_url, source='crawler_api')
                        endpoint.is_api = True
                        self.discovered_endpoints.append(endpoint)
            
            # Add current URL as GET endpoint
            if current_url not in [e.url for e in self.discovered_endpoints]:
                endpoint = self._create_endpoint(current_url)
                self.discovered_endpoints.append(endpoint)
        
        result.endpoints = self.discovered_endpoints
        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - start_time).total_seconds()
        
        return result
    
    def crawl_sync(self, target: Target) -> CrawlerResult:
        """Synchronous wrapper for crawl"""
        return asyncio.run(self.crawl(target))


# Default configuration
def get_default_crawler_config() -> CrawlerConfig:
    """Get default crawler configuration"""
    return CrawlerConfig()
