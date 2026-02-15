"""
VulnScope - Advanced Discovery Features
Advanced discovery capabilities: WebSocket, passive scanning, JS parsing, API versioning
"""

import asyncio
import re
import json
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, urljoin
import requests
from bs4 import BeautifulSoup

# Optional: WebSocket support - gracefully handle if not installed
try:
    import websocket
    WEBSOCKET_AVAILABLE = True
except ImportError:
    WEBSOCKET_AVAILABLE = False
    websocket = None

from ..core.models import Endpoint, Target
from .crawler import Crawler, CrawlerResult
from ..config.settings import CrawlerConfig


@dataclass
class WebSocketDiscoveryConfig:
    """Configuration for WebSocket discovery"""
    enabled: bool = True
    protocols: List[str] = field(default_factory=lambda: ["ws://", "wss://"])
    timeout: int = 10
    test_endpoints: bool = True


@dataclass
class JavaScriptParserConfig:
    """Configuration for JavaScript parsing"""
    extract_apis: bool = True
    extract_endpoints: bool = True
    parse_ajax_calls: bool = True
    extract_spa_routes: bool = True


@dataclass  
class APIVersionConfig:
    """Configuration for API versioning detection"""
    detect_versions: bool = True
    common_patterns: List[str] = field(default_factory=lambda: [
        "/v1/", "/v2/", "/v3/", "/api/v1/", "/api/v2/",
        "/api/v1alpha/", "/api/v1beta/", "/api/v2beta/"
    ])


class WebSocketDiscovery:
    """
    WebSocket endpoint discovery
    
    Features:
    - Discover WebSocket endpoints from HTML and JavaScript
    - Test WebSocket connections
    - Extract WS endpoints from various sources
    """
    
    def __init__(self, config: WebSocketDiscoveryConfig = None):
        self.config = config or WebSocketDiscoveryConfig()
        self.discovered_endpoints: List[Endpoint] = []
    
    def discover_from_html(self, html: str, base_url: str) -> List[str]:
        """Discover WebSocket endpoints from HTML"""
        ws_endpoints = []
        
        # Look for WebSocket URLs in HTML
        ws_patterns = [
            r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            r'ws://[^\s"\'<>]+',
            r'wss://[^\s"\'<>]+',
        ]
        
        for pattern in ws_patterns:
            matches = re.findall(pattern, html)
            ws_endpoints.extend(matches)
        
        return list(set(ws_endpoints))
    
    def discover_from_js(self, js_content: str, base_url: str) -> List[str]:
        """Discover WebSocket endpoints from JavaScript"""
        ws_endpoints = []
        
        # Look for WebSocket initialization
        ws_patterns = [
            r'new\s+WebSocket\s*\(\s*["\']([^"\']+)["\']',
            r'["\']ws://[^"\']+["\']',
            r'["\']wss://[^"\']+["\']',
            r'websocket\.connect\s*\(\s*["\']([^"\']+)["\']',
            r'socket\.io\s*\(\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in ws_patterns:
            matches = re.findall(pattern, js_content, re.IGNORECASE)
            ws_endpoints.extend(matches)
        
        # Normalize and dedupe
        normalized = []
        for ep in set(ws_endpoints):
            if ep.startswith('//'):
                ep = 'wss:' + ep
            elif ep.startswith('/'):
                parsed = urlparse(base_url)
                ep = f"{parsed.scheme}://{parsed.netloc}{ep}"
            normalized.append(ep)
        
        return normalized
    
    def test_websocket(self, ws_url: str) -> Dict[str, Any]:
        """
        Test WebSocket connection
        
        Args:
            ws_url: WebSocket URL to test
            
        Returns:
            Dictionary with test results
        """
        result = {
            "url": ws_url,
            "connected": False,
            "error": None,
            "supported_protocols": []
        }
        
        if not self.config.test_endpoints:
            return result
        
        if not WEBSOCKET_AVAILABLE:
            result["error"] = "WebSocket support not installed"
            return result
        
        try:
            ws = websocket.create_connection(
                ws_url,
                timeout=self.config.timeout,
                sockopt=((websocket._ssl.SOCK_SSL, 6),) if ws_url.startswith('wss') else None
            )
            result["connected"] = True
            ws.close()
        except Exception as e:
            result["error"] = str(e)
        
        return result
    
    async def discover(self, target: Target) -> List[Endpoint]:
        """
        Discover WebSocket endpoints for target
        
        Args:
            target: Target to scan
            
        Returns:
            List of discovered WebSocket endpoints
        """
        if not self.config.enabled:
            return []
        
        base_url = str(target.url)
        parsed = urlparse(base_url)
        
        # Try common WebSocket paths
        common_ws_paths = [
            "/ws",
            "/websocket",
            "/socket.io",
            "/socket.io/",
            "/ws/v1",
            f"/api/v1/ws",
        ]
        
        ws_urls = []
        for path in common_ws_paths:
            ws_url = f"ws://{parsed.netloc}{path}"
            ws_urls.append(ws_url)
            
            if parsed.scheme == "https":
                ws_urls.append(ws_url.replace("ws://", "wss://"))
        
        # Test each WebSocket endpoint
        for ws_url in ws_urls:
            test_result = self.test_websocket(ws_url)
            
            if test_result["connected"] or test_result.get("error") is None:
                endpoint = Endpoint(
                    target_id=target.id,
                    url=ws_url,
                    method="WS",
                    path=urlparse(ws_url).path,
                    source="websocket_discovery",
                    is_api=True
                )
                self.discovered_endpoints.append(endpoint)
        
        return self.discovered_endpoints


class PassiveScanner:
    """
    Passive scanning mode - no active requests to target
    
    Features:
    - Scan via proxy (ZAP, Burp)
    - Analyze captured traffic
    - No direct interaction with target
    """
    
    def __init__(self):
        self.findings: List[Any] = []
        self.requests: List[Dict[str, Any]] = []
    
    async def scan_via_proxy(self, target_url: str,
                           proxy_type: str = "zap",
                           proxy_url: str = "http://localhost:8080") -> Dict[str, Any]:
        """
        Scan target via proxy
        
        Args:
            target_url: Target URL to scan
            proxy_type: Proxy type (zap, burp)
            proxy_url: Proxy URL
            
        Returns:
            Scan results
        """
        # This would connect to ZAP/Burp API to scan
        # For now, return a placeholder
        return {
            "status": "configured",
            "proxy": proxy_url,
            "target": target_url,
            "proxy_type": proxy_type
        }
    
    def analyze_captured_request(self, request: Dict, response: Dict) -> Optional[Dict]:
        """
        Analyze captured HTTP request/response
        
        Args:
            request: HTTP request data
            response: HTTP response data
            
        Returns:
            Finding if vulnerability detected
        """
        findings = []
        
        # Check security headers
        missing_headers = self._check_security_headers(response.get("headers", {}))
        if missing_headers:
            findings.append({
                "type": "missing_security_headers",
                "headers": missing_headers
            })
        
        # Check for sensitive data exposure
        sensitive = self._check_sensitive_data(response.get("body", ""))
        if sensitive:
            findings.append({
                "type": "sensitive_data_exposure",
                "data": sensitive
            })
        
        return findings if findings else None
    
    def _check_security_headers(self, headers: Dict) -> List[str]:
        """Check for missing security headers"""
        required_headers = [
            "Strict-Transport-Security",
            "Content-Security-Policy",
            "X-Content-Type-Options",
            "X-Frame-Options",
            "X-XSS-Protection"
        ]
        
        header_names = {h.lower() for h in headers.keys()}
        missing = [h for h in required_headers if h.lower() not in header_names]
        
        return missing
    
    def _check_sensitive_data(self, body: str) -> List[str]:
        """Check for sensitive data in response"""
        sensitive_patterns = {
            "email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            "ssn": r'\b\d{3}-\d{2}-\d{4}\b',
            "api_key": r'["\']?[aA][pP][iI]_[kK][eE][yY]["\']?\s*[:=]\s*["\'][^"\']+["\']',
            "password": r'["\']?[pP][aA][sS][sS][wW][oO][rR][dD]["\']?\s*[:=]\s*["\'][^"\']+["\']',
            "token": r'["\']?[tT][oO][kK][eE][nN]["\']?\s*[:=]\s*["\'][^"\']+["\']',
        }
        
        found = []
        for data_type, pattern in sensitive_patterns.items():
            if re.search(pattern, body, re.IGNORECASE):
                found.append(data_type)
        
        return found


class JavaScriptParser:
    """
    Enhanced JavaScript parsing for SPAs and modern web apps
    
    Features:
    - Extract API endpoints from JS files
    - Find SPA routes
    - Parse AJAX calls
    """
    
    def __init__(self, config: JavaScriptParserConfig = None):
        self.config = config or JavaScriptParserConfig()
        self.discovered_apis: List[str] = []
        self.discovered_routes: List[str] = []
    
    def parse_html_scripts(self, html: str, base_url: str) -> Dict[str, List[str]]:
        """
        Parse JavaScript from HTML
        
        Args:
            html: HTML content
            base_url: Base URL for resolving relative URLs
            
        Returns:
            Dictionary with discovered APIs and routes
        """
        results = {
            "endpoints": [],
            "routes": [],
            "api_calls": []
        }
        
        soup = BeautifulSoup(html, 'html.parser')
        
        # Get all script sources
        for script in soup.find_all('script', src=True):
            src = script['src']
            full_url = urljoin(base_url, src)
            
            # Fetch and parse the script
            try:
                response = requests.get(full_url, timeout=10)
                if response.status_code == 200:
                    js_content = response.text
                    
                    # Extract endpoints
                    results["endpoints"].extend(
                        self._extract_api_endpoints(js_content, base_url)
                    )
                    
                    # Extract routes
                    results["routes"].extend(
                        self._extract_spa_routes(js_content)
                    )
                    
                    # Extract API calls
                    results["api_calls"].extend(
                        self._extract_api_calls(js_content)
                    )
            except Exception:
                continue
        
        return results
    
    def _extract_api_endpoints(self, js_content: str, base_url: str) -> List[str]:
        """Extract API endpoints from JavaScript"""
        endpoints = []
        
        # Patterns for API endpoints in JS
        patterns = [
            r'["\']\/api\/[^"\']+["\']',
            r'["\']https?:\/\/[^\/]*\/api\/[^"\']+["\']',
            r'["\']graphql["\']',
            r'baseURL\s*[=:]\s*["\']([^"\']+)["\']',
            r'axios\.get\s*\(\s*["\']([^"\']+)["\']',
            r'fetch\s*\(\s*["\']([^"\']+)["\']',
            r'\.ajax\s*\(\s*{[^}]*url:\s*["\']([^"\']+)["\']',
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            endpoints.extend(matches)
        
        # Normalize URLs
        normalized = []
        parsed_base = urlparse(base_url)
        
        for ep in set(endpoints):
            if ep.startswith('http'):
                normalized.append(ep)
            elif ep.startswith('/'):
                normalized.append(f"{parsed_base.scheme}://{parsed_base.netloc}{ep}")
        
        return normalized
    
    def _extract_spa_routes(self, js_content: str) -> List[str]:
        """Extract SPA routes from JavaScript"""
        routes = []
        
        # Common SPA routing patterns
        patterns = [
            r'router\.add\s*\(\s*["\']([^"\']+)["\']',
            r'router\.push\s*\(\s*["\']([^"\']+)["\']',
            r'path:\s*["\']([^"\']+)["\']',
            r'Route\s*\(\s*{[^}]*path:\s*["\']([^"\']+)["\']',
            r'["\']\/[a-zA-Z0-9_-]+["\']',  # Simple path patterns
        ]
        
        for pattern in patterns:
            matches = re.findall(pattern, js_content)
            routes.extend(matches)
        
        return list(set(routes))
    
    def _extract_api_calls(self, js_content: str) -> List[Dict[str, str]]:
        """Extract API calls with methods"""
        calls = []
        
        # Patterns for API calls
        patterns = {
            "get": r'\.(get|getJSON)\s*\(\s*["\']([^"\']+)["\']',
            "post": r'\.post\s*\(\s*["\']([^"\']+)["\']',
            "put": r'\.put\s*\(\s*["\']([^"\']+)["\']',
            "delete": r'\.delete\s*\(\s*["\']([^"\']+)["\']',
            "patch": r'\.patch\s*\(\s*["\']([^"\']+)["\']',
        }
        
        for method, pattern in patterns.items():
            matches = re.findall(pattern, js_content)
            for match in matches:
                calls.append({
                    "method": method.upper(),
                    "endpoint": match if isinstance(match, str) else match[-1]
                })
        
        return calls


class APIVersionDetector:
    """
    Detect and analyze API versions
    
    Features:
    - Find versioned API endpoints
    - Compare version coverage
    - Track version usage
    """
    
    def __init__(self, config: APIVersionConfig = None):
        self.config = config or APIVersionConfig()
        self.discovered_versions: Dict[str, List[str]] = {}
    
    def detect_versions(self, endpoints: List[Endpoint]) -> Dict[str, Any]:
        """
        Detect API versions from endpoints
        
        Args:
            endpoints: List of discovered endpoints
            
        Returns:
            Version analysis
        """
        version_map: Dict[str, List[str]] = {}
        
        for endpoint in endpoints:
            url = endpoint.url
            
            for pattern in self.config.common_patterns:
                if pattern in url:
                    # Extract version
                    version = pattern.strip('/')
                    
                    if version not in version_map:
                        version_map[version] = []
                    
                    version_map[version].append(url)
        
        self.discovered_versions = version_map
        
        return {
            "versions": version_map,
            "version_count": len(version_map),
            "endpoints_per_version": {
                v: len(endpoints) for v, endpoints in version_map.items()
            }
        }
    
    def get_latest_version(self) -> Optional[str]:
        """Get the latest detected API version"""
        if not self.discovered_versions:
            return None
        
        # Sort versions by number
        versions = sorted(
            self.discovered_versions.keys(),
            key=lambda v: [int(x) if x.isdigit() else x for x in v.split('.')],
            reverse=True
        )
        
        return versions[0] if versions else None
    
    def compare_versions(self) -> Dict[str, Any]:
        """Compare different API versions"""
        if len(self.discovered_versions) < 2:
            return {"message": "Need at least 2 versions to compare"}
        
        comparison = {}
        versions = list(self.discovered_versions.keys())
        
        for i, v1 in enumerate(versions):
            for v2 in versions[i+1:]:
                key = f"{v1}_vs_{v2}"
                comparison[key] = {
                    v1: len(self.discovered_versions[v1]),
                    v2: len(self.discovered_versions[v2]),
                    "difference": abs(
                        len(self.discovered_versions[v1]) - 
                        len(self.discovered_versions[v2])
                    )
                }
        
        return comparison
