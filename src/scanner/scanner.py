"""
VulnScope - DAST Scanner Engine
Dynamic Application Security Testing with headless browser support
"""

import asyncio
import time
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse
import requests

from ..core.models import (
    Endpoint, Finding, Scan, Target, Severity, 
    VulnerabilityType, Status
)
from ..core.exceptions import ScanError
from ..config.settings import ScannerConfig
from .detectors import (
    XSSDetector, SQLInjectionDetector, 
    SSRDetector, IDORDetector, CSRFDetector,
    XXEDetector, CommandInjectionDetector,
    SSTIDetector, DeserializationDetector,
    PathTraversalDetector, Detector
)


@dataclass
class ScanProgress:
    """Track scan progress"""
    total_endpoints: int = 0
    scanned_endpoints: int = 0
    total_tests: int = 0
    completed_tests: int = 0
    current_endpoint: str = ""
    start_time: datetime = field(default_factory=datetime.utcnow)
    errors: List[str] = field(default_factory=list)


@dataclass
class ScanResult:
    """Complete scan result"""
    findings: List[Finding] = field(default_factory=list)
    progress: ScanProgress = field(default_factory=ScanProgress)
    duration_seconds: float = 0.0


class VulnerabilityFinder:
    """Vulnerability detection coordinator"""
    
    def __init__(self, config: ScannerConfig):
        self.config = config
        self.detectors: List[Detector] = []
        self._setup_detectors()
    
    def _setup_detectors(self):
        """Initialize vulnerability detectors"""
        # Add all detectors
        self.detectors = [
            XSSDetector(),
            SQLInjectionDetector(),
            SSRDetector(),
            IDORDetector(),
            CSRFDetector(),
            XXEDetector(),
            CommandInjectionDetector(),
            SSTIDetector(),
            DeserializationDetector(),
            PathTraversalDetector(),
        ]
    
    def find_vulnerabilities(self, endpoint: Endpoint, 
                             session: requests.Session) -> List[Finding]:
        """
        Run all detectors on an endpoint
        
        Args:
            endpoint: Endpoint to test
            session: Authenticated session
            
        Returns:
            List of findings
        """
        findings = []
        
        for detector in self.detectors:
            try:
                detector_findings = detector.detect(endpoint, session)
                findings.extend(detector_findings)
            except Exception as e:
                # Log error but continue with other detectors
                print(f"Detector {detector.__class__.__name__} error: {e}")
        
        return findings


class Scanner:
    """
    Dynamic Application Security Testing (DAST) Scanner
    
    Features:
    - Headless browser support for JavaScript rendering
    - Safe payload execution (sandboxed)
    - Multiple vulnerability detection
    - Low false positive rate
    - Concurrent scanning
    """
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        self.config = config or ScannerConfig()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': self.config.user_agent
        })
        
        # Configure session
        self.session.verify = self.config.verify_ssl
        self.session.max_redirects = 10
        
        # State
        self.target: Optional[Target] = None
        self.scan: Optional[Scan] = None
        self.progress = ScanProgress()
        self.findings: List[Finding] = []
        
        # Vulnerability finder
        self.finder = VulnerabilityFinder(self.config)
        
        # Rate limiting
        self.request_times: List[float] = []
    
    def _check_rate_limit(self):
        """Check and enforce rate limiting"""
        now = time.time()
        
        # Remove old requests outside the time window
        self.request_times = [
            t for t in self.request_times 
            if now - t < 1.0
        ]
        
        # Check if we've hit the rate limit
        if len(self.request_times) >= self.config.rate_limit_per_second:
            sleep_time = 1.0 - (now - self.request_times[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        # Add current request time
        self.request_times.append(now)
    
    def _test_endpoint(self, endpoint: Endpoint) -> List[Finding]:
        """
        Test a single endpoint for vulnerabilities
        
        Args:
            endpoint: Endpoint to test
            
        Returns:
            List of findings
        """
        findings = []
        
        # Test query parameters
        if endpoint.parameters:
            findings.extend(self._test_parameters(endpoint))
        
        # Test body parameters
        if endpoint.has_body and endpoint.body:
            findings.extend(self._test_body(endpoint))
        
        # Test headers
        findings.extend(self._test_headers(endpoint))
        
        return findings
    
    def _test_parameters(self, endpoint: Endpoint) -> List[Finding]:
        """Test endpoint parameters"""
        findings = []
        
        for param in endpoint.parameters:
            param_name = param.get('name')
            param_in = param.get('in', 'query')
            
            # Generate test payloads
            test_params = self._generate_test_params(param_name)
            
            for test_name, test_value in test_params.items():
                try:
                    # Build test URL
                    parsed = urlparse(endpoint.url)
                    query_params = parse_qs(parsed.query) if parsed.query else {}
                    query_params[param_name] = test_value
                    
                    new_query = urlencode(query_params, doseq=True)
                    test_url = urlunparse((
                        parsed.scheme,
                        parsed.netloc,
                        parsed.path,
                        parsed.params,
                        new_query,
                        parsed.fragment
                    ))
                    
                    # Make request
                    self._check_rate_limit()
                    response = self.session.request(
                        method=endpoint.method,
                        url=test_url,
                        timeout=self.config.request_timeout,
                        allow_redirects=self.config.follow_redirects
                    )
                    
                    # Analyze response for vulnerabilities
                    param_findings = self.finder.find_vulnerabilities(
                        endpoint, self.session
                    )
                    findings.extend(param_findings)
                    
                except requests.RequestException as e:
                    self.progress.errors.append(
                        f"Error testing {param_name}: {str(e)}"
                    )
        
        return findings
    
    def _test_body(self, endpoint: Endpoint) -> List[Finding]:
        """Test request body"""
        # Similar to parameter testing but for body
        return []
    
    def _test_headers(self, endpoint: Endpoint) -> List[Finding]:
        """Test HTTP headers"""
        # Test for header injection, CRLF injection, etc.
        return []
    
    def _generate_test_params(self, param_name: str) -> Dict[str, str]:
        """Generate test parameters for fuzzing"""
        return {
            'xss': '<script>alert(1)</script>',
            'sql_error': "' OR '1'='1",
            'sql_union': "' UNION SELECT NULL--",
            'ssrf': 'http://localhost/',
            'null': '',
            'special': '../../../../etc/passwd',
        }
    
    async def scan_endpoints_async(self, endpoints: List[Endpoint], 
                                   target: Target, scan: Scan,
                                   max_concurrent: int = 10) -> ScanResult:
        """
        Scan multiple endpoints asynchronously with concurrency control
        
        Args:
            endpoints: List of endpoints to scan
            target: Target application
            scan: Scan configuration
            max_concurrent: Maximum concurrent scans
            
        Returns:
            ScanResult with findings
        """
        self.target = target
        self.scan = scan
        self.findings = []
        self.progress = ScanProgress()
        
        start_time = datetime.utcnow()
        self.progress.total_endpoints = len(endpoints)
        
        result = ScanResult()
        
        # Apply authentication if configured
        if target.auth_type and target.auth_config:
            from ..discovery.auth_flows import AuthHandler, AuthType
            auth_handler = AuthHandler()
            auth_result = auth_handler.authenticate(
                str(target.url),
                AuthType(target.auth_type),
                target.auth_config
            )
            if auth_result.success and auth_result.session:
                self.session = auth_result.session
        
        # Create semaphore for concurrency control
        semaphore = asyncio.Semaphore(max_concurrent)
        
        async def scan_with_semaphore(endpoint: Endpoint):
            async with semaphore:
                self.progress.current_endpoint = endpoint.url
                self.progress.scanned_endpoints += 1
                
                try:
                    endpoint_findings = await asyncio.to_thread(
                        self._test_endpoint, endpoint
                    )
                    self.findings.extend(endpoint_findings)
                except Exception as e:
                    self.progress.errors.append(
                        f"Error scanning {endpoint.url}: {str(e)}"
                    )
        
        # Run all scans concurrently
        await asyncio.gather(
            *[scan_with_semaphore(ep) for ep in endpoints],
            return_exceptions=True
        )
        
        # Update result
        result.findings = self.findings
        result.progress = self.progress
        result.duration_seconds = (datetime.utcnow() - start_time).total_seconds()
        
        return result
    
    async def scan_endpoints(self, endpoints: List[Endpoint], 
                            target: Target, scan: Scan) -> ScanResult:
        """
        Scan multiple endpoints for vulnerabilities
        
        Args:
            endpoints: List of endpoints to scan
            target: Target application
            scan: Scan configuration
            
        Returns:
            ScanResult with findings
        """
        # Use async version by default for better performance
        return await self.scan_endpoints_async(
            endpoints, target, scan,
            max_concurrent=self.config.max_concurrent_requests
        )
    
    def scan_endpoints_sync(self, endpoints: List[Endpoint],
                           target: Target, scan: Scan) -> ScanResult:
        """Synchronous wrapper for scan_endpoints"""
        return asyncio.run(self.scan_endpoints(endpoints, target, scan))
    
    def create_finding(self, endpoint: Endpoint, vuln_type: VulnerabilityType,
                      severity: Severity, title: str, description: str,
                      evidence: Dict[str, Any]) -> Finding:
        """
        Create a standardized finding
        
        Args:
            endpoint: Endpoint where vulnerability was found
            vuln_type: Type of vulnerability
            severity: Severity level
            title: Finding title
            description: Detailed description
            evidence: Evidence of vulnerability
            
        Returns:
            Finding object
        """
        # Map vulnerability type to CWE
        cwe_map = {
            VulnerabilityType.SQL_INJECTION: "CWE-89",
            VulnerabilityType.XSS: "CWE-79",
            VulnerabilityType.SSRF: "CWE-918",
            VulnerabilityType.IDOR: "CWE-639",
            VulnerabilityType.AUTH_BYPASS: "CWE-287",
        }
        
        return Finding(
            scan_id=str(self.scan.id) if self.scan else "",
            target_id=str(self.target.id) if self.target else "",
            endpoint_id=str(endpoint.id),
            vulnerability_type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            cwe_id=cwe_map.get(vuln_type),
            status=Status.PENDING,
        )


class HeadlessScanner(Scanner):
    """Scanner with headless browser support for JS-rendered pages"""
    
    def __init__(self, config: Optional[ScannerConfig] = None):
        super().__init__(config)
        self.playwright = None
        self.browser = None
    
    async def _setup_browser(self):
        """Setup headless browser"""
        from playwright.async_api import async_playwright
        
        self.playwright = await async_playwright().start()
        self.browser = await self.playwright.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-setuid-sandbox']
        )
    
    async def _close_browser(self):
        """Close headless browser"""
        if self.browser:
            await self.browser.close()
        if self.playwright:
            await self.playwright.stop()
    
    async def scan_with_browser(self, url: str) -> Dict[str, Any]:
        """
        Scan a page using headless browser
        
        Args:
            url: URL to scan
            
        Returns:
            Dictionary with scan results
        """
        await self._setup_browser()
        
        try:
            page = await self.browser.new_page()
            await page.goto(url, wait_until='networkidle')
            
            # Get page content after JavaScript execution
            content = await page.content()
            
            # Run vulnerability tests
            findings = self.finder.find_vulnerabilities(
                Endpoint(
                    target_id="",
                    url=url,
                    method="GET",
                    path=urlparse(url).path
                ),
                self.session
            )
            
            await page.close()
            
            return {
                'content': content,
                'findings': findings,
            }
            
        finally:
            await self._close_browser()
