"""
VulnScope - API Fuzzer
Auth-aware API fuzzing with schema validation
"""

import asyncio
import time
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, field
from datetime import datetime
import requests
import json

from ..core.models import Endpoint, Finding, Target, Scan, Severity, VulnerabilityType, Status
from ..core.exceptions import ScanError
from ..config.settings import FuzzerConfig
from ..scanner.payloads import PayloadGenerator


@dataclass
class FuzzingResult:
    """Result of fuzzing operation"""
    findings: List[Finding] = field(default_factory=list)
    requests_sent: int = 0
    unique_responses: int = 0
    errors: List[str] = field(default_factory=list)
    duration_seconds: float = 0.0
    start_time: datetime = field(default_factory=datetime.utcnow)
    end_time: Optional[datetime] = None


@dataclass
class FuzzTest:
    """Individual fuzz test"""
    endpoint: Endpoint
    method: str
    url: str
    params: Dict[str, Any] = field(default_factory=dict)
    headers: Dict[str, str] = field(default_factory=dict)
    body: Optional[str] = None
    payload: str = ""
    category: str = ""


class Fuzzer:
    """
    API Fuzzer with authentication awareness
    
    Features:
    - Auth-aware fuzzing (OAuth/OIDC support)
    - Schema-based testing
    - Rate limit detection
    - Automatic retries
    - Multiple vulnerability checks
    """
    
    def __init__(self, config: Optional[FuzzerConfig] = None):
        self.config = config or FuzzerConfig()
        self.session = requests.Session()
        self.payload_generator = PayloadGenerator(self.config.wordlists_path)
        
        # State
        self.target: Optional[Target] = None
        self.scan: Optional[Scan] = None
        self.findings: List[Finding] = []
        self.responses_cache: Dict[str, Any] = {}
        
        # Rate limiting
        self.request_times: List[float] = []
        self.rate_limit_detected: bool = False
        self.rate_limit_remaining: int = 0
    
    def _check_rate_limit(self):
        """Check and enforce rate limiting"""
        now = time.time()
        
        # Remove old requests
        self.request_times = [t for t in self.request_times if now - t < 1.0]
        
        if len(self.request_times) >= self.config.rate_limit_per_second:
            sleep_time = 1.0 - (now - self.request_times[0])
            if sleep_time > 0:
                time.sleep(sleep_time)
        
        self.request_times.append(time.time())
    
    def _detect_rate_limit(self, response: requests.Response) -> bool:
        """Detect rate limiting from response headers"""
        # Check common rate limit headers
        rate_limit_headers = [
            'X-RateLimit-Limit',
            'X-RateLimit-Remaining',
            'X-RateLimit-Reset',
            'Retry-After',
            'X-Rate-Limit-Limit',
            'X-Rate-Limit-Remaining',
        ]
        
        for header in rate_limit_headers:
            if header in response.headers:
                self.rate_limit_detected = True
                if 'Remaining' in header:
                    self.rate_limit_remaining = int(response.headers[header])
                return True
        
        # Check for 429 status
        if response.status_code == 429:
            self.rate_limit_detected = True
            return True
        
        return False
    
    def _retry_request(self, method: str, url: str, **kwargs) -> Optional[requests.Response]:
        """Make request with automatic retries"""
        max_retries = self.config.max_retries
        
        for attempt in range(max_retries):
            try:
                self._check_rate_limit()
                response = self.session.request(method, url, **kwargs)
                
                # Check for rate limiting
                if self._detect_rate_limit(response):
                    if self.rate_limit_remaining == 0:
                        # Wait for rate limit to reset
                        reset_time = response.headers.get('X-RateLimit-Reset')
                        if reset_time:
                            wait_time = int(reset_time) - time.time()
                            if wait_time > 0:
                                time.sleep(wait_time)
                
                # Success
                if response.status_code < 500:
                    return response
                    
            except requests.RequestException as e:
                if attempt == max_retries - 1:
                    raise
        
        return None
    
    def _fuzz_endpoint(self, endpoint: Endpoint) -> List[Finding]:
        """Fuzz a single endpoint"""
        findings = []
        
        # Generate test cases
        test_cases = self._generate_test_cases(endpoint)
        
        for test in test_cases:
            try:
                # Make request
                response = self._retry_request(
                    method=test.method,
                    url=test.url,
                    params=test.params if test.method == 'GET' else None,
                    headers=test.headers,
                    data=test.body if test.method in ['POST', 'PUT', 'PATCH'] else None,
                    timeout=30
                )
                
                if not response:
                    continue
                
                # Analyze response
                response_key = self._get_response_key(response)
                
                if response_key not in self.responses_cache:
                    self.responses_cache[response_key] = 0
                self.responses_cache[response_key] += 1
                
                # Check for vulnerabilities
                test_findings = self._analyze_response(endpoint, test, response)
                findings.extend(test_findings)
                
            except Exception as e:
                continue
        
        return findings
    
    def _generate_test_cases(self, endpoint: Endpoint) -> List[FuzzTest]:
        """Generate fuzzing test cases"""
        test_cases = []
        
        # Get payloads for each category
        categories = []
        
        if self.config.test_sql_injection:
            categories.append('sql')
        if self.config.test_xss:
            categories.append('xss')
        if self.config.test_ssrf:
            categories.append('ssrf')
        if self.config.test_idor:
            categories.append('idor')
        
        # Generate test cases for each parameter
        for param in endpoint.parameters:
            param_name = param.get('name', '')
            param_type = param.get('type', 'string')
            param_in = param.get('in', 'query')
            
            for category in categories:
                payloads = self.payload_generator.get_payloads_for_parameter(param_name, param_type)
                
                for payload in payloads[:10]:  # Limit payloads
                    test = FuzzTest(
                        endpoint=endpoint,
                        method=endpoint.method,
                        url=endpoint.url,
                        params={param_name: payload},
                        headers=endpoint.headers.copy(),
                        body=endpoint.body,
                        payload=payload,
                        category=category,
                    )
                    
                    # Add content-type specific body
                    if endpoint.has_body and endpoint.content_type:
                        if endpoint.content_type == 'application/json':
                            test.body = json.dumps({param_name: payload})
                        else:
                            test.body = f"{param_name}={payload}"
                    
                    test_cases.append(test)
        
        # Add default test cases if no parameters
        if not endpoint.parameters:
            for category in categories:
                payloads = self.payload_generator.get_payloads(category)
                
                test = FuzzTest(
                    endpoint=endpoint,
                    method=endpoint.method,
                    url=endpoint.url,
                    payload=payloads[0] if payloads else "",
                    category=category,
                )
                test_cases.append(test)
        
        return test_cases
    
    def _analyze_response(self, endpoint: Endpoint, test: FuzzTest, 
                         response: requests.Response) -> List[Finding]:
        """Analyze response for vulnerabilities"""
        findings = []
        
        # Check based on payload category
        if test.category == 'sql':
            if self._detect_sql_injection(response):
                findings.append(self._create_finding(
                    endpoint=endpoint,
                    vuln_type=VulnerabilityType.SQL_INJECTION,
                    severity=Severity.CRITICAL,
                    title=f"SQL Injection via {test.payload[:20]}",
                    description="SQL injection vulnerability detected",
                    evidence={'payload': test.payload, 'response': response.text[:500]}
                ))
        
        elif test.category == 'xss':
            if self._detect_xss(response, test.payload):
                findings.append(self._create_finding(
                    endpoint=endpoint,
                    vuln_type=VulnerabilityType.XSS,
                    severity=Severity.HIGH,
                    title=f"Cross-Site Scripting (XSS)",
                    description="XSS vulnerability detected",
                    evidence={'payload': test.payload, 'response': response.text[:500]}
                ))
        
        elif test.category == 'ssrf':
            if self._detect_ssrf(response):
                findings.append(self._create_finding(
                    endpoint=endpoint,
                    vuln_type=VulnerabilityType.SSRF,
                    severity=Severity.HIGH,
                    title="Server-Side Request Forgery (SSRF)",
                    description="SSRF vulnerability detected",
                    evidence={'payload': test.payload, 'response': response.text[:500]}
                ))
        
        # Check for sensitive data exposure
        if self._detect_sensitive_data(response):
            findings.append(self._create_finding(
                endpoint=endpoint,
                vuln_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
                severity=Severity.HIGH,
                title="Sensitive Data Exposure",
                description="Application exposes sensitive data",
                evidence={'response': response.text[:500]}
            ))
        
        return findings
    
    def _detect_sql_injection(self, response: requests.Response) -> bool:
        """Detect SQL injection from response"""
        sql_errors = [
            'sql syntax', 'mysql', 'postgresql', 'ora-', 'sqlite',
            'microsoft sql', 'odbc', 'fatal error'
        ]
        
        text = response.text.lower()
        return any(err in text for err in sql_errors)
    
    def _detect_xss(self, response: requests.Response, payload: str) -> bool:
        """Detect XSS from response"""
        # Check if payload is reflected without encoding
        if payload in response.text:
            return True
        
        # Check for XSS indicators
        xss_indicators = ['<script', 'onerror=', 'onload=', 'javascript:']
        return any(indicator in response.text.lower() for indicator in xss_indicators)
    
    def _detect_ssrf(self, response: requests.Response) -> bool:
        """Detect SSRF from response"""
        # Check for internal network indicators
        indicators = ['localhost', '127.0.0.1', 'metadata', 'internal']
        return any(indicator in response.text.lower() for indicator in indicators)
    
    def _detect_sensitive_data(self, response: requests.Response) -> bool:
        """Detect sensitive data in response"""
        sensitive_patterns = [
            r'"password":\s*"[^"]+"',
            r'"ssn":\s*"[^"]+"',
            r'"credit_card":\s*"[^"]+"',
            r'-----BEGIN (RSA |EC )?PRIVATE KEY-----',
            r'-----BEGIN CERTIFICATE-----',
        ]
        
        import re
        text = response.text.lower()
        return any(re.search(pattern, text) for pattern in sensitive_patterns)
    
    def _get_response_key(self, response: requests.Response) -> str:
        """Generate unique key for response caching"""
        return f"{response.status_code}:{len(response.text)}"
    
    def _create_finding(self, endpoint: Endpoint, vuln_type: VulnerabilityType,
                       severity: Severity, title: str, description: str,
                       evidence: Dict[str, Any]) -> Finding:
        """Create a finding"""
        return Finding(
            scan_id=str(self.scan.id) if self.scan else "",
            target_id=str(self.target.id) if self.target else "",
            endpoint_id=str(endpoint.id),
            vulnerability_type=vuln_type,
            severity=severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )
    
    async def fuzz_endpoints(self, endpoints: List[Endpoint],
                            target: Target, scan: Scan) -> FuzzingResult:
        """Fuzz multiple endpoints"""
        self.target = target
        self.scan = scan
        self.findings = []
        self.responses_cache = {}
        
        start_time = datetime.utcnow()
        result = FuzzingResult()
        
        # Apply authentication
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
        
        # Fuzz each endpoint
        for endpoint in endpoints:
            endpoint_findings = self._fuzz_endpoint(endpoint)
            self.findings.extend(endpoint_findings)
            result.requests_sent += len(endpoint.parameters) * 10
        
        # Update result
        result.findings = self.findings
        result.unique_responses = len(self.responses_cache)
        result.end_time = datetime.utcnow()
        result.duration_seconds = (result.end_time - start_time).total_seconds()
        
        return result
    
    def fuzz_endpoints_sync(self, endpoints: List[Endpoint],
                           target: Target, scan: Scan) -> FuzzingResult:
        """Synchronous wrapper for fuzz_endpoints"""
        return asyncio.run(self.fuzz_endpoints(endpoints, target, scan))
