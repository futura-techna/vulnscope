"""
VulnScope - Cloud & Cryptographic Security Detectors
Detectors for Cloud Misconfigurations, IAM, SSL/TLS, and Cryptographic Hygiene
"""

import re
import ssl
import socket
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from urllib.parse import urlparse

from ..core.models import Endpoint, Finding, Severity, VulnerabilityType, Status


class CloudSecurityDetector(Detector):
    """Cloud Security & Misconfiguration detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.CLOUD_MISCONFIGURATION
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # Cloud metadata endpoints
    METADATA_ENDPOINTS = [
        "169.254.169.254",
        "metadata.google.internal",
        "metadata.googleusercontent.com",
        "azure.metadata.internal",
        "169.254.169.254/latest/meta-data/",
    ]
    
    # Common insecure storage patterns
    STORAGE_PATTERNS = [
        r's3\.amazonaws\.com/[a-zA-Z0-9\-]+',
        r'blob\.core\.windows\.net/[a-zA-Z0-9\-]+',
        r'storage\.googleapis\.com/[a-zA-Z0-9\-]+',
    ]
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect cloud misconfigurations"""
        findings = []
        
        # Check for SSRF-like patterns that could access cloud metadata
        url_lower = endpoint.url.lower()
        
        for metadata_ip in self.METADATA_ENDPOINTS:
            if metadata_ip in url_lower or metadata_ip.replace('.', '') in url_lower.replace('.', ''):
                finding = self._create_finding(
                    endpoint=endpoint,
                    title=f"Potential Cloud Metadata Access - {metadata_ip}",
                    description=f"The application may allow access to cloud metadata service at {metadata_ip}. "
                               f"This could expose sensitive cloud provider information.",
                    evidence={
                        'url': endpoint.url,
                        'metadata_endpoint': metadata_ip,
                        'method': endpoint.method,
                    }
                )
                findings.append(finding)
        
        # Check for overly permissive CORS (cloud-related)
        if endpoint.headers:
            cors_origin = endpoint.headers.get('Access-Control-Allow-Origin', '')
            if cors_origin == '*' or cors_origin == 'null':
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Overly Permissive CORS Configuration",
                    description=f"CORS is configured with wildcard origin '{cors_origin}', allowing any domain to access resources.",
                    evidence={
                        'url': endpoint.url,
                        'cors_origin': cors_origin,
                    }
                )
                findings.append(finding)
        
        return findings
    
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


class IAMDetector(Detector):
    """Identity & Access Management detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.OVERLY_PERMISSIVE_IAM
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect IAM misconfigurations"""
        findings = []
        
        # Check for missing authentication on sensitive endpoints
        sensitive_patterns = [
            r'/admin',
            r'/api/v[0-9]+/admin',
            r'/users',
            r'/api/users',
            r'/api/keys',
            r'/api/credentials',
            r'/api/permissions',
            r'/api/roles',
            r'/api/access',
        ]
        
        url_path = endpoint.path.lower()
        
        for pattern in sensitive_patterns:
            if re.search(pattern, url_path):
                # Check if endpoint doesn't require auth
                if not endpoint.is_authenticated and endpoint.method == 'GET':
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title=f"Unauthenticated Access to Sensitive Endpoint - {pattern}",
                        description=f"Sensitive endpoint '{pattern}' does not appear to require authentication. "
                                   f"This could allow unauthorized access to sensitive data.",
                        evidence={
                            'url': endpoint.url,
                            'method': endpoint.method,
                            'pattern_matched': pattern,
                            'authenticated': endpoint.is_authenticated,
                        }
                    )
                    findings.append(finding)
        
        # Check for missing authorization checks
        if endpoint.method in ['PUT', 'DELETE', 'PATCH']:
            # Look for IDOR-prone patterns
            id_patterns = [r'/[0-9]+$', r'/[a-f0-9\-]{36}', r'/[a-zA-Z0-9]+/edit']
            for pattern in id_patterns:
                if re.search(pattern, endpoint.path):
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title="Potential Missing Authorization Check",
                        description=f"Endpoint uses object ID in path but no explicit authorization check was detected. "
                                   f"Ensure proper authorization is enforced for all operations.",
                        evidence={
                            'url': endpoint.url,
                            'method': endpoint.method,
                            'path': endpoint.path,
                        }
                    )
                    findings.append(finding)
                    break
        
        return findings
    
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


class CryptographicHygieneDetector(Detector):
    """Cryptographic Hygiene detector for SSL/TLS and weak cryptography"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.WEAK_SSL_TLS
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # Weak cipher suites
    WEAK_CIPHERS = [
        'NULL',
        'aNULL',
        'eNULL',
        'EXPORT',
        'DES',
        'RC4',
        'MD5',
        'SHA1',
        '3DES',
        'IDEA',
    ]
    
    # Minimum safe TLS version
    MIN_TLS_VERSION = 1.2
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect weak cryptographic configurations"""
        findings = []
        
        # Parse URL to get host and port
        parsed = urlparse(endpoint.url)
        if parsed.scheme in ['https', 'http']:
            host = parsed.hostname
            port = parsed.port or (443 if parsed.scheme == 'https' else 80)
            
            if host and port:
                # Check SSL/TLS configuration
                tls_findings = self._check_ssl_configuration(host, port)
                findings.extend(tls_findings)
        
        # Check response headers for security headers
        try:
            response = session.get(endpoint.url, timeout=10)
            
            # Check for missing security headers
            security_headers_findings = self._check_security_headers(endpoint, response.headers)
            findings.extend(security_headers_findings)
            
            # Check for weak cookies (missing secure/httponly flags)
            cookie_findings = self._check_cookie_security(endpoint, response.headers)
            findings.extend(cookie_findings)
            
        except Exception:
            pass
        
        return findings
    
    def _check_ssl_configuration(self, host: str, port: int) -> List[Finding]:
        """Check SSL/TLS configuration of a server"""
        findings = []
        
        try:
            # Create SSL context
            context = ssl.create_default_context()
            context.check_hostname = True
            context.verify_mode = ssl.CERT_REQUIRED
            
            # Try to connect with decreasing security
            with socket.create_connection((host, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    version = ssock.version()
                    
                    # Check TLS version
                    if version in ['TLSv1', 'TLSv1.1', 'SSLv3', 'SSLv2']:
                        finding = Finding(
                            scan_id="",
                            target_id="",
                            endpoint_id="",
                            vulnerability_type=VulnerabilityType.WEAK_SSL_TLS,
                            severity=Severity.CRITICAL,
                            title=f"Deprecated TLS/SSL Version - {version}",
                            description=f"The server supports deprecated TLS/SSL version '{version}'. "
                                       f"This version has known vulnerabilities and should be disabled.",
                            evidence={
                                'host': host,
                                'port': port,
                                'tls_version': version,
                            },
                            status=Status.PENDING,
                        )
                        findings.append(finding)
                    
                    # Check cipher suite
                    cipher = ssock.cipher()
                    if cipher:
                        cipher_name = cipher[0].upper()
                        for weak_cipher in self.WEAK_CIPHERS:
                            if weak_cipher in cipher_name:
                                finding = Finding(
                                    scan_id="",
                                    target_id="",
                                    endpoint_id="",
                                    vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
                                    severity=Severity.HIGH,
                                    title=f"Weak Cipher Suite - {cipher_name}",
                                    description=f"The server uses weak cipher suite '{cipher_name}'. "
                                               f"This cipher has known vulnerabilities.",
                                    evidence={
                                        'host': host,
                                        'port': port,
                                        'cipher': cipher_name,
                                    },
                                    status=Status.PENDING,
                                )
                                findings.append(finding)
                                break
        
        except ssl.SSLError as e:
            # SSL error could indicate weak configuration
            finding = Finding(
                scan_id="",
                target_id="",
                endpoint_id="",
                vulnerability_type=VulnerabilityType.WEAK_SSL_TLS,
                severity=Severity.MEDIUM,
                title="SSL Configuration Issue Detected",
                description=f"SSL connection error detected: {str(e)}. "
                           f"This may indicate misconfigured SSL/TLS settings.",
                evidence={
                    'host': host,
                    'port': port,
                    'error': str(e),
                },
                status=Status.PENDING,
            )
            findings.append(finding)
        
        except Exception:
            pass
        
        return findings
    
    def _check_security_headers(self, endpoint: Endpoint, headers: Dict) -> List[Finding]:
        """Check for missing security headers"""
        findings = []
        
        # Required security headers
        required_headers = {
            'Strict-Transport-Security': 'HSTS',
            'Content-Security-Policy': 'CSP',
            'X-Content-Type-Options': 'X-Content-Type-Options',
            'X-Frame-Options': 'X-Frame-Options',
            'X-XSS-Protection': 'X-XSS-Protection',
        }
        
        for header, name in required_headers.items():
            if header not in headers:
                finding = Finding(
                    scan_id="",
                    target_id=endpoint.target_id,
                    endpoint_id=str(endpoint.id),
                    vulnerability_type=VulnerabilityType.WEAK_SSL_TLS,
                    severity=Severity.MEDIUM,
                    title=f"Missing Security Header - {name}",
                    description=f"The response is missing the '{header}' security header. "
                               f"This header helps protect against various attacks.",
                    evidence={
                        'url': endpoint.url,
                        'missing_header': header,
                    },
                    status=Status.PENDING,
                )
                findings.append(finding)
        
        return findings
    
    def _check_cookie_security(self, endpoint: Endpoint, headers: Dict) -> List[Finding]:
        """Check for insecure cookie configuration"""
        findings = []
        
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie:
            # Check if cookies are missing security flags
            if 'Secure' not in set_cookie:
                finding = Finding(
                    scan_id="",
                    target_id=endpoint.target_id,
                    endpoint_id=str(endpoint.id),
                    vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
                    severity=Severity.MEDIUM,
                    title="Insecure Cookie - Missing Secure Flag",
                    description=f"Cookie is set without the 'Secure' flag, allowing transmission over HTTP.",
                    evidence={
                        'url': endpoint.url,
                        'set_cookie': set_cookie[:200],
                    },
                    status=Status.PENDING,
                )
                findings.append(finding)
            
            if 'HttpOnly' not in set_cookie:
                finding = Finding(
                    scan_id="",
                    target_id=endpoint.target_id,
                    endpoint_id=str(endpoint.id),
                    vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
                    severity=Severity.MEDIUM,
                    title="Insecure Cookie - Missing HttpOnly Flag",
                    description=f"Cookie is set without the 'HttpOnly' flag, allowing JavaScript access.",
                    evidence={
                        'url': endpoint.url,
                        'set_cookie': set_cookie[:200],
                    },
                    status=Status.PENDING,
                )
                findings.append(finding)
            
            # Check for missing SameSite
            if 'SameSite' not in set_cookie:
                finding = Finding(
                    scan_id="",
                    target_id=endpoint.target_id,
                    endpoint_id=str(endpoint.id),
                    vulnerability_type=VulnerabilityType.WEAK_CRYPTOGRAPHY,
                    severity=Severity.LOW,
                    title="Insecure Cookie - Missing SameSite Attribute",
                    description=f"Cookie is set without the 'SameSite' attribute. "
                               f"This could lead to CSRF vulnerabilities.",
                    evidence={
                        'url': endpoint.url,
                        'set_cookie': set_cookie[:200],
                    },
                    status=Status.PENDING,
                )
                findings.append(finding)
        
        return findings


class ZeroTrustDetector(Detector):
    """Zero Trust Architecture detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.MISSING_ZERO_TRUST
    
    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect missing Zero Trust principles"""
        findings = []
        
        # Check for implicit trust patterns
        url = endpoint.url.lower()
        
        # Check for internal network access without authentication
        internal_patterns = [
            r'10\.\d+\.\d+\.\d+',
            r'192\.168\.\d+\.\d+',
            r'172\.(1[6-9]|2\d|3[01])\.\d+\.\d+',
            r'localhost',
            r'127\.0\.0\.1',
            r'::1',
        ]
        
        for pattern in internal_patterns:
            if re.search(pattern, url):
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Internal Network Access Without Explicit Auth",
                    description=f"Endpoint accesses internal network resource ({pattern}) "
                               f"without explicit authentication. Zero Trust requires verifying every request.",
                    evidence={
                        'url': endpoint.url,
                        'internal_pattern': pattern,
                    }
                )
                findings.append(finding)
                break
        
        # Check for missing micro-segmentation indicators
        if endpoint.path.count('/') > 3:
            # Deep paths might indicate poor micro-segmentation
            finding = self._create_finding(
                endpoint=endpoint,
                title="Complex URL Structure - Possible Poor Micro-segmentation",
                description=f"Deep URL path structure detected. Consider implementing proper "
                           f"micro-segmentation for better Zero Trust implementation.",
                evidence={
                    'url': endpoint.url,
                    'path_depth': endpoint.path.count('/'),
                }
            )
            findings.append(finding)
        
        return findings
    
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


class NetworkSecurityDetector(Detector):
    """Endpoint & Network Security detector"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.INSECURE_NETWORK_CONFIG
    
    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM
    
    # Insecure protocols
    INSECURE_PROTOCOLS = [
        'http://',
        'ftp://',
        'telnet://',
        'rtsp://',
    ]
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect network security issues"""
        findings = []
        
        url = endpoint.url.lower()
        
        # Check for insecure protocols
        for protocol in self.INSECURE_PROTOCOLS:
            if url.startswith(protocol):
                protocol_name = protocol.replace('://', '').upper()
                finding = self._create_finding(
                    endpoint=endpoint,
                    title=f"Insecure Protocol Usage - {protocol_name}",
                    description=f"The application uses '{protocol_name}' which transmits data in plaintext. "
                               f"Use HTTPS or other encrypted protocols instead.",
                    evidence={
                        'url': endpoint.url,
                        'protocol': protocol_name,
                    }
                )
                findings.append(finding)
                break
        
        # Check for missing rate limiting headers
        try:
            response = session.get(endpoint.url, timeout=10)
            
            # Check rate limiting
            rate_limit_headers = ['X-RateLimit-Limit', 'X-RateLimit-Remaining', 'Retry-After']
            has_rate_limit = any(h in response.headers for h in rate_limit_headers)
            
            if not has_rate_limit and endpoint.method in ['POST', 'PUT', 'DELETE']:
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Missing Rate Limiting",
                    description=f"No rate limiting headers detected on state-changing endpoint. "
                               f"This could indicate vulnerability to brute-force or DoS attacks.",
                    evidence={
                        'url': endpoint.url,
                        'method': endpoint.method,
                    }
                )
                findings.append(finding)
        
        except Exception:
            pass
        
        return findings
    
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
