"""
VulnScope - Advanced Network Security Detectors
Network scanning, port analysis, service discovery, and network configuration
"""

import re
import socket
import subprocess
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set, Tuple
from enum import Enum
import requests

from ..core.models import Endpoint, Finding, Severity, VulnerabilityType, Status


class PortState(str, Enum):
    """Port states"""
    OPEN = "OPEN"
    CLOSED = "CLOSED"
    FILTERED = "FILTERED"
    UNKNOWN = "UNKNOWN"


class ServiceType(str, Enum):
    """Common dangerous services"""
    HTTP = "HTTP"
    HTTPS = "HTTPS"
    SSH = "SSH"
    TELNET = "TELNET"
    FTP = "FTP"
    SMTP = "SMTP"
    POP3 = "POP3"
    IMAP = "IMAP"
    DNS = "DNS"
    LDAP = "LDAP"
    KERBEROS = "KERBEROS"
    MYSQL = "MYSQL"
    POSTGRES = "POSTGRES"
    MONGODB = "MONGODB"
    REDIS = "REDIS"
    MEMCACHED = "MEMCACHED"
    ELASTICSEARCH = "ELASTICSEARCH"
    KAFKA = "KAFKA"
    RABBIT_MQ = "RABBIT_MQ"
    DOCKER = "DOCKER"
    KUBERNETES = "KUBERNETES"
    NFS = "NFS"
    SMB = "SMB"


class Detector(ABC):
    """Base class for vulnerability detectors"""
    
    @property
    @abstractmethod
    def vulnerability_type(self) -> VulnerabilityType:
        pass
    
    @property
    @abstractmethod
    def severity(self) -> Severity:
        pass
    
    @abstractmethod
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        pass


class PortScannerDetector(Detector):
    """Detect open and unexpected ports"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.OPEN_PORT
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # Common dangerous services and their ports
    DANGEROUS_PORTS = {
        21: ServiceType.FTP,
        23: ServiceType.TELNET,
        25: ServiceType.SMTP,
        53: ServiceType.DNS,
        110: ServiceType.POP3,
        143: ServiceType.IMAP,
        389: ServiceType.LDAP,
        445: ServiceType.SMB,
        2049: ServiceType.NFS,
        3306: ServiceType.MYSQL,
        5432: ServiceType.POSTGRES,
        5984: ServiceType.ELASTICSEARCH,  # CouchDB
        6379: ServiceType.REDIS,
        7000: ServiceType.ELASTICSEARCH,
        9042: ServiceType.ELASTICSEARCH,  # Cassandra
        9200: ServiceType.ELASTICSEARCH,
        9300: ServiceType.ELASTICSEARCH,
        11211: ServiceType.MEMCACHED,
        27017: ServiceType.MONGODB,
        50070: ServiceType.HADOOP,
    }
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect open dangerous ports"""
        findings = []
        
        try:
            # Extract host from endpoint
            import urllib.parse
            parsed = urllib.parse.urlparse(endpoint.url)
            host = parsed.hostname
            
            if host:
                # Scan for open ports
                open_ports = self._scan_ports(host)
                
                for port, service_type in open_ports.items():
                    if port in self.DANGEROUS_PORTS:
                        service = self.DANGEROUS_PORTS[port]
                        severity = Severity.CRITICAL if service in [
                            ServiceType.TELNET, ServiceType.MYSQL, ServiceType.POSTGRES,
                            ServiceType.MONGODB, ServiceType.REDIS, ServiceType.ELASTICSEARCH
                        ] else Severity.HIGH
                        
                        finding = self._create_finding(
                            endpoint=endpoint,
                            title=f"Open Dangerous Port Detected - {service.value} ({port})",
                            description=f"Port {port} ({service.value}) is open and exposed to the network. "
                                       f"This service should be blocked or restricted to authorized networks only.",
                            evidence={
                                'host': host,
                                'port': port,
                                'service': service.value,
                                'status': PortState.OPEN.value,
                            },
                            severity=severity,
                        )
                        findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def _scan_ports(self, host: str, ports: Optional[List[int]] = None) -> Dict[int, str]:
        """Scan for open ports on a host"""
        if ports is None:
            ports = list(self.DANGEROUS_PORTS.keys()) + [80, 443, 8080, 8443, 3000, 5000, 8000]
        
        open_ports = {}
        
        for port in ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(1)
                result = sock.connect_ex((host, port))
                sock.close()
                
                if result == 0:
                    service = self.DANGEROUS_PORTS.get(port, "UNKNOWN")
                    open_ports[port] = service.value if isinstance(service, ServiceType) else str(service)
            except Exception:
                pass
        
        return open_ports
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any],
                       severity: Severity = None) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=severity or self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )


class ServiceDiscoveryDetector(Detector):
    """Detect exposed services and their information"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.INSECURE_NETWORK_CONFIG
    
    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect exposed service information"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            
            # Check for service version disclosure
            version_headers = [
                'Server',
                'X-Powered-By',
                'X-AspNet-Version',
                'X-Runtime-Version',
                'X-Framework-Version',
            ]
            
            for header in version_headers:
                if header in response.headers:
                    value = response.headers[header]
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title=f"Service Version Disclosure - {header}",
                        description=f"Service identifies itself as '{value}'. "
                                   f"This information can be used for targeted attacks.",
                        evidence={
                            'url': endpoint.url,
                            'header': header,
                            'value': value,
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


class NetworkSegmentationDetector(Detector):
    """Detect network access control issues"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.INSECURE_NETWORK_CONFIG
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # Internal network ranges to check
    INTERNAL_NETWORKS = [
        (0x0A000000, 0x0AFFFFFF),  # 10.0.0.0/8
        (0xAC100000, 0xAC1FFFFF),  # 172.16.0.0/12
        (0xC0A80000, 0xC0A8FFFF),  # 192.168.0.0/16
        (0x7F000000, 0x7FFFFFFF),  # 127.0.0.0/8 (localhost)
    ]
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect network segmentation issues"""
        findings = []
        
        # Check for internal network access
        if self._is_internal_network(endpoint.url):
            finding = self._create_finding(
                endpoint=endpoint,
                title="Direct Access to Internal Network Resource",
                description="Endpoint directly exposes internal network resource. "
                           "Network segmentation should prevent external access.",
                evidence={'url': endpoint.url}
            )
            findings.append(finding)
        
        # Check for cross-network communication
        findings.extend(self._check_cross_network_exposure(endpoint, session))
        
        return findings
    
    def _is_internal_network(self, url: str) -> bool:
        """Check if URL points to internal network"""
        try:
            import urllib.parse
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname
            
            if host:
                try:
                    ip = socket.inet_aton(host)
                    ip_int = int.from_bytes(ip, byteorder='big')
                    
                    for start, end in self.INTERNAL_NETWORKS:
                        if start <= ip_int <= end:
                            return True
                except socket.error:
                    pass
        except Exception:
            pass
        
        return False
    
    def _check_cross_network_exposure(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check for cross-network communication exposure"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            
            # Check for exposed internal IPs in response
            ip_pattern = r'\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b'
            if re.search(ip_pattern, response.text):
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Internal IP Address Disclosure",
                    description="Internal network addresses are leaked in response. "
                              "This allows network reconnaissance attacks.",
                    evidence={'url': endpoint.url}
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


class FirewallDetectionDetector(Detector):
    """Detect WAF/Firewall configurations"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.INSECURE_NETWORK_CONFIG
    
    @property
    def severity(self) -> Severity:
        return Severity.MEDIUM
    
    # WAF signatures to detect
    WAF_SIGNATURES = {
        'cloudflare': ['cf-ray', 'cf-request-id', 'server.*cloudflare'],
        'akamai': ['akamai-x-cache-on', 'x-akamai-transformed'],
        'cloudfront': ['x-amz-cloudfront-id'],
        'aws-waf': ['x-amzn-waf'],
        'azure-waf': ['azure-application-gateway'],
        'imperva': ['x-cdn', 'server.*imperva'],
        'f5': ['x-cache-key', 'server.*f5'],
        'palo-alto': ['x-content-type-options'],
    }
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect firewall/WAF presence and configuration"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            headers = response.headers
            
            # Identify WAF
            detected_waf = self._detect_waf(headers)
            
            if detected_waf:
                finding = self._create_finding(
                    endpoint=endpoint,
                    title=f"Firewall/WAF Detected - {detected_waf}",
                    description=f"The endpoint is protected by {detected_waf}. "
                              f"Adjust testing strategy accordingly.",
                    evidence={
                        'url': endpoint.url,
                        'waf': detected_waf,
                    },
                    severity=Severity.INFO,
                )
                findings.append(finding)
            else:
                # No WAF detected - potential risk
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="No Web Application Firewall Detected",
                    description="No WAF/Firewall detected protecting the application. "
                              "Consider implementing WAF for attack prevention.",
                    evidence={'url': endpoint.url},
                    severity=Severity.MEDIUM,
                )
                findings.append(finding)
        
        except Exception:
            pass
        
        return findings
    
    def _detect_waf(self, headers: Dict[str, str]) -> Optional[str]:
        """Detect WAF from response headers"""
        headers_lower = {k.lower(): v.lower() for k, v in headers.items()}
        
        for waf_name, signatures in self.WAF_SIGNATURES.items():
            for signature in signatures:
                for header_name, header_value in headers_lower.items():
                    if re.search(signature, f"{header_name}:{header_value}"):
                        return waf_name.upper()
        
        return None
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any],
                       severity: Severity = None) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=severity or self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )
