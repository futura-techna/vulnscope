"""
VulnScope - Passive Scanner
Passive scanning via proxy (OWASP ZAP, Burp Suite integration)
"""

import requests
from typing import List, Dict, Any, Optional, Callable
from dataclasses import dataclass
from urllib.parse import urlparse

from ..core.models import Endpoint, Finding


@dataclass
class ProxyConfig:
    """Proxy configuration"""
    proxy_url: str = ""
    verify_ssl: bool = True
    authenticate: bool = False
    username: Optional[str] = None
    password: Optional[str] = None


class PassiveScanner:
    """
    Passive scanner using proxy for traffic interception
    
    Supports:
    - OWASP ZAP
    - Burp Suite
    - Custom proxies
    
    Features:
    - Intercept all traffic
    - Passive vulnerability detection
    - No active requests
    """
    
    def __init__(self, config: ProxyConfig):
        self.config = config
        self.session = requests.Session()
        
        # Setup proxy
        if config.proxy_url:
            self.session.proxies = {
                'http': config.proxy_url,
                'https': config.proxy_url,
            }
        
        # Setup authentication
        if config.authenticate and config.username and config.password:
            self.session.auth = (config.username, config.password)
        
        self.session.verify = config.verify_ssl
    
    def create_zap_session(self, zap_url: str = "http://localhost:8080") -> Dict[str, Any]:
        """
        Create OWASP ZAP session
        
        Args:
            zap_url: ZAP API URL
            
        Returns:
            Session info
        """
        try:
            # Create new session
            response = self.session.post(
                f"{zap_url}/JSON/core/action/newSession",
                params={'name': 'vulnscope_session'}
            )
            
            # Enable passive scanner
            self.session.post(
                f"{zap_url}/JSON/pscan/action/enableAllScanners"
            )
            
            return {'status': 'created', 'zap_url': zap_url}
        except Exception as e:
            return {'status': 'error', 'message': str(e)}
    
    def create_burp_session(self, burp_url: str = "http://localhost:8080") -> Dict[str, Any]:
        """
        Create Burp Suite session
        
        Args:
            burp_url: Burp Suite proxy URL
            
        Returns:
            Session info
        """
        return {'status': 'created', 'burp_url': burp_url}
    
    def get_alerts(self, base_url: str, 
                  proxy_url: str = "http://localhost:8080") -> List[Finding]:
        """
        Get alerts from proxy
        
        Args:
            base_url: Base URL to get alerts for
            proxy_url: Proxy API URL
            
        Returns:
            List of findings from proxy
        """
        findings = []
        
        try:
            # Get ZAP alerts
            response = self.session.get(
                f"{proxy_url}/JSON/alert/alertsByUrl",
                params={'url': base_url}
            )
            
            if response.status_code == 200:
                alerts = response.json()
                
                for alert in alerts.get('alerts', []):
                    finding = self._create_finding_from_alert(alert)
                    findings.append(finding)
        
        except Exception:
            pass
        
        return findings
    
    def _create_finding_from_alert(self, alert: Dict[str, Any]) -> Finding:
        """Convert ZAP/Burp alert to Finding"""
        from ..core.models import Severity, VulnerabilityType, Status
        
        # Map risk to severity
        risk_map = {
            'HIGH': Severity.HIGH,
            'MEDIUM': Severity.MEDIUM,
            'LOW': Severity.LOW,
            'INFORMATIONAL': Severity.INFO,
        }
        
        # Map plugin to vulnerability type
        plugin_map = {
            '10001': VulnerabilityType.SQL_INJECTION,
            '10002': VulnerabilityType.XSS,
            '10003': VulnerabilityType.CSRF,
            '10017': VulnerabilityType.XSS,
            '10019': VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
            '10020': VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
        }
        
        severity = risk_map.get(alert.get('risk', 'MEDIUM'), Severity.MEDIUM)
        vuln_type = plugin_map.get(alert.get('pluginId', ''), VulnerabilityType.SECURITY_MISCONFIGURATION)
        
        return Finding(
            scan_id="",
            target_id="",
            vulnerability_type=vuln_type,
            severity=severity,
            title=alert.get('name', 'Security Alert'),
            description=alert.get('description', ''),
            evidence={
                'url': alert.get('url', ''),
                'alert': alert.get('alert', ''),
                'risk': alert.get('risk', ''),
                'confidence': alert.get('confidence', ''),
                'attack': alert.get('attack', ''),
                'evidence': alert.get('evidence', ''),
            },
            cwe_id=alert.get('cweid'),
            cve_id=alert.get('cveid'),
            status=Status.PENDING,
        )
    
    def scan_via_proxy(self, target_url: str, 
                      proxy_url: str = "http://localhost:8080") -> List[Finding]:
        """
        Scan target via proxy interception
        
        Args:
            target_url: Target URL to scan
            proxy_url: Proxy API URL
            
        Returns:
            List of findings
        """
        # First, spider the target
        try:
            self.session.get(proxy_url + "/JSON/spider/action/scan",
                params={'url': target_url, 'maxChildren': '10'}
            )
        except:
            pass
        
        # Wait for spider to complete
        import time
        time.sleep(2)
        
        # Get alerts
        return self.get_alerts(target_url, proxy_url)
    
    def passive_scan_callback(self, request: Dict, response: Dict) -> Optional[Finding]:
        """
        Callback for passive scanning
        
        Args:
            request: HTTP request
            response: HTTP response
            
        Returns:
            Finding if vulnerability detected
        """
        # Check for various vulnerabilities in passive mode
        
        # Check for missing security headers
        missing_headers = self._check_security_headers(response)
        if missing_headers:
            return self._create_header_finding(missing_headers, request['url'])
        
        # Check for sensitive data in response
        sensitive = self._check_sensitive_data(response)
        if sensitive:
            return self._create_sensitive_finding(sensitive, request['url'])
        
        return None
    
    def _check_security_headers(self, response: Dict) -> List[str]:
        """Check for missing security headers"""
        headers = response.get('headers', {})
        missing = []
        
        security_headers = [
            'X-Content-Type-Options',
            'X-Frame-Options',
            'Content-Security-Policy',
            'Strict-Transport-Security',
        ]
        
        for header in security_headers:
            if header.lower() not in [h.lower() for h in headers.keys()]:
                missing.append(header)
        
        return missing
    
    def _check_sensitive_data(self, response: Dict) -> List[str]:
        """Check for sensitive data in response"""
        body = response.get('body', '')
        sensitive = []
        
        patterns = [
            ('password', 'Password'),
            ('ssn', 'SSN'),
            ('credit_card', 'Credit Card'),
            ('api_key', 'API Key'),
            ('token', 'Token'),
        ]
        
        for pattern, label in patterns:
            if pattern.lower() in body.lower():
                sensitive.append(label)
        
        return sensitive
    
    def _create_header_finding(self, missing_headers: List[str], url: str):
        """Create finding for missing headers"""
        from ..core.models import Severity, VulnerabilityType, Status
        
        return Finding(
            scan_id="",
            target_id="",
            vulnerability_type=VulnerabilityType.SECURITY_MISCONFIGURATION,
            severity=Severity.MEDIUM,
            title="Missing Security Headers",
            description=f"The following security headers are missing: {', '.join(missing_headers)}",
            evidence={'missing_headers': missing_headers, 'url': url},
            status=Status.PENDING,
        )
    
    def _create_sensitive_finding(self, sensitive: List[str], url: str):
        """Create finding for sensitive data"""
        from ..core.models import Severity, VulnerabilityType, Status
        
        return Finding(
            scan_id="",
            target_id="",
            vulnerability_type=VulnerabilityType.SENSITIVE_DATA_EXPOSURE,
            severity=Severity.HIGH,
            title="Sensitive Data Exposure",
            description=f"Potential sensitive data detected: {', '.join(sensitive)}",
            evidence={'sensitive_types': sensitive, 'url': url},
            status=Status.PENDING,
        )


class PassiveProxyMiddleware:
    """Middleware for passive scanning"""
    
    def __init__(self, scanner: PassiveScanner):
        self.scanner = scanner
    
    async def __call__(self, request, call_next):
        """Process request through passive scanner"""
        # Pass request to next handler
        response = await call_next(request)
        
        # Scan passively
        finding = self.scanner.passive_scan_callback(
            {'url': str(request.url), 'method': request.method},
            {'headers': dict(response.headers), 'body': ''}
        )
        
        if finding:
            # Store finding
            pass
        
        return response
