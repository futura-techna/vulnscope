"""
VulnScope - Core Data Models
Comprehensive data models for vulnerability management
"""

from datetime import datetime
from typing import Optional, List, Dict, Any
from enum import Enum
from pydantic import BaseModel, Field, HttpUrl
from uuid import UUID, uuid4


class Severity(str, Enum):
    """Vulnerability severity levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class Status(str, Enum):
    """Scan and finding status"""
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class VulnerabilityType(str, Enum):
    """Types of vulnerabilities"""
    SQL_INJECTION = "SQL_INJECTION"
    XSS = "XSS"
    SSRF = "SSRF"
    IDOR = "IDOR"
    AUTH_BYPASS = "AUTH_BYPASS"
    CSRF = "CSRF"
    XXE = "XXE"
    PATH_TRAVERSAL = "PATH_TRAVERSAL"
    COMMAND_INJECTION = "COMMAND_INJECTION"
    INSECURE_DESERIALIZATION = "INSECURE_DESERIALIZATION"
    SENSITIVE_DATA_EXPOSURE = "SENSITIVE_DATA_EXPOSURE"
    BROKEN_AUTH = "BROKEN_AUTH"
    SECURITY_MISCONFIGURATION = "SECURITY_MISCONFIGURATION"
    XML_EXTERNAL_ENTITIES = "XML_EXTERNAL_ENTITIES"
    BUFFER_OVERFLOW = "BUFFER_OVERFLOW"
    RATE_LIMITING = "RATE_LIMITING"
    CORS = "CORS"
    INFO_LEAK = "INFO_LEAK"
    # Cloud Security
    CLOUD_MISCONFIGURATION = "CLOUD_MISCONFIGURATION"
    INSECURE_STORAGE = "INSECURE_STORAGE"
    OVERLY_PERMISSIVE_IAM = "OVERLY_PERMISSIVE_IAM"
    # Cryptographic Hygiene
    WEAK_CRYPTOGRAPHY = "WEAK_CRYPTOGRAPHY"
    WEAK_SSL_TLS = "WEAK_SSL_TLS"
    INSECURE_CIPHER = "INSECURE_CIPHER"
    # Software Supply Chain
    VULNERABLE_DEPENDENCY = "VULNERABLE_DEPENDENCY"
    SUPPLY_CHAIN_COMPROMISE = "SUPPLY_CHAIN_COMPROMISE"
    # Zero Trust
    MISSING_ZERO_TRUST = "MISSING_ZERO_TRUST"
    # Network Security
    INSECURE_NETWORK_CONFIG = "INSECURE_NETWORK_CONFIG"
    OPEN_PORT = "OPEN_PORT"
    INSECURE_PROTOCOL = "INSECURE_PROTOCOL"


class Target(BaseModel):
    """Target application/system to scan"""
    id: UUID = Field(default_factory=uuid4)
    name: str
    url: HttpUrl
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    updated_at: datetime = Field(default_factory=datetime.utcnow)
    
    # Authentication
    auth_type: Optional[str] = None  # basic, bearer, oauth, api_key
    auth_config: Dict[str, Any] = Field(default_factory=dict)
    
    # Scope
    allowed_endpoints: List[str] = Field(default_factory=list)
    blocked_endpoints: List[str] = Field(default_factory=list)


class Endpoint(BaseModel):
    """API endpoint or web page discovered"""
    id: UUID = Field(default_factory=uuid4)
    target_id: Optional[UUID] = None
    url: str
    method: str = "GET"  # GET, POST, PUT, DELETE, PATCH, etc.
    path: str
    parameters: List[Dict[str, Any]] = Field(default_factory=list)
    headers: Dict[str, str] = Field(default_factory=dict)
    body: Optional[str] = None
    content_type: Optional[str] = None
    
    # Metadata
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    source: str = "crawler"  # crawler, openapi, graphql, manual
    is_authenticated: bool = False
    
    # Analysis
    has_params: bool = False
    has_body: bool = False
    is_api: bool = False


class Finding(BaseModel):
    """Security finding/vulnerability"""
    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    target_id: UUID
    endpoint_id: Optional[UUID] = None
    
    # Vulnerability details
    vulnerability_type: VulnerabilityType = VulnerabilityType.XSS
    severity: Severity = Severity.MEDIUM
    title: str
    description: Optional[str] = None
    
    # Technical details
    url: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Dict[str, Any] = Field(default_factory=dict)
    
    # Remediation
    remediation: Optional[str] = None
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    owasp_category: Optional[str] = None
    cvss_score: Optional[float] = None
    
    # Status
    status: Status = Field(default=Status.PENDING)
    false_positive: bool = False
    verified: bool = False
    
    # Timestamps
    discovered_at: datetime = Field(default_factory=datetime.utcnow)
    created_at: datetime = Field(default_factory=datetime.utcnow)
    verified_at: Optional[datetime] = None
    remediated_at: Optional[datetime] = None


class Vulnerability(BaseModel):
    """Detailed vulnerability information (alias for Finding)"""
    id: UUID = Field(default_factory=uuid4)
    title: str
    description: str
    severity: Severity
    vulnerability_type: VulnerabilityType
    
    # Technical details
    url: str
    method: str
    payload: Optional[str] = None
    response_snippet: Optional[str] = None
    
    # Classification
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    owasp_category: Optional[str] = None
    
    # Impact
    impact: Optional[str] = None
    remediation: Optional[str] = None
    
    # Evidence
    evidence: Dict[str, Any] = Field(default_factory=dict)
    screenshots: List[str] = Field(default_factory=list)
    requests: List[Dict[str, Any]] = Field(default_factory=list)
    
    # Status
    status: Status = Field(default=Status.PENDING)
    false_positive: bool = False
    verified: bool = False


class Scan(BaseModel):
    """Security scan configuration and execution"""
    id: UUID = Field(default_factory=uuid4)
    target_id: UUID
    name: str
    description: Optional[str] = None
    
    # Scan configuration
    scan_type: str = "full"  # full, quick, stealth, auth_aware
    scanner_mode: str = "active"  # passive, active, fuzzing
    
    # Discovery options
    enable_crawler: bool = True
    enable_openapi_import: bool = True
    enable_graphql_import: bool = True
    
    # Scanner options
    enable_dast: bool = True
    enable_fuzzer: bool = True
    test_sql_injection: bool = True
    test_xss: bool = True
    test_ssrf: bool = True
    test_idor: bool = True
    test_auth_bypass: bool = True
    
    # Rate limiting
    max_requests_per_second: int = 100
    max_concurrent_requests: int = 10
    
    # Execution
    status: Status = Field(default=Status.PENDING)
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None
    
    # Progress tracking
    progress: int = 0
    error_message: Optional[str] = None
    
    # Results
    total_endpoints: int = 0
    total_findings: int = 0
    endpoints_discovered: int = 0
    findings_count: int = 0
    findings_by_severity: Dict[Severity, int] = Field(default_factory=dict)
    
    # Metadata
    created_at: datetime = Field(default_factory=datetime.utcnow)
    created_by: Optional[str] = None
    tags: List[str] = Field(default_factory=list)


class ScanResult(BaseModel):
    """Complete scan result with all findings"""
    scan: Scan
    target: Target
    endpoints: List[Endpoint] = Field(default_factory=list)
    findings: List[Finding] = Field(default_factory=list)
    summary: Dict[str, Any] = Field(default_factory=dict)
    errors: List[str] = Field(default_factory=list)


class Report(BaseModel):
    """Formatted report for export"""
    id: UUID = Field(default_factory=uuid4)
    scan_id: UUID
    target_id: UUID
    
    # Report metadata
    format: str = "json"  # json, xml, html, sarif, csv
    title: str
    generated_at: datetime = Field(default_factory=datetime.utcnow)
    generated_by: str = "VulnScope"
    
    # Compliance
    compliance_standards: List[str] = Field(default_factory=list)  # PCI-DSS, NIS2, SOC2
    
    # Content
    executive_summary: str = ""
    technical_summary: str = ""
    findings: List[Finding] = Field(default_factory=list)
    recommendations: List[str] = Field(default_factory=list)
    
    # Statistics
    statistics: Dict[str, Any] = Field(default_factory=dict)
