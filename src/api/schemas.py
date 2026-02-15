"""
VulnScope - API Schemas
Pydantic models for API request/response validation
"""

from pydantic import BaseModel, Field, HttpUrl
from typing import List, Optional, Dict, Any
from uuid import UUID
from datetime import datetime
from enum import Enum


# ============ Enums ============

class ScanStatus(str, Enum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# ============ Target Schemas ============

class TargetCreate(BaseModel):
    name: str = Field(..., description="Target name")
    url: HttpUrl = Field(..., description="Target URL")
    description: Optional[str] = Field(None, description="Target description")
    tags: List[str] = Field(default_factory=list, description="Target tags")
    auth_type: Optional[str] = Field(None, description="Authentication type")
    auth_config: Optional[Dict[str, Any]] = Field(None, description="Authentication configuration")


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    auth_type: Optional[str] = None
    auth_config: Optional[Dict[str, Any]] = None


class TargetResponse(BaseModel):
    id: UUID
    name: str
    url: str
    description: Optional[str]
    tags: List[str]
    auth_type: Optional[str]
    created_at: datetime
    updated_at: Optional[datetime] = None


# ============ Scan Schemas ============

class ScanCreate(BaseModel):
    target_id: UUID = Field(..., description="Target ID to scan")
    name: str = Field(..., description="Scan name")
    description: Optional[str] = Field(None, description="Scan description")
    scan_type: str = Field(default="full", description="Scan type: full, quick, stealth")
    
    # Discovery options
    enable_crawler: bool = Field(default=True, description="Enable web crawler")
    enable_openapi_import: bool = Field(default=True, description="Enable OpenAPI import")
    enable_graphql_import: bool = Field(default=True, description="Enable GraphQL import")
    
    # Scanner options
    enable_dast: bool = Field(default=True, description="Enable DAST scanner")
    enable_fuzzer: bool = Field(default=True, description="Enable API fuzzer")
    test_sql_injection: bool = Field(default=True)
    test_xss: bool = Field(default=True)
    test_ssrf: bool = Field(default=True)
    test_idor: bool = Field(default=True)
    test_auth_bypass: bool = Field(default=True)


class ScanResponse(BaseModel):
    id: UUID
    target_id: UUID
    name: str
    status: str
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScanStatusResponse(BaseModel):
    scan_id: UUID
    status: str
    progress: int = Field(ge=0, le=100)
    endpoints_discovered: int
    findings_count: int


# ============ Finding Schemas ============

class FindingResponse(BaseModel):
    id: UUID
    scan_id: UUID
    target_id: UUID
    title: str
    description: str
    severity: str
    vulnerability_type: str
    status: str
    cwe_id: Optional[str] = None
    cve_id: Optional[str] = None
    remediation: Optional[str] = None
    false_positive: bool = False
    verified: bool = False
    discovered_at: datetime


class FindingListResponse(BaseModel):
    total: int
    findings: List[FindingResponse]


# ============ Report Schemas ============

class ReportGenerateRequest(BaseModel):
    scan_id: UUID = Field(..., description="Scan ID to generate report for")
    format: str = Field(default="json", description="Report format: json, xml, html, sarif, csv")
    title: Optional[str] = Field(None, description="Report title")
    compliance_standards: List[str] = Field(default_factory=list, description="Compliance standards to include")


class ReportResponse(BaseModel):
    id: UUID
    scan_id: UUID
    format: str
    content: Optional[str] = None
    download_url: Optional[str] = None


# ============ Policy Schemas ============

class PolicyRuleInput(BaseModel):
    name: str
    description: str
    vulnerability_types: List[str] = Field(default_factory=list)
    severities: List[str] = Field(default_factory=list)
    cwe_ids: List[str] = Field(default_factory=list)
    action: str = "fail"
    message: str = ""


class PolicyCreate(BaseModel):
    name: str = Field(..., description="Policy name")
    description: str = Field(..., description="Policy description")
    version: str = Field(default="1.0")
    scope: str = Field(default="finding")
    rules: List[PolicyRuleInput] = Field(default_factory=list)
    compliance_standards: List[str] = Field(default_factory=list)


class PolicyResponse(BaseModel):
    id: UUID
    name: str
    description: str
    rules_count: int
    version: str = "1.0"
    created_at: Optional[datetime] = None


# ============ Compliance Schemas ============

class ComplianceRequest(BaseModel):
    scan_id: UUID = Field(..., description="Scan ID to check compliance for")
    standard: str = Field(..., description="Compliance standard: PCI-DSS, NIS2, SOC2")


class ComplianceResponse(BaseModel):
    standard: str
    compliant: bool
    score: float
    violations: List[Dict[str, Any]]
    requirements: Optional[List[Dict[str, Any]]] = None


# ============ Integration Schemas ============

class IntegrationConfig(BaseModel):
    type: str = Field(..., description="Integration type: github, gitlab, jenkins, jira, servicenow, splunk, elk")
    config: Dict[str, Any] = Field(..., description="Integration configuration")


class GitHubCheckRequest(BaseModel):
    scan_id: UUID
    owner: str
    repo: str
    branch: Optional[str] = "main"


class JiraTicketRequest(BaseModel):
    scan_id: UUID
    project_key: str
    create_individual_tickets: bool = False


class SIEMEventRequest(BaseModel):
    scan_id: UUID
    system: str = Field(..., description="SIEM system: splunk, elk")
    send_findings: bool = False
