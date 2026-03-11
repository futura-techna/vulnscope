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
    PENDING = "pending"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class Severity(str, Enum):
    CRITICAL = "Critical"
    HIGH = "High"
    MEDIUM = "Medium"
    LOW = "Low"
    INFO = "Info"


# ============ Target Schemas ============

class TargetCreate(BaseModel):
    name: str = Field(..., description="Target name")
    url: str = Field(..., description="Target URL")
    description: Optional[str] = Field(None, description="Target description")
    tags: Optional[List[str]] = Field(default=None, description="Target tags")
    auth_type: Optional[str] = Field(None, description="Authentication type")
    auth_config: Optional[Dict[str, Any]] = Field(None, description="Authentication configuration")


class TargetUpdate(BaseModel):
    name: Optional[str] = None
    url: Optional[str] = None
    description: Optional[str] = None
    tags: Optional[List[str]] = None
    auth_type: Optional[str] = None
    auth_config: Optional[Dict[str, Any]] = None


class TargetResponse(BaseModel):
    id: UUID
    name: str
    url: str
    description: Optional[str] = None
    tags: List[str] = Field(default_factory=list)
    auth_type: Optional[str] = None
    created_at: datetime
    updated_at: Optional[datetime] = None


# ============ Scan Schemas ============

class ScanCreate(BaseModel):
    target_id: str = Field(..., description="Target ID to scan")
    name: str = Field(..., description="Scan name")
    description: Optional[str] = Field(None, description="Scan description")
    scan_type: Optional[str] = Field(default="full", description="Scan type: full, quick, stealth, api, auth")
    
    # Discovery options
    enable_crawler: Optional[bool] = Field(default=True, description="Enable web crawler")
    enable_openapi_import: Optional[bool] = Field(default=False, description="Enable OpenAPI import")
    enable_graphql_import: Optional[bool] = Field(default=False, description="Enable GraphQL import")
    
    # Scanner options
    enable_dast: Optional[bool] = Field(default=True, description="Enable DAST scanner")
    enable_fuzzer: Optional[bool] = Field(default=False, description="Enable API fuzzer")
    
    # Additional options
    max_concurrent: Optional[int] = Field(default=10, description="Max concurrent requests")
    timeout: Optional[int] = Field(default=30, description="Request timeout in seconds")
    recursive_depth: Optional[int] = Field(default=3, description="Recursive scan depth")


class ScanResponse(BaseModel):
    id: UUID
    target_id: UUID
    name: str
    description: Optional[str] = None
    status: str
    scan_type: Optional[str] = None
    progress: Optional[int] = 0
    endpoints_discovered: Optional[int] = 0
    findings_count: Optional[int] = 0
    created_at: datetime
    started_at: Optional[datetime] = None
    completed_at: Optional[datetime] = None


class ScanStatusResponse(BaseModel):
    scan_id: UUID
    status: str
    progress: int = Field(ge=0, le=100, default=0)
    endpoints_discovered: int = 0
    findings_count: int = 0


# ============ Finding Schemas ============

class FindingResponse(BaseModel):
    id: UUID
    scan_id: UUID
    target_id: UUID
    title: str
    description: Optional[str] = None
    severity: str
    vuln_type: str = Field(alias="vulnerability_type", default="Unknown")
    url: Optional[str] = None
    method: Optional[str] = None
    parameter: Optional[str] = None
    payload: Optional[str] = None
    evidence: Optional[str] = None
    status: str = "Open"
    cvss_score: Optional[float] = None
    cwe_id: Optional[str] = None
    owasp_category: Optional[str] = None
    created_at: datetime
    
    class Config:
        populate_by_name = True


class FindingListResponse(BaseModel):
    total: int
    findings: List[FindingResponse]


# ============ Report Schemas ============

class ReportGenerateRequest(BaseModel):
    scan_id: str = Field(..., description="Scan ID to generate report for")
    name: Optional[str] = Field(None, description="Report name")
    format: str = Field(default="json", description="Report format: json, xml, html, sarif, csv, pdf")
    include_evidence: Optional[bool] = Field(default=True, description="Include evidence in report")
    compliance_standards: Optional[List[str]] = Field(default=None, description="Compliance standards to include")


class ReportResponse(BaseModel):
    id: UUID
    scan_id: UUID
    name: Optional[str] = None
    format: str
    content: Optional[str] = None
    download_url: Optional[str] = None
    created_at: Optional[datetime] = None


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
    rules: Optional[List[PolicyRuleInput]] = Field(default=None)
    compliance_standards: Optional[List[str]] = Field(default=None)


class PolicyResponse(BaseModel):
    id: UUID
    name: str
    description: str
    rules_count: int = 0
    version: str = "1.0"
    created_at: Optional[datetime] = None


# ============ Compliance Schemas ============

class ComplianceRequest(BaseModel):
    scan_id: Optional[str] = Field(None, description="Scan ID to check compliance for")
    standard: str = Field(..., description="Compliance standard: PCI-DSS, NIS2, SOC2, HIPAA, ISO27001")


class ComplianceResponse(BaseModel):
    standard: str
    compliant: bool
    score: float
    violations: List[Dict[str, Any]] = Field(default_factory=list)
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