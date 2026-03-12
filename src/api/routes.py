"""
VulnScope - API Routes
REST API endpoints for VulnScope platform
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query, Depends
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from datetime import datetime
from sqlalchemy import select, func
from sqlalchemy.ext.asyncio import AsyncSession
import asyncio
import random
import os
import json

from .schemas import (
    TargetCreate, TargetResponse, TargetUpdate,
    ScanCreate, ScanResponse, ScanStatusResponse,
    FindingResponse, FindingListResponse,
    ReportGenerateRequest, ReportResponse,
    PolicyCreate, PolicyResponse,
    ComplianceRequest, ComplianceResponse,
)
from ..core.models import Target, Scan, Finding, Endpoint, Status
from ..database import (
    get_session, get_or_create_session, init_db,
    TargetModel, ScanModel, FindingModel, ReportModel, SettingsModel, ComplianceDataModel
)

# Fallback in-memory storage (used if database is not available)
_targets_db: Dict[UUID, Target] = {}
_scans_db: Dict[UUID, Scan] = {}
_findings_db: Dict[UUID, Finding] = {}
_reports_db: Dict[UUID, Dict] = {}

# Check if database is enabled
USE_DATABASE = os.environ.get("DATABASE_URL") or os.environ.get("USE_DATABASE", "false").lower() == "true"


async def get_db_session():
    """Get database session if available, otherwise return None"""
    if USE_DATABASE:
        try:
            return await get_or_create_session()
        except Exception:
            return None
    return None

from ..discovery.crawler import Crawler
from ..discovery.openapi_importer import OpenAPIImporter
from ..discovery.graphql_importer import GraphQLImporter
from ..scanner.scanner import Scanner
from ..fuzzer.fuzzer import Fuzzer
from ..evidence.vault import EvidenceVault
from ..evidence.policy import PolicyEngine
from ..evidence.exporters import ExporterFactory
from ..evidence.compliance import ComplianceReport
from ..config.settings import get_settings

router = APIRouter()


# ============ Dashboard Endpoints ============

@router.get("/dashboard/stats", tags=["dashboard"])
async def get_dashboard_stats():
    """Get dashboard statistics"""
    total_scans = len(_scans_db)
    active_scans = sum(1 for s in _scans_db.values() if s.status in [Status.RUNNING, Status.PENDING])
    
    total_findings = len(_findings_db)
    critical_findings = sum(1 for f in _findings_db.values() if f.severity == "Critical")
    high_findings = sum(1 for f in _findings_db.values() if f.severity == "High")
    medium_findings = sum(1 for f in _findings_db.values() if f.severity == "Medium")
    low_findings = sum(1 for f in _findings_db.values() if f.severity == "Low")
    
    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "medium_findings": medium_findings,
        "low_findings": low_findings,
        "total_targets": len(_targets_db),
        "scans_change": random.randint(-5, 15),  # Mock change percentage
        "critical_change": random.randint(-3, 2),
        "high_change": random.randint(-5, 10),
    }


@router.get("/dashboard/trends", tags=["dashboard"])
async def get_dashboard_trends():
    """Get vulnerability trends over time"""
    # Mock trend data - in production, this would query historical data
    return [
        {"period": "Week 1", "count": random.randint(10, 30)},
        {"period": "Week 2", "count": random.randint(15, 35)},
        {"period": "Week 3", "count": random.randint(12, 28)},
        {"period": "Week 4", "count": random.randint(18, 40)},
    ]


@router.get("/dashboard/severity", tags=["dashboard"])
async def get_severity_distribution():
    """Get findings distribution by severity"""
    return {
        "severity": [
            {"name": "Critical", "count": sum(1 for f in _findings_db.values() if f.severity == "Critical")},
            {"name": "High", "count": sum(1 for f in _findings_db.values() if f.severity == "High")},
            {"name": "Medium", "count": sum(1 for f in _findings_db.values() if f.severity == "Medium")},
            {"name": "Low", "count": sum(1 for f in _findings_db.values() if f.severity == "Low")},
            {"name": "Info", "count": sum(1 for f in _findings_db.values() if f.severity == "Info")},
        ]
    }


# ============ Target Endpoints ============

@router.post("/targets", response_model=TargetResponse, tags=["targets"])
async def create_target(target: TargetCreate):
    """Create a new target to scan"""
    new_target = Target(
        name=target.name,
        url=target.url,
        description=target.description,
        tags=target.tags or [],
        auth_type=target.auth_type,
        auth_config=target.auth_config or {},
    )
    
    # Save to in-memory storage
    _targets_db[new_target.id] = new_target
    
    return TargetResponse(
        id=new_target.id,
        name=new_target.name,
        url=str(new_target.url),
        description=new_target.description,
        tags=new_target.tags,
        auth_type=new_target.auth_type,
        created_at=new_target.created_at,
    )


@router.get("/targets", response_model=List[TargetResponse], tags=["targets"])
async def list_targets(skip: int = 0, limit: int = 100):
    """List all targets"""
    targets = list(_targets_db.values())
    # Apply pagination
    return [
        TargetResponse(
            id=t.id,
            name=t.name,
            url=str(t.url),
            description=t.description,
            tags=t.tags,
            auth_type=t.auth_type,
            created_at=t.created_at,
        )
        for t in targets[skip:skip + limit]
    ]


@router.get("/targets/{target_id}", response_model=TargetResponse, tags=["targets"])
async def get_target(target_id: UUID):
    """Get target by ID"""
    if target_id not in _targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    
    t = _targets_db[target_id]
    return TargetResponse(
        id=t.id,
        name=t.name,
        url=str(t.url),
        description=t.description,
        tags=t.tags,
        auth_type=t.auth_type,
        created_at=t.created_at,
    )


@router.put("/targets/{target_id}", response_model=TargetResponse, tags=["targets"])
async def update_target(target_id: UUID, target: TargetCreate):
    """Update a target"""
    if target_id not in _targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    
    existing = _targets_db[target_id]
    existing.name = target.name
    existing.url = target.url
    existing.description = target.description
    existing.tags = target.tags
    existing.auth_type = target.auth_type
    existing.auth_config = target.auth_config or {}
    existing.updated_at = datetime.utcnow()
    
    return TargetResponse(
        id=existing.id,
        name=existing.name,
        url=str(existing.url),
        description=existing.description,
        tags=existing.tags,
        auth_type=existing.auth_type,
        created_at=existing.created_at,
    )


@router.delete("/targets/{target_id}", tags=["targets"])
async def delete_target(target_id: UUID):
    """Delete a target"""
    if target_id not in _targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    
    del _targets_db[target_id]
    return {"status": "deleted", "target_id": str(target_id)}


# ============ Scan Endpoints ============

# Store for background scan tasks
_scan_tasks: Dict[UUID, asyncio.Task] = {}


async def run_scan_task(scan: Scan, target_url: str):
    """Execute scan workflow in background"""
    try:
        scan.status = Status.RUNNING
        scan.started_at = datetime.utcnow()
        
        # Simulate scan progress
        total_steps = 10
        for step in range(total_steps):
            await asyncio.sleep(2)  # Simulate work
            scan.progress = int((step + 1) / total_steps * 100)
            
            # Generate some mock findings during scan
            if random.random() > 0.7:
                finding = Finding(
                    scan_id=scan.id,
                    target_id=scan.target_id,
                    title=f"Vulnerability found at /api/endpoint{step}",
                    severity=random.choice(["Critical", "High", "Medium", "Low"]),
                    vuln_type=random.choice(["SQL Injection", "XSS", "SSRF", "IDOR", "CSRF"]),
                    url=f"{target_url}/api/endpoint{step}",
                    method=random.choice(["GET", "POST", "PUT", "DELETE"]),
                    status="Open",
                )
                _findings_db[finding.id] = finding
                scan.findings_count = len([f for f in _findings_db.values() if f.scan_id == scan.id])
        
        # Mark completed
        scan.status = Status.COMPLETED
        scan.completed_at = datetime.utcnow()
        scan.endpoints_discovered = random.randint(50, 200)
        
    except asyncio.CancelledError:
        scan.status = Status.CANCELLED
        scan.completed_at = datetime.utcnow()
    except Exception as e:
        scan.status = Status.FAILED
        scan.completed_at = datetime.utcnow()
        scan.error_message = str(e)


@router.post("/scans", response_model=ScanResponse, tags=["scans"])
async def create_scan(scan: ScanCreate, background_tasks: BackgroundTasks):
    """Create and start a new scan"""
    # Verify target exists
    try:
        target_id = UUID(scan.target_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid target_id format")
    
    if target_id not in _targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    
    target = _targets_db[target_id]
    
    # Create scan object
    new_scan = Scan(
        target_id=target_id,
        name=scan.name,
        description=scan.description,
        scan_type=scan.scan_type,
        enable_crawler=scan.enable_crawler,
        enable_openapi_import=scan.enable_openapi_import,
        enable_graphql_import=scan.enable_graphql_import,
        enable_dast=scan.enable_dast,
        enable_fuzzer=scan.enable_fuzzer,
    )
    
    # Save scan
    _scans_db[new_scan.id] = new_scan
    
    # Start scan in background
    background_tasks.add_task(run_scan_task, new_scan, str(target.url))
    
    return ScanResponse(
        id=new_scan.id,
        target_id=new_scan.target_id,
        name=new_scan.name,
        status=new_scan.status.value,
        progress=getattr(new_scan, 'progress', 0),
        endpoints_discovered=getattr(new_scan, 'endpoints_discovered', 0),
        findings_count=getattr(new_scan, 'findings_count', 0),
        created_at=new_scan.created_at,
        started_at=getattr(new_scan, 'started_at', None),
        completed_at=getattr(new_scan, 'completed_at', None),
    )


@router.get("/scans", response_model=List[ScanResponse], tags=["scans"])
async def list_scans(
    target_id: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0, 
    limit: int = 100
):
    """List all scans"""
    scans = list(_scans_db.values())
    
    # Filter by target_id
    if target_id:
        try:
            tid = UUID(target_id)
            scans = [s for s in scans if s.target_id == tid]
        except ValueError:
            pass
    
    # Filter by status
    if status:
        try:
            status_enum = Status(status.lower())
            scans = [s for s in scans if s.status == status_enum]
        except ValueError:
            pass
    
    # Sort by created_at descending
    scans = sorted(scans, key=lambda s: s.created_at, reverse=True)
    
    # Apply pagination
    return [
        ScanResponse(
            id=s.id,
            target_id=s.target_id,
            name=s.name,
            status=s.status.value,
            progress=getattr(s, 'progress', 0),
            endpoints_discovered=getattr(s, 'endpoints_discovered', 0),
            findings_count=getattr(s, 'findings_count', 0),
            created_at=s.created_at,
            started_at=getattr(s, 'started_at', None),
            completed_at=getattr(s, 'completed_at', None),
        )
        for s in scans[skip:skip + limit]
    ]


@router.get("/scans/{scan_id}", response_model=ScanResponse, tags=["scans"])
async def get_scan(scan_id: UUID):
    """Get scan by ID"""
    if scan_id not in _scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    s = _scans_db[scan_id]
    return ScanResponse(
        id=s.id,
        target_id=s.target_id,
        name=s.name,
        status=s.status.value,
        progress=getattr(s, 'progress', 0),
        endpoints_discovered=getattr(s, 'endpoints_discovered', 0),
        findings_count=getattr(s, 'findings_count', 0),
        created_at=s.created_at,
        started_at=getattr(s, 'started_at', None),
        completed_at=getattr(s, 'completed_at', None),
    )


@router.get("/scans/{scan_id}/status", response_model=ScanStatusResponse, tags=["scans"])
async def get_scan_status(scan_id: UUID):
    """Get scan status"""
    if scan_id not in _scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    s = _scans_db[scan_id]
    return ScanStatusResponse(
        scan_id=scan_id,
        status=s.status.value,
        progress=getattr(s, 'progress', 0),
        endpoints_discovered=getattr(s, 'endpoints_discovered', 0),
        findings_count=getattr(s, 'findings_count', 0),
    )


@router.post("/scans/{scan_id}/cancel", tags=["scans"])
async def cancel_scan(scan_id: UUID):
    """Cancel a running scan"""
    if scan_id not in _scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = _scans_db[scan_id]
    if scan.status == Status.RUNNING:
        scan.status = Status.CANCELLED
        scan.completed_at = datetime.utcnow()
    
    return {"status": "cancelled", "scan_id": str(scan_id)}


# ============ Finding Endpoints ============

@router.get("/findings", response_model=FindingListResponse, tags=["findings"])
async def list_findings(
    scan_id: Optional[str] = None,
    target_id: Optional[str] = None,
    severity: Optional[str] = None,
    vuln_type: Optional[str] = None,
    status: Optional[str] = None,
    skip: int = 0, 
    limit: int = 100
):
    """List all findings"""
    findings = list(_findings_db.values())
    
    # Filter by scan_id
    if scan_id:
        try:
            sid = UUID(scan_id)
            findings = [f for f in findings if f.scan_id == sid]
        except ValueError:
            pass
    
    # Filter by target_id
    if target_id:
        try:
            tid = UUID(target_id)
            findings = [f for f in findings if f.target_id == tid]
        except ValueError:
            pass
    
    # Filter by severity
    if severity:
        findings = [f for f in findings if f.severity.lower() == severity.lower()]
    
    # Filter by vuln_type
    if vuln_type:
        findings = [f for f in findings if f.vuln_type.lower() == vuln_type.lower()]
    
    # Filter by status
    if status:
        findings = [f for f in findings if f.status.lower() == status.lower()]
    
    # Sort by created_at descending
    findings = sorted(findings, key=lambda f: f.created_at, reverse=True)
    
    total = len(findings)
    
    return FindingListResponse(
        total=total,
        findings=[
            FindingResponse(
                id=f.id,
                scan_id=f.scan_id,
                target_id=f.target_id,
                title=f.title,
                description=getattr(f, 'description', None),
                severity=f.severity,
                vuln_type=f.vuln_type,
                url=getattr(f, 'url', None),
                method=getattr(f, 'method', None),
                parameter=getattr(f, 'parameter', None),
                payload=getattr(f, 'payload', None),
                evidence=getattr(f, 'evidence', None),
                status=f.status,
                cvss_score=getattr(f, 'cvss_score', None),
                cwe_id=getattr(f, 'cwe_id', None),
                owasp_category=getattr(f, 'owasp_category', None),
                created_at=f.created_at,
            )
            for f in findings[skip:skip + limit]
        ],
    )


@router.get("/findings/{finding_id}", response_model=FindingResponse, tags=["findings"])
async def get_finding(finding_id: UUID):
    """Get finding by ID"""
    if finding_id not in _findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    f = _findings_db[finding_id]
    return FindingResponse(
        id=f.id,
        scan_id=f.scan_id,
        target_id=f.target_id,
        title=f.title,
        description=getattr(f, 'description', None),
        severity=f.severity,
        vuln_type=f.vuln_type,
        url=getattr(f, 'url', None),
        method=getattr(f, 'method', None),
        parameter=getattr(f, 'parameter', None),
        payload=getattr(f, 'payload', None),
        evidence=getattr(f, 'evidence', None),
        status=f.status,
        cvss_score=getattr(f, 'cvss_score', None),
        cwe_id=getattr(f, 'cwe_id', None),
        owasp_category=getattr(f, 'owasp_category', None),
        created_at=f.created_at,
    )


@router.patch("/findings/{finding_id}", tags=["findings"])
async def update_finding(finding_id: UUID, status: str = None, false_positive: bool = False):
    """Update finding status"""
    if finding_id not in _findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding = _findings_db[finding_id]
    if status:
        finding.status = status
    if false_positive:
        finding.false_positive = True
        finding.status = "False Positive"
    
    return {
        "status": "updated",
        "finding_id": str(finding_id),
        "new_status": finding.status,
        "false_positive": false_positive,
    }


@router.post("/findings/{finding_id}/verify", tags=["findings"])
async def verify_finding(finding_id: UUID, verified: bool = True):
    """Verify a finding"""
    if finding_id not in _findings_db:
        raise HTTPException(status_code=404, detail="Finding not found")
    
    finding = _findings_db[finding_id]
    finding.verified = verified
    
    return {
        "status": "verified",
        "finding_id": str(finding_id),
        "verified": verified,
    }


# ============ Discovery Endpoints ============

@router.post("/discover/crawl", tags=["discovery"])
async def discover_crawl(target_id: UUID):
    """Discover endpoints via crawling"""
    if target_id not in _targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # In production, run actual crawler
    return {
        "status": "completed",
        "endpoints_found": random.randint(50, 200),
    }


@router.post("/discover/openapi", tags=["discovery"])
async def discover_openapi(spec_url: str = Query(...), target_id: UUID = Query(...)):
    """Import endpoints from OpenAPI spec"""
    if target_id not in _targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # In production, import from OpenAPI
    return {
        "status": "completed",
        "endpoints_imported": random.randint(20, 100),
    }


@router.post("/discover/graphql", tags=["discovery"])
async def discover_graphql(endpoint_url: str = Query(...), target_id: UUID = Query(...)):
    """Import endpoints from GraphQL"""
    if target_id not in _targets_db:
        raise HTTPException(status_code=404, detail="Target not found")
    
    # In production, import from GraphQL
    return {
        "status": "completed",
        "queries_found": random.randint(10, 50),
        "mutations_found": random.randint(5, 30),
    }


# ============ Report Endpoints ============

@router.get("/reports", tags=["reports"])
async def list_reports():
    """List all reports"""
    return [
        {
            "id": str(r["id"]),
            "scan_id": str(r["scan_id"]),
            "name": r["name"],
            "format": r["format"],
            "size": r.get("size", "Unknown"),
            "created_at": r["created_at"],
        }
        for r in _reports_db.values()
    ]


@router.post("/reports/generate", response_model=ReportResponse, tags=["reports"])
async def generate_report(request: ReportGenerateRequest):
    """Generate a report"""
    # Verify scan exists
    try:
        scan_id = UUID(request.scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    
    if scan_id not in _scans_db:
        raise HTTPException(status_code=404, detail="Scan not found")
    
    scan = _scans_db[scan_id]
    
    # Create report
    report_id = uuid4()
    report = {
        "id": report_id,
        "scan_id": scan_id,
        "name": request.name or f"Report for {scan.name}",
        "format": request.format,
        "size": f"{random.randint(50, 500)} KB",
        "created_at": datetime.utcnow().isoformat(),
        "content": "Report content would be here",
    }
    
    _reports_db[report_id] = report
    
    return ReportResponse(
        id=report_id,
        scan_id=scan_id,
        format=request.format,
        content=report["content"],
    )


@router.get("/reports/{report_id}", tags=["reports"])
async def get_report(report_id: UUID):
    """Get a report"""
    if report_id not in _reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return _reports_db[report_id]


@router.get("/reports/{report_id}/download", tags=["reports"])
async def download_report(report_id: UUID):
    """Download a report"""
    if report_id not in _reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    
    report = _reports_db[report_id]
    # In production, return actual file
    return {"download_url": f"/reports/{report_id}/file.{report['format']}"}


# ============ Policy Endpoints ============

@router.post("/policies", response_model=PolicyResponse, tags=["policies"])
async def create_policy(policy: PolicyCreate):
    """Create a security policy"""
    # In production, save to database
    return PolicyResponse(
        id=uuid4(),
        name=policy.name,
        description=policy.description,
        rules_count=len(policy.rules) if policy.rules else 0,
    )


@router.get("/policies", response_model=List[PolicyResponse], tags=["policies"])
async def list_policies():
    """List all policies"""
    # In production, fetch from database
    return []


@router.get("/policies/{policy_id}", response_model=PolicyResponse, tags=["policies"])
async def get_policy(policy_id: UUID):
    """Get policy by ID"""
    # In production, fetch from database
    raise HTTPException(status_code=404, detail="Policy not found")


@router.post("/policies/{policy_id}/evaluate", tags=["policies"])
async def evaluate_policy(policy_id: UUID, scan_id: UUID):
    """Evaluate scan against a policy"""
    # In production, evaluate
    return {
        "policy_id": str(policy_id),
        "scan_id": str(scan_id),
        "passed": True,
        "violations": [],
    }


# ============ Compliance Endpoints ============

@router.post("/compliance/check", response_model=ComplianceResponse, tags=["compliance"])
async def check_compliance(request: ComplianceRequest):
    """Check compliance status"""
    # In production, run compliance check
    return ComplianceResponse(
        standard=request.standard,
        compliant=True,
        score=random.uniform(75, 98),
        violations=[],
    )


@router.get("/compliance/standards", tags=["compliance"])
async def list_compliance_standards():
    """List supported compliance standards with scores"""
    # Calculate scores based on actual findings
    total_findings = len(_findings_db)
    critical = sum(1 for f in _findings_db.values() if f.severity == "Critical")
    high = sum(1 for f in _findings_db.values() if f.severity == "High")
    medium = sum(1 for f in _findings_db.values() if f.severity == "Medium")
    low = sum(1 for f in _findings_db.values() if f.severity == "Low")
    
    # Base score on findings - deterministic calculation
    # Critical findings have the most impact, then High, Medium, Low
    base_score = max(0, 100 - (critical * 15) - (high * 8) - (medium * 3) - (low * 1))
    
    # Calculate requirements met based on findings severity
    # Each standard has different tolerance for vulnerabilities
    def calculate_requirements(met_base: int, total: int, critical_count: int, high_count: int) -> int:
        """Calculate requirements met based on vulnerability counts"""
        failed = min(met_base // 5, critical_count * 3 + high_count)
        return max(0, met_base - failed)
    
    standards = [
        {
            "name": "PCI-DSS",
            "score": min(100, max(0, base_score - critical * 5)),
            "status": "pass" if (base_score - critical * 5) >= 90 else "warning" if (base_score - critical * 5) >= 70 else "fail",
            "requirements_met": calculate_requirements(20, 20, critical, high),
            "requirements_total": 20,
        },
        {
            "name": "NIS2",
            "score": min(100, max(0, base_score - critical * 3 - high * 2)),
            "status": "pass" if (base_score - critical * 3 - high * 2) >= 85 else "warning" if (base_score - critical * 3 - high * 2) >= 65 else "fail",
            "requirements_met": calculate_requirements(32, 32, critical, high),
            "requirements_total": 32,
        },
        {
            "name": "SOC2",
            "score": min(100, max(0, base_score - critical * 4)),
            "status": "pass" if (base_score - critical * 4) >= 90 else "warning" if (base_score - critical * 4) >= 70 else "fail",
            "requirements_met": calculate_requirements(50, 50, critical, high),
            "requirements_total": 50,
        },
        {
            "name": "HIPAA",
            "score": min(100, max(0, base_score - critical * 6 - high * 2)),
            "status": "pass" if (base_score - critical * 6 - high * 2) >= 88 else "warning" if (base_score - critical * 6 - high * 2) >= 68 else "fail",
            "requirements_met": calculate_requirements(50, 50, critical, high),
            "requirements_total": 50,
        },
        {
            "name": "ISO27001",
            "score": min(100, max(0, base_score - critical * 2 - high)),
            "status": "pass" if (base_score - critical * 2 - high) >= 85 else "warning" if (base_score - critical * 2 - high) >= 65 else "fail",
            "requirements_met": calculate_requirements(80, 80, critical, high),
            "requirements_total": 80,
        },
    ]
    
    return {"standards": standards}


@router.get("/compliance/categories", tags=["compliance"])
async def get_compliance_categories():
    """Get compliance scores by category based on actual findings"""
    # Count findings by vulnerability type to determine category scores
    total_findings = len(_findings_db)
    critical = sum(1 for f in _findings_db.values() if f.severity == "Critical")
    high = sum(1 for f in _findings_db.values() if f.severity == "High")
    medium = sum(1 for f in _findings_db.values() if f.severity == "Medium")
    low = sum(1 for f in _findings_db.values() if f.severity == "Low")
    
    # Map vulnerability types to categories
    vuln_types = [f.vuln_type for f in _findings_db.values()]
    
    # Calculate category scores based on relevant findings
    def calc_category_score(base: int, relevant_critical: int, relevant_high: int) -> int:
        return max(0, min(100, base - relevant_critical * 20 - relevant_high * 10))
    
    # Access Control - affected by IDOR, CSRF, auth issues
    auth_vulns = sum(1 for f in _findings_db.values() if f.vuln_type in ["IDOR", "CSRF", "Broken Authentication"])
    access_score = calc_category_score(95, auth_vulns // 2, auth_vulns)
    
    # Encryption - affected by data exposure issues
    crypto_vulns = sum(1 for f in _findings_db.values() if "crypto" in f.vuln_type.lower() or "exposure" in f.vuln_type.lower())
    encryption_score = calc_category_score(98, crypto_vulns, crypto_vulns // 2)
    
    # Monitoring - affected by injection issues
    injection_vulns = sum(1 for f in _findings_db.values() if "injection" in f.vuln_type.lower() or "xss" in f.vuln_type.lower())
    monitoring_score = calc_category_score(92, injection_vulns // 2, injection_vulns)
    
    # Incident Response - general security posture
    incident_score = calc_category_score(90, critical // 3, high // 2)
    
    # Vendor Management - SSRF and external service issues
    ssrf_vulns = sum(1 for f in _findings_db.values() if "ssrf" in f.vuln_type.lower())
    vendor_score = calc_category_score(94, ssrf_vulns, ssrf_vulns // 2)
    
    return {
        "categories": [
            {"name": "Access Control", "score": access_score},
            {"name": "Encryption", "score": encryption_score},
            {"name": "Monitoring", "score": monitoring_score},
            {"name": "Incident Response", "score": incident_score},
            {"name": "Vendor Management", "score": vendor_score},
        ]
    }


# ============ Integration Endpoints ============

@router.post("/integrations/github/check", tags=["integrations"])
async def create_github_check(scan_id: UUID):
    """Create GitHub check"""
    return {
        "status": "created",
        "check_url": "https://github.com/...",
    }


@router.post("/integrations/jira/ticket", tags=["integrations"])
async def create_jira_ticket(scan_id: UUID):
    """Create Jira ticket"""
    return {
        "status": "created",
        "ticket_key": "PROJECT-123",
    }


@router.post("/integrations/siem/send", tags=["integrations"])
async def send_to_siem(scan_id: UUID, system: str = "splunk"):
    """Send results to SIEM"""
    return {
        "status": "sent",
        "system": system,
    }


# ============ Settings Endpoints ============

_settings_store: Dict[str, Any] = {
    "api_url": "http://localhost:8000/api/v1",
    "max_concurrent": 10,
    "timeout": 30,
    "rate_limit": 100,
    "email_notifications": True,
    "slack_integration": False,
    "default_theme": "dark",
    "auto_refresh": False,
}


@router.get("/settings", tags=["settings"])
async def get_settings_endpoint():
    """Get application settings"""
    settings = get_settings()
    # Handle case where get_settings is async
    if hasattr(settings, '__await__'):
        settings = await settings
    return {
        **_settings_store,
        "app_name": settings.app_name,
        "version": settings.app_version,
        "environment": settings.environment,
    }


@router.put("/settings", tags=["settings"])
async def update_settings(settings: Dict[str, Any]):
    """Update application settings"""
    # Update only allowed settings
    allowed_keys = [
        "api_url", "max_concurrent", "timeout", "rate_limit",
        "email_notifications", "slack_integration", "default_theme", "auto_refresh"
    ]
    
    for key in allowed_keys:
        if key in settings:
            _settings_store[key] = settings[key]
    
    return {**_settings_store, "status": "updated"}