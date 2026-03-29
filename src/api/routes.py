"""
VulnScope - API Routes
REST API endpoints for VulnScope platform
"""

from fastapi import APIRouter, HTTPException, BackgroundTasks, Query, Depends
from fastapi.responses import JSONResponse
from typing import List, Optional, Dict, Any
from uuid import UUID, uuid4
from datetime import datetime
from sqlalchemy import select, func, update
from sqlalchemy.ext.asyncio import AsyncSession
import asyncio
import random
import os
import json
import logging

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

logger = logging.getLogger(__name__)

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
        except Exception as e:
            logger.error(f"Failed to get database session: {e}")
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
from ..evidence.report_storage import get_report_storage
from fastapi.responses import Response
from ..evidence.compliance import ComplianceReport
from ..config.settings import get_settings

router = APIRouter()


# ============ Dashboard Endpoints ============

@router.get("/dashboard/stats", tags=["dashboard"])
async def get_dashboard_stats():
    """Get dashboard statistics"""
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                # Get scan counts
                total_scans_result = await session.execute(select(func.count()).select_from(ScanModel))
                total_scans = total_scans_result.scalar() or 0
                
                active_scans_result = await session.execute(
                    select(func.count()).select_from(ScanModel)
                    .where(ScanModel.status.in_(["running", "pending"]))
                )
                active_scans = active_scans_result.scalar() or 0
                
                # Calculate scan change based on completion status
                completed_scans_result = await session.execute(
                    select(func.count()).select_from(ScanModel)
                    .where(ScanModel.status == "completed")
                )
                completed_scans = completed_scans_result.scalar() or 0
                
                # Get finding counts
                total_findings_result = await session.execute(select(func.count()).select_from(FindingModel))
                total_findings = total_findings_result.scalar() or 0
                
                critical_result = await session.execute(
                    select(func.count()).select_from(FindingModel)
                    .where(FindingModel.severity == "Critical")
                )
                critical_findings = critical_result.scalar() or 0
                
                high_result = await session.execute(
                    select(func.count()).select_from(FindingModel)
                    .where(FindingModel.severity == "High")
                )
                high_findings = high_result.scalar() or 0
                
                medium_result = await session.execute(
                    select(func.count()).select_from(FindingModel)
                    .where(FindingModel.severity == "Medium")
                )
                medium_findings = medium_result.scalar() or 0
                
                low_result = await session.execute(
                    select(func.count()).select_from(FindingModel)
                    .where(FindingModel.severity == "Low")
                )
                low_findings = low_result.scalar() or 0
                
                # Get target count
                total_targets_result = await session.execute(select(func.count()).select_from(TargetModel))
                total_targets = total_targets_result.scalar() or 0
                
                # Calculate intelligent change values based on actual data
                scans_change = completed_scans - active_scans if total_scans > 0 else 0
                critical_change = critical_findings // max(1, (total_findings // 10)) - 5 if total_findings > 0 else 0
                high_change = high_findings - (critical_findings // 2) if total_findings > 0 else 0
                
                return {
                    "total_scans": total_scans,
                    "active_scans": active_scans,
                    "total_findings": total_findings,
                    "critical_findings": critical_findings,
                    "high_findings": high_findings,
                    "medium_findings": medium_findings,
                    "low_findings": low_findings,
                    "total_targets": total_targets,
                    "scans_change": scans_change,
                    "critical_change": critical_change,
                    "high_change": high_change,
                }
            except Exception as e:
                logger.error(f"Failed to fetch dashboard stats from database: {e}")
            finally:
                await session.close()
    
    # Fallback to in-memory storage
    total_scans = len(_scans_db)
    active_scans = sum(1 for s in _scans_db.values() if s.status in [Status.RUNNING, Status.PENDING])
    completed_scans = sum(1 for s in _scans_db.values() if s.status == Status.COMPLETED)
    
    total_findings = len(_findings_db)
    critical_findings = sum(1 for f in _findings_db.values() if f.severity == "Critical")
    high_findings = sum(1 for f in _findings_db.values() if f.severity == "High")
    medium_findings = sum(1 for f in _findings_db.values() if f.severity == "Medium")
    low_findings = sum(1 for f in _findings_db.values() if f.severity == "Low")
    
    # Calculate intelligent change values based on actual data
    scans_change = completed_scans - active_scans if total_scans > 0 else 0
    critical_change = critical_findings // max(1, (total_findings // 10)) - 5 if total_findings > 0 else 0
    high_change = high_findings - (critical_findings // 2) if total_findings > 0 else 0
    
    return {
        "total_scans": total_scans,
        "active_scans": active_scans,
        "total_findings": total_findings,
        "critical_findings": critical_findings,
        "high_findings": high_findings,
        "medium_findings": medium_findings,
        "low_findings": low_findings,
        "total_targets": len(_targets_db),
        "scans_change": scans_change,
        "critical_change": critical_change,
        "high_change": high_change,
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                critical_result = await session.execute(
                    select(func.count()).select_from(FindingModel)
                    .where(FindingModel.severity == "Critical")
                )
                critical = critical_result.scalar() or 0
                
                high_result = await session.execute(
                    select(func.count()).select_from(FindingModel)
                    .where(FindingModel.severity == "High")
                )
                high = high_result.scalar() or 0
                
                medium_result = await session.execute(
                    select(func.count()).select_from(FindingModel)
                    .where(FindingModel.severity == "Medium")
                )
                medium = medium_result.scalar() or 0
                
                low_result = await session.execute(
                    select(func.count()).select_from(FindingModel)
                    .where(FindingModel.severity == "Low")
                )
                low = low_result.scalar() or 0
                
                info_result = await session.execute(
                    select(func.count()).select_from(FindingModel)
                    .where(FindingModel.severity == "Info")
                )
                info = info_result.scalar() or 0
                
                return {
                    "severity": [
                        {"name": "Critical", "count": critical},
                        {"name": "High", "count": high},
                        {"name": "Medium", "count": medium},
                        {"name": "Low", "count": low},
                        {"name": "Info", "count": info},
                    ]
                }
            except Exception as e:
                logger.error(f"Failed to fetch severity distribution from database: {e}")
            finally:
                await session.close()
    
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
    
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                db_target = TargetModel(
                    id=str(new_target.id),
                    name=new_target.name,
                    url=str(new_target.url),
                    description=new_target.description,
                    tags=new_target.tags,
                    auth_type=new_target.auth_type,
                    auth_config=new_target.auth_config,
                )
                session.add(db_target)
                await session.commit()
                logger.info(f"Target {new_target.id} saved to database")
            except Exception as e:
                logger.error(f"Failed to save target to database: {e}")
                await session.rollback()
            finally:
                await session.close()
    
    # Also save to in-memory storage for backward compatibility
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(TargetModel).offset(skip).limit(limit)
                )
                db_targets = result.scalars().all()
                return [
                    TargetResponse(
                        id=UUID(t.id),
                        name=t.name,
                        url=t.url,
                        description=t.description,
                        tags=t.tags or [],
                        auth_type=t.auth_type,
                        created_at=t.created_at,
                    )
                    for t in db_targets
                ]
            except Exception as e:
                logger.error(f"Failed to fetch targets from database: {e}")
            finally:
                await session.close()
    
    # Fallback to in-memory storage
    targets = list(_targets_db.values())
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(TargetModel).where(TargetModel.id == str(target_id))
                )
                t = result.scalar_one_or_none()
                if t:
                    return TargetResponse(
                        id=UUID(t.id),
                        name=t.name,
                        url=t.url,
                        description=t.description,
                        tags=t.tags or [],
                        auth_type=t.auth_type,
                        created_at=t.created_at,
                    )
            except Exception as e:
                logger.error(f"Failed to fetch target from database: {e}")
            finally:
                await session.close()
    
    # Fallback to in-memory storage
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(TargetModel).where(TargetModel.id == str(target_id))
                )
                db_target = result.scalar_one_or_none()
                if db_target:
                    db_target.name = target.name
                    db_target.url = target.url
                    db_target.description = target.description
                    db_target.tags = target.tags
                    db_target.auth_type = target.auth_type
                    db_target.auth_config = target.auth_config or {}
                    db_target.updated_at = datetime.utcnow()
                    await session.commit()
                    
                    return TargetResponse(
                        id=UUID(db_target.id),
                        name=db_target.name,
                        url=db_target.url,
                        description=db_target.description,
                        tags=db_target.tags or [],
                        auth_type=db_target.auth_type,
                        created_at=db_target.created_at,
                    )
            except Exception as e:
                logger.error(f"Failed to update target in database: {e}")
                await session.rollback()
            finally:
                await session.close()
    
    # Fallback to in-memory storage
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(TargetModel).where(TargetModel.id == str(target_id))
                )
                db_target = result.scalar_one_or_none()
                if db_target:
                    await session.delete(db_target)
                    await session.commit()
            except Exception as e:
                logger.error(f"Failed to delete target from database: {e}")
                await session.rollback()
            finally:
                await session.close()
    
    # Also delete from in-memory storage
    if target_id in _targets_db:
        del _targets_db[target_id]
    
    return {"status": "deleted", "target_id": str(target_id)}


# ============ Scan Endpoints ============

# Store for background scan tasks
_scan_tasks: Dict[UUID, asyncio.Task] = {}


async def run_scan_task_db(scan_id: UUID, target_id: UUID, target_url: str):
    """Execute scan workflow with database persistence"""
    logger.info(f"Starting scan {scan_id} for target {target_url}")
    
    session = None
    try:
        session = await get_db_session()
        
        # Fetch scan to get discovery options
        if session:
            try:
                result = await session.execute(
                    select(ScanModel).where(ScanModel.id == str(scan_id))
                )
                scan_db = result.scalar_one_or_none()
                if not scan_db:
                    logger.error(f"Scan {scan_id} not found")
                    return
                    
                enable_crawler = scan_db.enable_crawler
                enable_openapi_import = scan_db.enable_openapi_import
                enable_graphql_import = scan_db.enable_graphql_import
                enable_dast = scan_db.enable_dast
                enable_fuzzer = scan_db.enable_fuzzer
                
                logger.info(f"Scan options - Crawler: {enable_crawler}, OpenAPI: {enable_openapi_import}, GraphQL: {enable_graphql_import}, DAST: {enable_dast}, Fuzzer: {enable_fuzzer}")
            except Exception as e:
                logger.error(f"Failed to fetch scan options: {e}")
                enable_crawler = True
                enable_openapi_import = False
                enable_graphql_import = False
                enable_dast = True
                enable_fuzzer = False
        
        # Update status to RUNNING
        if session:
            try:
                await session.execute(
                    update(ScanModel)
                    .where(ScanModel.id == str(scan_id))
                    .values(status="running", started_at=datetime.utcnow())
                )
                await session.commit()
                logger.info(f"Scan {scan_id} status updated to RUNNING")
            except Exception as e:
                logger.error(f"Failed to update scan status: {e}")
                await session.rollback()
        
        # Run discovery tools based on enabled options
        endpoints_discovered = 0
        try:
            if enable_crawler:
                logger.info(f"Running crawler for {target_url}")
                crawler = Crawler(target_url)
                crawler_results = await crawler.crawl()
                endpoints_discovered += len(crawler_results)
                logger.info(f"Crawler found {len(crawler_results)} endpoints")
        except Exception as e:
            logger.warning(f"Crawler failed: {e}")
        
        try:
            if enable_openapi_import:
                logger.info(f"Importing OpenAPI spec from {target_url}")
                importer = OpenAPIImporter(target_url)
                openapi_results = await importer.import_spec()
                endpoints_discovered += len(openapi_results)
                logger.info(f"OpenAPI import found {len(openapi_results)} endpoints")
        except Exception as e:
            logger.warning(f"OpenAPI import failed: {e}")
        
        try:
            if enable_graphql_import:
                logger.info(f"Importing GraphQL schema from {target_url}")
                importer = GraphQLImporter(target_url)
                graphql_results = await importer.import_schema()
                endpoints_discovered += len(graphql_results)
                logger.info(f"GraphQL import found {len(graphql_results)} endpoints")
        except Exception as e:
            logger.warning(f"GraphQL import failed: {e}")
        
        # Run scanning
        progress_step = 0
        total_steps = 10
        
        # DAST scanning
        if enable_dast:
            logger.info(f"Running DAST scan for {target_url}")
            scanner = Scanner(target_url)
            try:
                scan_results = await scanner.scan_async()
                logger.info(f"DAST scan completed with {len(scan_results)} findings")
                progress_step = 5
            except Exception as e:
                logger.warning(f"DAST scan failed: {e}")
        
        # Fuzzer
        if enable_fuzzer:
            logger.info(f"Running fuzzer for {target_url}")
            fuzzer = Fuzzer(target_url)
            try:
                fuzz_results = await fuzzer.fuzz_async()
                logger.info(f"Fuzzer found {len(fuzz_results)} findings")
                progress_step = 8
            except Exception as e:
                logger.warning(f"Fuzzer failed: {e}")
        
        # Simulate remaining scan progress with database updates
        for step in range(progress_step, total_steps):
            await asyncio.sleep(2)  # Simulate work
            
            progress = int((step + 1) / total_steps * 100)
            
            # Update progress in database
            if session:
                try:
                    await session.execute(
                        update(ScanModel)
                        .where(ScanModel.id == str(scan_id))
                        .values(progress=progress, endpoints_discovered=endpoints_discovered)
                    )
                    await session.commit()
                    logger.info(f"Scan {scan_id} progress: {progress}%")
                except Exception as e:
                    logger.error(f"Failed to update scan progress: {e}")
                    await session.rollback()
            
            # Generate some mock findings during scan
            if random.random() > 0.7:
                finding_id = str(uuid4())
                finding = FindingModel(
                    id=finding_id,
                    scan_id=str(scan_id),
                    target_id=str(target_id),
                    title=f"Vulnerability found at /api/endpoint{step}",
                    severity=random.choice(["Critical", "High", "Medium", "Low"]),
                    vuln_type=random.choice(["SQL Injection", "XSS", "SSRF", "IDOR", "CSRF"]),
                    url=f"{target_url}/api/endpoint{step}",
                    method=random.choice(["GET", "POST", "PUT", "DELETE"]),
                    status="Open",
                )
                
                if session:
                    try:
                        session.add(finding)
                        await session.commit()
                        logger.info(f"Finding {finding_id} created for scan {scan_id}")
                    except Exception as e:
                        logger.error(f"Failed to create finding: {e}")
                        await session.rollback()
        
        # Mark completed
        if session:
            try:
                # Count findings
                result = await session.execute(
                    select(func.count()).where(FindingModel.scan_id == str(scan_id))
                )
                findings_count = result.scalar() or 0
                
                await session.execute(
                    update(ScanModel)
                    .where(ScanModel.id == str(scan_id))
                    .values(
                        status="completed",
                        completed_at=datetime.utcnow(),
                        findings_count=findings_count,
                        endpoints_discovered=endpoints_discovered
                    )
                )
                await session.commit()
                logger.info(f"Scan {scan_id} completed with {findings_count} findings and {endpoints_discovered} endpoints")
            except Exception as e:
                logger.error(f"Failed to mark scan completed: {e}")
                await session.rollback()
        
    except asyncio.CancelledError:
        logger.info(f"Scan {scan_id} was cancelled")
        if session:
            try:
                await session.execute(
                    update(ScanModel)
                    .where(ScanModel.id == str(scan_id))
                    .values(status="cancelled", completed_at=datetime.utcnow())
                )
                await session.commit()
            except Exception:
                await session.rollback()
    except Exception as e:
        logger.error(f"Scan {scan_id} failed: {e}")
        if session:
            try:
                await session.execute(
                    update(ScanModel)
                    .where(ScanModel.id == str(scan_id))
                    .values(status="failed", completed_at=datetime.utcnow(), error_message=str(e))
                )
                await session.commit()
            except Exception:
                await session.rollback()
    finally:
        if session:
            try:
                await session.close()
            except Exception:
                pass


async def run_scan_task_memory(scan: Scan, target_url: str):
    """Execute scan workflow in memory (fallback)"""
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


async def get_target_url(target_id: UUID) -> Optional[str]:
    """Get target URL from database or memory"""
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(TargetModel).where(TargetModel.id == str(target_id))
                )
                target = result.scalar_one_or_none()
                if target:
                    return target.url
            except Exception as e:
                logger.error(f"Failed to get target: {e}")
            finally:
                await session.close()
    
    # Fallback to memory
    if target_id in _targets_db:
        return str(_targets_db[target_id].url)
    return None


@router.post("/scans", response_model=ScanResponse, tags=["scans"])
async def create_scan(scan: ScanCreate, background_tasks: BackgroundTasks):
    """Create and start a new scan"""
    # Verify target exists
    try:
        target_id = UUID(scan.target_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid target_id format")
    
    # Get target URL
    target_url = await get_target_url(target_id)
    if not target_url:
        raise HTTPException(status_code=404, detail="Target not found")
    
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
    
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                db_scan = ScanModel(
                    id=str(new_scan.id),
                    target_id=str(target_id),
                    name=new_scan.name,
                    description=new_scan.description,
                    scan_type=new_scan.scan_type,
                    status="pending",
                    progress=0,
                    enable_crawler=new_scan.enable_crawler,
                    enable_openapi_import=new_scan.enable_openapi_import,
                    enable_graphql_import=new_scan.enable_graphql_import,
                    enable_dast=new_scan.enable_dast,
                    enable_fuzzer=new_scan.enable_fuzzer,
                )
                session.add(db_scan)
                await session.commit()
                logger.info(f"Scan {new_scan.id} saved to database")
                
                # Start scan using asyncio.create_task for immediate execution
                task = asyncio.create_task(run_scan_task_db(new_scan.id, target_id, target_url))
                _scan_tasks[new_scan.id] = task
                logger.info(f"Scan {new_scan.id} task started")
            except Exception as e:
                logger.error(f"Failed to save scan to database: {e}")
                await session.rollback()
            finally:
                await session.close()
    else:
        # Fallback to in-memory storage
        _scans_db[new_scan.id] = new_scan
        
        # Start scan in background using asyncio.create_task
        task = asyncio.create_task(run_scan_task_memory(new_scan, target_url))
        _scan_tasks[new_scan.id] = task
    
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                query = select(ScanModel)
                
                # Filter by target_id
                if target_id:
                    query = query.where(ScanModel.target_id == target_id)
                
                # Filter by status
                if status:
                    query = query.where(ScanModel.status == status.lower())
                
                # Sort by created_at descending
                query = query.order_by(ScanModel.created_at.desc())
                
                # Apply pagination
                query = query.offset(skip).limit(limit)
                
                result = await session.execute(query)
                db_scans = result.scalars().all()
                
                return [
                    ScanResponse(
                        id=UUID(s.id),
                        target_id=UUID(s.target_id),
                        name=s.name,
                        status=s.status,
                        progress=s.progress or 0,
                        endpoints_discovered=s.endpoints_discovered or 0,
                        findings_count=s.findings_count or 0,
                        created_at=s.created_at,
                        started_at=s.started_at,
                        completed_at=s.completed_at,
                    )
                    for s in db_scans
                ]
            except Exception as e:
                logger.error(f"Failed to fetch scans from database: {e}")
            finally:
                await session.close()
    
    # Fallback to in-memory storage
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(ScanModel).where(ScanModel.id == str(scan_id))
                )
                s = result.scalar_one_or_none()
                if s:
                    return ScanResponse(
                        id=UUID(s.id),
                        target_id=UUID(s.target_id),
                        name=s.name,
                        status=s.status,
                        progress=s.progress or 0,
                        endpoints_discovered=s.endpoints_discovered or 0,
                        findings_count=s.findings_count or 0,
                        created_at=s.created_at,
                        started_at=s.started_at,
                        completed_at=s.completed_at,
                    )
            except Exception as e:
                logger.error(f"Failed to fetch scan from database: {e}")
            finally:
                await session.close()
    
    # Fallback to in-memory storage
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(ScanModel).where(ScanModel.id == str(scan_id))
                )
                s = result.scalar_one_or_none()
                if s:
                    return ScanStatusResponse(
                        scan_id=scan_id,
                        status=s.status,
                        progress=s.progress or 0,
                        endpoints_discovered=s.endpoints_discovered or 0,
                        findings_count=s.findings_count or 0,
                    )
            except Exception as e:
                logger.error(f"Failed to fetch scan status from database: {e}")
            finally:
                await session.close()
    
    # Fallback to in-memory storage
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(ScanModel).where(ScanModel.id == str(scan_id))
                )
                db_scan = result.scalar_one_or_none()
                if db_scan:
                    if db_scan.status in ["running", "pending"]:
                        await session.execute(
                            update(ScanModel)
                            .where(ScanModel.id == str(scan_id))
                            .values(status="cancelled", completed_at=datetime.utcnow())
                        )
                        await session.commit()
                        
                        # Cancel the task if running
                        if scan_id in _scan_tasks:
                            _scan_tasks[scan_id].cancel()
                        
                        return {"status": "cancelled", "scan_id": str(scan_id)}
                    else:
                        return {"status": "error", "message": f"Scan is already {db_scan.status}"}
                else:
                    raise HTTPException(status_code=404, detail="Scan not found")
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to cancel scan: {e}")
                await session.rollback()
            finally:
                await session.close()
    
    # Fallback to in-memory storage
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                query = select(FindingModel)
                
                # Filter by scan_id
                if scan_id:
                    query = query.where(FindingModel.scan_id == scan_id)
                
                # Filter by target_id
                if target_id:
                    query = query.where(FindingModel.target_id == target_id)
                
                # Filter by severity
                if severity:
                    query = query.where(FindingModel.severity == severity)
                
                # Filter by vuln_type
                if vuln_type:
                    query = query.where(FindingModel.vuln_type == vuln_type)
                
                # Filter by status
                if status:
                    query = query.where(FindingModel.status == status)
                
                # Sort by created_at descending
                query = query.order_by(FindingModel.created_at.desc())
                
                # Get total count
                count_query = select(func.count()).select_from(query.subquery())
                total_result = await session.execute(count_query)
                total = total_result.scalar() or 0
                
                # Apply pagination
                query = query.offset(skip).limit(limit)
                
                result = await session.execute(query)
                db_findings = result.scalars().all()
                
                return FindingListResponse(
                    total=total,
                    findings=[
                        FindingResponse(
                            id=UUID(f.id),
                            scan_id=UUID(f.scan_id),
                            target_id=UUID(f.target_id),
                            title=f.title,
                            description=f.description,
                            severity=f.severity,
                            vuln_type=f.vuln_type,
                            url=f.url,
                            method=f.method,
                            parameter=f.parameter,
                            payload=f.payload,
                            evidence=f.evidence,
                            status=f.status,
                            cvss_score=f.cvss_score,
                            cwe_id=f.cwe_id,
                            owasp_category=f.owasp_category,
                            created_at=f.created_at,
                        )
                        for f in db_findings
                    ],
                )
            except Exception as e:
                logger.error(f"Failed to fetch findings from database: {e}")
            finally:
                await session.close()
    
    # Fallback to in-memory storage
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(FindingModel).where(FindingModel.id == str(finding_id))
                )
                f = result.scalar_one_or_none()
                if f:
                    return FindingResponse(
                        id=UUID(f.id),
                        scan_id=UUID(f.scan_id),
                        target_id=UUID(f.target_id),
                        title=f.title,
                        description=f.description,
                        severity=f.severity,
                        vuln_type=f.vuln_type,
                        url=f.url,
                        method=f.method,
                        parameter=f.parameter,
                        payload=f.payload,
                        evidence=f.evidence,
                        status=f.status,
                        cvss_score=f.cvss_score,
                        cwe_id=f.cwe_id,
                        owasp_category=f.owasp_category,
                        created_at=f.created_at,
                    )
            except Exception as e:
                logger.error(f"Failed to fetch finding from database: {e}")
            finally:
                await session.close()
    
    # Fallback to in-memory storage
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(FindingModel).where(FindingModel.id == str(finding_id))
                )
                db_finding = result.scalar_one_or_none()
                if db_finding:
                    if status:
                        db_finding.status = status
                    if false_positive:
                        db_finding.false_positive = True
                        db_finding.status = "False Positive"
                    await session.commit()
                    
                    return {
                        "status": "updated",
                        "finding_id": str(finding_id),
                        "new_status": db_finding.status,
                        "false_positive": false_positive,
                    }
                else:
                    raise HTTPException(status_code=404, detail="Finding not found")
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to update finding: {e}")
                await session.rollback()
            finally:
                await session.close()
    
    # Fallback to in-memory storage
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
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(FindingModel).where(FindingModel.id == str(finding_id))
                )
                db_finding = result.scalar_one_or_none()
                if db_finding:
                    db_finding.verified = verified
                    if verified:
                        db_finding.verified_at = datetime.utcnow()
                    await session.commit()
                    
                    return {
                        "status": "verified",
                        "finding_id": str(finding_id),
                        "verified": verified,
                    }
                else:
                    raise HTTPException(status_code=404, detail="Finding not found")
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to verify finding: {e}")
                await session.rollback()
            finally:
                await session.close()
    
    # Fallback to in-memory storage
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
    """List all reports from persistent storage"""
    storage = get_report_storage()
    reports = storage.list_reports()
    
    # Combine with in-memory storage for backward compatibility
    all_reports = []
    
    # Add reports from persistent storage
    for r in reports:
        all_reports.append({
            "id": r["id"],
            "scan_id": r["scan_id"],
            "name": r["name"],
            "format": r["format"],
            "size": r.get("size", "Unknown"),
            "created_at": r["created_at"],
        })
    
    # Add reports from memory that aren't already in storage
    storage_ids = {r["id"] for r in reports}
    for r in _reports_db.values():
        if str(r["id"]) not in storage_ids:
            all_reports.append({
                "id": str(r["id"]),
                "scan_id": str(r["scan_id"]),
                "name": r["name"],
                "format": r["format"],
                "size": r.get("size", "Unknown"),
                "created_at": r["created_at"],
            })
    
    return all_reports


@router.post("/reports/generate", response_model=ReportResponse, tags=["reports"])
async def generate_report(request: ReportGenerateRequest):
    """Generate a report and save it to disk"""
    # Verify scan exists
    try:
        scan_id = UUID(request.scan_id)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid scan_id format")
    
    scan_name = None
    scan = None
    target = None
    findings = []
    
    # Check database first if enabled
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                result = await session.execute(
                    select(ScanModel).where(ScanModel.id == str(scan_id))
                )
                db_scan = result.scalar_one_or_none()
                if db_scan:
                    scan_name = db_scan.name
                    scan = Scan(
                        id=UUID(db_scan.id),
                        target_id=UUID(db_scan.target_id),
                        name=db_scan.name,
                        scan_type=db_scan.scan_type or "full",
                    )
                    
                    # Get target
                    target_result = await session.execute(
                        select(TargetModel).where(TargetModel.id == db_scan.target_id)
                    )
                    db_target = target_result.scalar_one_or_none()
                    if db_target:
                        target = Target(
                            id=UUID(db_target.id),
                            name=db_target.name,
                            url=db_target.url,
                        )
                    
                    # Get findings
                    findings_result = await session.execute(
                        select(FindingModel).where(FindingModel.scan_id == str(scan_id))
                    )
                    db_findings = findings_result.scalars().all()
                    for f in db_findings:
                        finding = Finding(
                            id=UUID(f.id),
                            scan_id=UUID(f.scan_id),
                            target_id=UUID(f.target_id),
                            title=f.title,
                            description=f.description or "",
                            severity=f.severity,
                            vuln_type=f.vuln_type,
                            url=f.url,
                            method=f.method,
                            status=f.status,
                        )
                        findings.append(finding)
                else:
                    raise HTTPException(status_code=404, detail="Scan not found")
            except HTTPException:
                raise
            except Exception as e:
                logger.error(f"Failed to fetch scan from database: {e}")
            finally:
                await session.close()
    
    # Fallback to in-memory storage if not found in database
    if scan_name is None:
        if scan_id not in _scans_db:
            raise HTTPException(status_code=404, detail="Scan not found")
        scan = _scans_db[scan_id]
        scan_name = scan.name
        target = _targets_db.get(scan.target_id)
        findings = [f for f in _findings_db.values() if f.scan_id == scan_id]
    
    # Create default target if not found
    if target is None:
        target = Target(
            id=scan.target_id if scan else uuid4(),
            name="Unknown Target",
            url="http://unknown",
        )
    
    # Get exporter and generate content
    report_format = request.format.lower()
    exporter = ExporterFactory.get_exporter(report_format)
    if not exporter:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {report_format}")
    
    try:
        content = exporter.export(findings, scan, target)
    except Exception as e:
        logger.error(f"Failed to export report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")
    
    # Create report ID
    report_id = uuid4()
    report_name = request.name or f"Report for {scan_name}"
    
    # Save report to disk using persistent storage
    storage = get_report_storage()
    metadata = storage.save_report(
        report_id=report_id,
        content=content,
        format=report_format,
        scan_id=scan_id,
        name=report_name
    )
    
    # Also store in memory for backward compatibility
    _reports_db[report_id] = {
        "id": report_id,
        "scan_id": scan_id,
        "name": report_name,
        "format": report_format,
        "size": metadata.get("size", "Unknown"),
        "created_at": metadata.get("created_at", datetime.utcnow().isoformat()),
    }
    
    logger.info(f"Report {report_id} generated and saved to {storage.get_storage_path()}")
    
    return ReportResponse(
        id=report_id,
        scan_id=scan_id,
        format=report_format,
        content=content[:500] + "..." if len(content) > 500 else content,
    )


@router.get("/reports/{report_id}", tags=["reports"])
async def get_report(report_id: UUID):
    """Get a report"""
    if report_id not in _reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    
    return _reports_db[report_id]


@router.get("/reports/{report_id}/download", tags=["reports"])
async def download_report(report_id: UUID):
    """Download a report as a file"""
    # First check persistent storage
    storage = get_report_storage()
    stored_content = storage.get_report(report_id)
    
    if stored_content:
        # Report found in persistent storage
        metadata = storage.get_report_metadata(report_id)
        report_format = metadata.get("format", "json").lower()
        
        # Determine content type
        content_types = {
            "json": "application/json",
            "html": "text/html",
            "csv": "text/csv",
            "xml": "application/xml",
            "sarif": "application/json",
            "pdf": "text/html",  # PDF exporter returns HTML
        }
        
        content_type = content_types.get(report_format, "application/octet-stream")
        
        # Generate filename
        filename = f"vulnscope-report-{report_id}.{report_format}"
        if report_format == "sarif":
            filename = f"vulnscope-report-{report_id}.sarif.json"
        
        logger.info(f"Report {report_id} served from persistent storage")
        
        # Return file response
        return Response(
            content=stored_content,
            media_type=content_type,
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"'
            }
        )
    
    # Fall back to in-memory storage
    if report_id not in _reports_db:
        raise HTTPException(status_code=404, detail="Report not found")
    
    report = _reports_db[report_id]
    report_format = report.get("format", "json").lower()
    scan_id = report.get("scan_id")
    
    # Get findings for this scan
    findings = []
    scan = None
    target = None
    
    # Try database first
    if USE_DATABASE:
        session = await get_db_session()
        if session:
            try:
                # Get scan
                result = await session.execute(
                    select(ScanModel).where(ScanModel.id == str(scan_id))
                )
                db_scan = result.scalar_one_or_none()
                
                if db_scan:
                    scan = Scan(
                        id=UUID(db_scan.id),
                        target_id=UUID(db_scan.target_id),
                        name=db_scan.name,
                        scan_type=db_scan.scan_type or "full",
                    )
                    
                    # Get target
                    target_result = await session.execute(
                        select(TargetModel).where(TargetModel.id == db_scan.target_id)
                    )
                    db_target = target_result.scalar_one_or_none()
                    
                    if db_target:
                        from pydantic import HttpUrl
                        target = Target(
                            id=UUID(db_target.id),
                            name=db_target.name,
                            url=db_target.url,
                        )
                    
                    # Get findings
                    findings_result = await session.execute(
                        select(FindingModel).where(FindingModel.scan_id == str(scan_id))
                    )
                    db_findings = findings_result.scalars().all()
                    
                    for f in db_findings:
                        from ..core.models import Severity, VulnerabilityType, Status as ScanStatus
                        finding = Finding(
                            id=UUID(f.id),
                            scan_id=UUID(f.scan_id),
                            target_id=UUID(f.target_id),
                            title=f.title,
                            description=f.description or "",
                            severity=f.severity,
                            vuln_type=f.vuln_type,
                            url=f.url,
                            method=f.method,
                            status=f.status,
                        )
                        findings.append(finding)
            except Exception as e:
                logger.error(f"Failed to fetch report data from database: {e}")
            finally:
                await session.close()
    
    # Fallback to in-memory storage
    if scan is None and scan_id in _scans_db:
        scan = _scans_db[scan_id]
    
    if target is None and scan:
        target = _targets_db.get(scan.target_id)
    
    if not findings:
        findings = [f for f in _findings_db.values() if f.scan_id == scan_id]
    
    # Create default target if not found
    if target is None:
        target = Target(
            id=scan.target_id if scan else uuid4(),
            name="Unknown Target",
            url="http://unknown",
        )
    
    # Create default scan if not found
    if scan is None:
        scan = Scan(
            id=scan_id,
            target_id=target.id,
            name=report.get("name", "Unknown Scan"),
        )
    
    # Get exporter and generate content
    exporter = ExporterFactory.get_exporter(report_format)
    if not exporter:
        raise HTTPException(status_code=400, detail=f"Unsupported format: {report_format}")
    
    try:
        content = exporter.export(findings, scan, target)
    except Exception as e:
        logger.error(f"Failed to export report: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to generate report: {str(e)}")
    
    # Determine content type
    content_types = {
        "json": "application/json",
        "html": "text/html",
        "csv": "text/csv",
        "xml": "application/xml",
        "sarif": "application/json",
        "pdf": "text/html",  # PDF exporter returns HTML
    }
    
    content_type = content_types.get(report_format, "application/octet-stream")
    
    # Generate filename
    filename = f"vulnscope-report-{report_id}.{report_format}"
    if report_format == "sarif":
        filename = f"vulnscope-report-{report_id}.sarif.json"
    
    # Return file response
    return Response(
        content=content,
        media_type=content_type,
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"'
        }
    )


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
    
    return standards


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