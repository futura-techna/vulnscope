"""
VulnScope - GraphQL API
GraphQL API for VulnScope
"""

from typing import List, Optional
from datetime import datetime
from uuid import UUID, uuid4
import strawberry


@strawberry.type
class Target:
    id: UUID
    name: str
    url: str
    description: Optional[str]
    tags: List[str]
    created_at: datetime


@strawberry.type
class Endpoint:
    id: UUID
    url: str
    method: str
    path: str
    source: str


@strawberry.type
class Finding:
    id: UUID
    title: str
    description: str
    severity: str
    vulnerability_type: str
    status: str
    cwe_id: Optional[str]
    discovered_at: datetime


@strawberry.type
class Scan:
    id: UUID
    target_id: UUID
    name: str
    status: str
    scan_type: str
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    total_endpoints: int
    total_findings: int


@strawberry.type
class ScanResult:
    scan: Scan
    target: Target
    endpoints: List[Endpoint]
    findings: List[Finding]


@strawberry.type
class ComplianceResult:
    standard: str
    compliant: bool
    score: float
    violations: List[str]


@strawberry.type
class Query:
    """GraphQL Query root"""
    
    @strawberry.field
    def targets(self) -> List[Target]:
        """List all targets"""
        # In production, fetch from database
        return []
    
    @strawberry.field
    def target(self, id: UUID) -> Optional[Target]:
        """Get target by ID"""
        # In production, fetch from database
        return None
    
    @strawberry.field
    def scans(self, target_id: Optional[UUID] = None) -> List[Scan]:
        """List scans"""
        # In production, fetch from database
        return []
    
    @strawberry.field
    def scan(self, id: UUID) -> Optional[Scan]:
        """Get scan by ID"""
        # In production, fetch from database
        return None
    
    @strawberry.field
    def findings(self, scan_id: Optional[UUID] = None, 
                severity: Optional[str] = None) -> List[Finding]:
        """List findings"""
        # In production, fetch from database
        return []
    
    @strawberry.field
    def compliance(self, scan_id: UUID, standard: str) -> ComplianceResult:
        """Get compliance status"""
        # In production, calculate from findings
        return ComplianceResult(
            standard=standard,
            compliant=True,
            score=95.0,
            violations=[]
        )


@strawberry.input
class CreateTargetInput:
    name: str
    url: str
    description: Optional[str] = None
    tags: List[str] = strawberry.field(default_factory=list)


@strawberry.input
class CreateScanInput:
    target_id: UUID
    name: str
    scan_type: str = "full"


@strawberry.type
class Mutation:
    """GraphQL Mutation root"""
    
    @strawberry.mutation
    def create_target(self, input: CreateTargetInput) -> Target:
        """Create a new target"""
        # In production, save to database
        return Target(
            id=uuid4(),
            name=input.name,
            url=input.url,
            description=input.description,
            tags=input.tags,
            created_at=datetime.utcnow()
        )
    
    @strawberry.mutation
    def create_scan(self, input: CreateScanInput) -> Scan:
        """Create and start a new scan"""
        # In production, save to database and start scan
        return Scan(
            id=uuid4(),
            target_id=input.target_id,
            name=input.name,
            status="RUNNING",
            scan_type=input.scan_type,
            created_at=datetime.utcnow(),
            started_at=datetime.utcnow(),
            completed_at=None,
            total_endpoints=0,
            total_findings=0
        )
    
    @strawberry.mutation
    def cancel_scan(self, scan_id: UUID) -> bool:
        """Cancel a running scan"""
        # In production, cancel scan
        return True
    
    @strawberry.mutation
    def update_finding_status(self, finding_id: UUID, status: str) -> bool:
        """Update finding status"""
        # In production, update in database
        return True


# Create schema
schema = strawberry.Schema(query=Query, mutation=Mutation)
