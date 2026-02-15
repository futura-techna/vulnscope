"""
VulnScope - ITSM Integrations
ServiceNow, Jira integrations for ticket management
"""

import os
import json
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
import requests

from ..core.models import Finding, Scan, Severity


class ITSMAdapter(ABC):
    """Base class for ITSM integrations"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return ITSM system name"""
        pass
    
    @abstractmethod
    def create_ticket(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create a ticket in ITSM system"""
        pass
    
    @abstractmethod
    def update_ticket(self, ticket_id: str, status: str) -> Dict[str, Any]:
        """Update ticket status"""
        pass


class JiraIntegration(ITSMAdapter):
    """Jira integration for ticket creation"""
    
    def __init__(self, url: Optional[str] = None, user: Optional[str] = None,
                 token: Optional[str] = None, project_key: Optional[str] = None):
        self.url = url or os.getenv("JIRA_URL")
        self.user = user or os.getenv("JIRA_USER")
        self.token = token or os.getenv("JIRA_TOKEN")
        self.project_key = project_key or os.getenv("JIRA_PROJECT_KEY")
    
    @property
    def name(self) -> str:
        return "Jira"
    
    def create_ticket(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create Jira ticket for scan results"""
        if not all([self.url, self.user, self.token, self.project_key]):
            return {"error": "Missing Jira configuration"}
        
        # Group findings by severity
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high = [f for f in findings if f.severity == Severity.HIGH]
        
        # Build description
        description = self._build_description(scan, findings)
        
        # Determine priority
        priority = "Highest" if critical else "High" if high else "Medium"
        
        # Build ticket data
        ticket_data = {
            "fields": {
                "project": {"key": self.project_key},
                "summary": f"Security Scan: {scan.name} - {len(findings)} findings",
                "description": description,
                "issuetype": {"name": "Task"},
                "priority": {"name": priority},
                "labels": ["vulnscope", "security"],
            }
        }
        
        # This would create ticket in real implementation
        return {
            "status": "created",
            "ticket_key": f"{self.project_key}-1234",
            "ticket_url": f"{self.url}/browse/{self.project_key}-1234",
            "findings_count": len(findings),
            "critical_count": len(critical),
            "high_count": len(high),
        }
    
    def update_ticket(self, ticket_id: str, status: str) -> Dict[str, Any]:
        """Update Jira ticket status"""
        if not all([self.url, self.user, self.token]):
            return {"error": "Missing Jira configuration"}
        
        # This would update ticket in real implementation
        return {
            "status": "updated",
            "ticket_id": ticket_id,
            "new_status": status,
        }
    
    def _build_description(self, scan: Scan, findings: List[Finding]) -> str:
        """Build Jira ticket description"""
        lines = [
            "h2. VulnScope Security Scan Results",
            "",
            f"*Scan:* {scan.name}",
            f"*Target:* {scan.target_id}",
            f"*Total Findings:* {len(findings)}",
            "",
        ]
        
        # Add severity breakdown
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = len([f for f in findings if f.severity == severity])
            if count > 0:
                lines.append(f"*{severity.value}:* {count}")
        
        lines.append("")
        lines.append("h3. Critical & High Findings")
        lines.append("")
        
        # Add critical/high findings
        for finding in findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                lines.append(f"* {finding.title}")
                lines.append(f"** Type: {finding.vulnerability_type.value}")
                lines.append(f"** Severity: {finding.severity.value}")
                if finding.cwe_id:
                    lines.append(f"** CWE: {finding.cwe_id}")
                lines.append("")
        
        return "\n".join(lines)
    
    def create_findings_tickets(self, scan: Scan, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Create individual tickets for critical/high findings"""
        tickets = []
        
        for finding in findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                ticket = self.create_ticket(scan, [finding])
                tickets.append(ticket)
        
        return tickets


class ServiceNowIntegration(ITSMAdapter):
    """ServiceNow integration for ticket creation"""
    
    def __init__(self, instance: Optional[str] = None, user: Optional[str] = None,
                 password: Optional[str] = None, table: Optional[str] = None):
        self.instance = instance or os.getenv("SERVICENOW_INSTANCE")
        self.user = user or os.getenv("SERVICENOW_USER")
        self.password = password or os.getenv("SERVICENOW_PASSWORD")
        self.table = table or "incident"
        self.api_url = f"https://{self.instance}.service-now.com/api/now/table"
    
    @property
    def name(self) -> str:
        return "ServiceNow"
    
    def create_ticket(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create ServiceNow incident"""
        if not all([self.instance, self.user, self.password]):
            return {"error": "Missing ServiceNow configuration"}
        
        # Group findings by severity
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high = [f for f in findings if f.severity == Severity.HIGH]
        
        # Determine impact and urgency
        impact = 1 if critical else 2 if high else 3
        urgency = 1 if critical else 2 if high else 3
        
        # Build description
        description = self._build_description(scan, findings)
        
        # Build ticket data
        ticket_data = {
            "short_description": f"Security Scan: {scan.name} - {len(findings)} vulnerabilities",
            "description": description,
            "impact": impact,
            "urgency": urgency,
            "category": "Software",
            "subcategory": "Vulnerability",
            "cmdb_ci": str(scan.target_id),
        }
        
        # This would create ticket in real implementation
        return {
            "status": "created",
            "ticket_number": "INC0012345",
            "ticket_url": f"https://{self.instance}.service-now.com/nav_to.do?uri=incident.do?sys_id=xxx",
            "findings_count": len(findings),
        }
    
    def update_ticket(self, ticket_id: str, status: str) -> Dict[str, Any]:
        """Update ServiceNow ticket"""
        if not all([self.instance, self.user, self.password]):
            return {"error": "Missing ServiceNow configuration"}
        
        # This would update ticket in real implementation
        return {
            "status": "updated",
            "ticket_id": ticket_id,
            "new_status": status,
        }
    
    def _build_description(self, scan: Scan, findings: List[Finding]) -> str:
        """Build ServiceNow ticket description"""
        lines = [
            "VulnScope Security Scan Results",
            "=" * 50,
            "",
            f"Scan: {scan.name}",
            f"Target: {scan.target_id}",
            f"Date: {scan.started_at}",
            "",
            "Summary:",
            f"- Critical: {len([f for f in findings if f.severity == Severity.CRITICAL])}",
            f"- High: {len([f for f in findings if f.severity == Severity.HIGH])}",
            f"- Medium: {len([f for f in findings if f.severity == Severity.MEDIUM])}",
            f"- Low: {len([f for f in findings if f.severity == Severity.LOW])}",
            "",
            "Findings:",
        ]
        
        # Add findings
        for finding in findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                lines.append("")
                lines.append(f"Title: {finding.title}")
                lines.append(f"Type: {finding.vulnerability_type.value}")
                lines.append(f"Severity: {finding.severity.value}")
                if finding.cwe_id:
                    lines.append(f"CWE: {finding.cwe_id}")
                lines.append(f"Description: {finding.description}")
                if finding.remediation:
                    lines.append(f"Remediation: {finding.remediation}")
        
        return "\n".join(lines)
    
    def create_findings_tickets(self, scan: Scan, findings: List[Finding]) -> List[Dict[str, Any]]:
        """Create individual tickets for critical/high findings"""
        tickets = []
        
        # Group by severity
        critical = [f for f in findings if f.severity == Severity.CRITICAL]
        high = [f for f in findings if f.severity == Severity.HIGH]
        
        # Create one ticket for critical, one for high
        if critical:
            ticket = self.create_ticket(scan, critical)
            tickets.append(ticket)
        
        if high:
            ticket = self.create_ticket(scan, high)
            tickets.append(ticket)
        
        return tickets


class TicketManager:
    """Manage tickets across ITSM systems"""
    
    def __init__(self):
        self.adapters: Dict[str, ITSMAdapter] = {}
    
    def register_adapter(self, name: str, adapter: ITSMAdapter):
        """Register an ITSM adapter"""
        self.adapters[name.lower()] = adapter
    
    def create_tickets(self, scan: Scan, findings: List[Finding],
                      system: str = "jira") -> Dict[str, Any]:
        """Create ticket in specified ITSM system"""
        adapter = self.adapters.get(system.lower())
        
        if not adapter:
            return {"error": f"Unknown ITSM system: {system}"}
        
        return adapter.create_ticket(scan, findings)
    
    def create_auto_tickets(self, scan: Scan, findings: List[Finding],
                          config: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Automatically create tickets based on configuration"""
        tickets = []
        
        # Get systems from config
        systems = config.get("systems", ["jira"])
        
        for system in systems:
            ticket = self.create_tickets(scan, findings, system)
            tickets.append(ticket)
        
        return tickets
