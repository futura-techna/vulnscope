"""
VulnScope - CI/CD Integrations
GitHub, GitLab, Jenkins integrations for security gates
"""

import os
import json
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
import requests

from ..core.models import Finding, Scan, Severity


class CIAdapter(ABC):
    """Base class for CI/CD integrations"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return CI/CD system name"""
        pass
    
    @abstractmethod
    def create_check(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create a check/run in CI/CD system"""
        pass
    
    @abstractmethod
    def add_gate(self, scan: Scan, findings: List[Finding]) -> bool:
        """Add security gate to pipeline"""
        pass


class GitHubIntegration(CIAdapter):
    """GitHub Actions integration"""
    
    def __init__(self, token: Optional[str] = None, owner: Optional[str] = None, 
                 repo: Optional[str] = None):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.owner = owner or os.getenv("GITHUB_OWNER")
        self.repo = repo or os.getenv("GITHUB_REPO")
        self.api_url = "https://api.github.com"
    
    @property
    def name(self) -> str:
        return "GitHub"
    
    def create_check(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create GitHub check"""
        if not self.token or not self.owner or not self.repo:
            return {"error": "Missing GitHub configuration"}
        
        # Count findings by severity
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        medium = len([f for f in findings if f.severity == Severity.MEDIUM])
        
        # Determine conclusion
        if critical > 0:
            conclusion = "failure"
        elif high > 0:
            conclusion = "failure"
        else:
            conclusion = "success"
        
        # Build output
        output = {
            "title": f"Security Scan Results - {critical} Critical, {high} High",
            "summary": f"VulnScope found {len(findings)} vulnerabilities",
            "text": self._format_findings(findings),
        }
        
        # This would create a check run in real implementation
        return {
            "status": "created",
            "conclusion": conclusion,
            "output": output,
            "url": f"{self.api_url}/repos/{self.owner}/{self.repo}/runs",
        }
    
    def add_gate(self, scan: Scan, findings: List[Finding]) -> bool:
        """Add security gate to GitHub Actions"""
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        
        # Fail if critical or high vulnerabilities found
        return not (critical > 0 or high > 0)
    
    def _format_findings(self, findings: List[Finding]) -> str:
        """Format findings for GitHub output"""
        lines = ["## Vulnerability Findings\n"]
        
        # Group by severity
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            sev_findings = [f for f in findings if f.severity == severity]
            if sev_findings:
                lines.append(f"\n### {severity.value} ({len(sev_findings)})\n")
                for f in sev_findings[:10]:  # Limit to 10 per severity
                    lines.append(f"- {f.title} ({f.vulnerability_type.value})\n")
        
        return "".join(lines)


class GitLabIntegration(CIAdapter):
    """GitLab CI/CD integration"""
    
    def __init__(self, token: Optional[str] = None, project_id: Optional[str] = None):
        self.token = token or os.getenv("GITLAB_TOKEN")
        self.project_id = project_id or os.getenv("GITLAB_PROJECT_ID")
        self.api_url = os.getenv("GITLAB_API_URL", "https://gitlab.com/api/v4")
    
    @property
    def name(self) -> str:
        return "GitLab"
    
    def create_check(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create GitLab security report"""
        if not self.token:
            return {"error": "Missing GitLab token"}
        
        # Generate security report in GitLab format
        report = {
            "scan": {
                "type": "vulnscope",
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "finished_at": scan.completed_at.isoformat() if scan.completed_at else None,
            },
            "vulnerabilities": [
                {
                    "id": str(f.id),
                    "name": f.title,
                    "description": f.description,
                    "severity": f.severity.value.lower(),
                    "confidence": "certain",
                    "url": f.evidence.get("url", ""),
                }
                for f in findings
            ],
        }
        
        return {
            "status": "created",
            "report": report,
        }
    
    def add_gate(self, scan: Scan, findings: List[Finding]) -> bool:
        """Add security gate to GitLab CI"""
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        
        return not (critical > 0 or high > 0)


class JenkinsIntegration(CIAdapter):
    """Jenkins integration"""
    
    def __init__(self, url: Optional[str] = None, user: Optional[str] = None,
                 token: Optional[str] = None):
        self.url = url or os.getenv("JENKINS_URL")
        self.user = user or os.getenv("JENKINS_USER")
        self.token = token or os.getenv("JENKINS_TOKEN")
    
    @property
    def name(self) -> str:
        return "Jenkins"
    
    def create_check(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create Jenkins build check"""
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        
        # Generate JSON report
        report = {
            "scan_id": str(scan.id),
            "target": str(scan.target_id),
            "status": "failure" if (critical > 0 or high > 0) else "success",
            "findings": {
                "critical": critical,
                "high": high,
                "medium": len([f for f in findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in findings if f.severity == Severity.LOW]),
            },
            "vulnerabilities": [
                {
                    "title": f.title,
                    "severity": f.severity.value,
                    "type": f.vulnerability_type.value,
                }
                for f in findings
            ],
        }
        
        return {
            "status": "created",
            "report": report,
        }
    
    def add_gate(self, scan: Scan, findings: List[Finding]) -> bool:
        """Add security gate to Jenkins pipeline"""
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        
        return not (critical > 0 or high > 0)


class AzureDevOpsIntegration(CIAdapter):
    """Azure DevOps integration"""
    
    def __init__(self, token: Optional[str] = None, organization: Optional[str] = None,
                 project: Optional[str] = None):
        self.token = token or os.getenv("AZURE_DEVOPS_TOKEN")
        self.organization = organization or os.getenv("AZURE_DEVOPS_ORG")
        self.project = project or os.getenv("AZURE_DEVOPS_PROJECT")
        self.api_url = f"https://dev.azure.com/{self.organization}/{self.project}/_apis"
    
    @property
    def name(self) -> str:
        return "Azure DevOps"
    
    def create_check(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create Azure DevOps security task"""
        if not self.token or not self.organization or not self.project:
            return {"error": "Missing Azure DevOps configuration"}
        
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        
        # Generate security work item
        work_item = {
            "fields": {
                "System.Title": f"Security Scan: {scan.name}",
                "System.Description": self._build_description(findings),
                "System.WorkItemType": "Bug",
                "Microsoft.VSTS.Common.Priority": 1 if critical > 0 else 2,
            }
        }
        
        return {
            "status": "created",
            "work_item": work_item,
            "url": f"{self.api_url}/wit/workitems",
        }
    
    def add_gate(self, scan: Scan, findings: List[Finding]) -> bool:
        """Add security gate to Azure DevOps pipeline"""
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        
        return not (critical > 0 or high > 0)
    
    def _build_description(self, findings: List[Finding]) -> str:
        lines = ["## VulnScope Security Scan Results\n"]
        for severity in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW]:
            count = len([f for f in findings if f.severity == severity])
            if count > 0:
                lines.append(f"- **{severity.value}:** {count}")
        return "\n".join(lines)


class GitHubAdvancedSecurityIntegration(CIAdapter):
    """GitHub Advanced Security integration"""
    
    def __init__(self, token: Optional[str] = None, owner: Optional[str] = None,
                 repo: Optional[str] = None):
        self.token = token or os.getenv("GITHUB_TOKEN")
        self.owner = owner or os.getenv("GITHUB_OWNER")
        self.repo = repo or os.getenv("GITHUB_REPO")
        self.api_url = "https://api.github.com"
    
    @property
    def name(self) -> str:
        return "GitHub Advanced Security"
    
    def create_check(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create GitHub Advanced Security alert"""
        if not self.token:
            return {"error": "Missing GitHub token"}
        
        # Create SARIF report for GitHub Advanced Security
        sarif_report = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "VulnScope",
                        "version": "1.0.0",
                        "informationUri": "https://vulnscope.io",
                    }
                },
                "results": [
                    {
                        "ruleId": f.vulnerability_type.value,
                        "level": "error" if f.severity == Severity.CRITICAL else "warning",
                        "message": {"text": f.title},
                        "locations": [{
                            "physicalLocation": {
                                "artifactLocation": {"uri": f.evidence.get("url", "")}
                            }
                        }]
                    }
                    for f in findings
                ]
            }]
        }
        
        return {
            "status": "created",
            "sarif_report": sarif_report,
            "total_alerts": len(findings),
        }
    
    def add_gate(self, scan: Scan, findings: List[Finding]) -> bool:
        """Add security gate with GitHub Advanced Security"""
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        
        return not (critical > 0 or high > 0)


class SecurityGate:
    """Security gate for CI/CD pipelines"""
    
    def __init__(self):
        self.ci_adapters: Dict[str, CIAdapter] = {}
    
    def register_adapter(self, name: str, adapter: CIAdapter):
        """Register a CI/CD adapter"""
        self.ci_adapters[name.lower()] = adapter
    
    def evaluate_gate(self, scan: Scan, findings: List[Finding],
                    config: Dict[str, Any]) -> bool:
        """
        Evaluate security gate
        
        Args:
            scan: Scan object
            findings: List of findings
            config: Gate configuration
            
        Returns:
            True if gate passes, False otherwise
        """
        # Get thresholds from config
        critical_threshold = config.get("critical_threshold", 0)
        high_threshold = config.get("high_threshold", 0)
        medium_threshold = config.get("medium_threshold", 10)
        
        # Count findings
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        medium = len([f for f in findings if f.severity == Severity.MEDIUM])
        
        # Check thresholds
        if critical > critical_threshold:
            return False
        if high > high_threshold:
            return False
        if medium > medium_threshold:
            return False
        
        return True
    
    def get_blocking_findings(self, findings: List[Finding]) -> List[Finding]:
        """Get findings that would block a gate"""
        blocking = []
        
        for finding in findings:
            if finding.severity in [Severity.CRITICAL, Severity.HIGH]:
                blocking.append(finding)
        
        return blocking
    
    def generate_gate_config(self) -> Dict[str, Any]:
        """Generate default gate configuration"""
        return {
            "critical_threshold": 0,
            "high_threshold": 0,
            "medium_threshold": 10,
            "low_threshold": 50,
            "block_on_critical": True,
            "block_on_high": True,
        }
