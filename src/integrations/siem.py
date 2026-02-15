"""
VulnScope - SIEM Integrations
Splunk, ELK integrations for security observability
"""

import os
import json
from typing import Dict, Any, List, Optional
from abc import ABC, abstractmethod
import requests

from ..core.models import Finding, Scan, Severity


class SIEMAdapter(ABC):
    """Base class for SIEM integrations"""
    
    @property
    @abstractmethod
    def name(self) -> str:
        """Return SIEM system name"""
        pass
    
    @abstractmethod
    def send_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Send event to SIEM"""
        pass
    
    @abstractmethod
    def create_alert(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create alert in SIEM"""
        pass


class SplunkIntegration(SIEMAdapter):
    """Splunk integration for security events"""
    
    def __init__(self, url: Optional[str] = None, token: Optional[str] = None,
                 index: Optional[str] = None):
        self.url = url or os.getenv("SPLUNK_URL")
        self.token = token or os.getenv("SPLUNK_TOKEN")
        self.index = index or os.getenv("SPLUNK_INDEX", "vulnscope")
        self.hec_url = f"{self.url}/services/collector"
    
    @property
    def name(self) -> str:
        return "Splunk"
    
    def send_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Send event to Splunk HEC"""
        if not all([self.url, self.token]):
            return {"error": "Missing Splunk configuration"}
        
        # Build HEC event
        hec_event = {
            "host": "vulnscope",
            "source": "vulnscope",
            "sourcetype": "vulnscope:scan",
            "index": self.index,
            "time": int(event.get("timestamp", 0)),
            "event": event,
        }
        
        # This would send to Splunk in real implementation
        return {
            "status": "sent",
            "event_id": event.get("id", ""),
        }
    
    def create_alert(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create Splunk alert"""
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        
        # Build alert event
        alert_event = {
            "id": str(scan.id),
            "type": "security_scan",
            "timestamp": scan.started_at.isoformat() if scan.started_at else None,
            "target": str(scan.target_id),
            "scan_name": scan.name,
            "total_findings": len(findings),
            "findings": {
                "critical": critical,
                "high": high,
                "medium": len([f for f in findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in findings if f.severity == Severity.LOW]),
            },
            "status": scan.status.value,
        }
        
        # Send to Splunk
        self.send_event(alert_event)
        
        return {
            "status": "alert_created",
            "scan_id": str(scan.id),
            "critical_count": critical,
            "high_count": high,
        }
    
    def send_findings(self, findings: List[Finding]) -> Dict[str, Any]:
        """Send individual findings to Splunk"""
        sent_count = 0
        
        for finding in findings:
            event = {
                "id": str(finding.id),
                "type": "vulnerability",
                "timestamp": finding.discovered_at.isoformat() if finding.discovered_at else None,
                "finding": {
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity.value,
                    "type": finding.vulnerability_type.value,
                    "cwe_id": finding.cwe_id,
                    "cve_id": finding.cve_id,
                },
            }
            
            result = self.send_event(event)
            if result.get("status") == "sent":
                sent_count += 1
        
        return {
            "status": "completed",
            "findings_sent": sent_count,
        }


class ELKIntegration(SIEMAdapter):
    """Elasticsearch/Logstash/Kibana integration"""
    
    def __init__(self, url: Optional[str] = None, index: Optional[str] = None,
                 api_key: Optional[str] = None):
        self.url = url or os.getenv("ELASTIC_URL")
        self.index = index or os.getenv("ELASTIC_INDEX", "vulnscope")
        self.api_key = api_key or os.getenv("ELASTIC_API_KEY")
        self.elasticsearch_url = f"{self.url}/{self.index}/_doc"
    
    @property
    def name(self) -> str:
        return "ELK"
    
    def send_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Send event to Elasticsearch"""
        if not all([self.url, self.api_key]):
            return {"error": "Missing ELK configuration"}
        
        # This would send to Elasticsearch in real implementation
        return {
            "status": "indexed",
            "event_id": event.get("id", ""),
        }
    
    def create_alert(self, scan: Scan, findings: List[Finding]) -> Dict[str, Any]:
        """Create ELK alert/watch"""
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        
        # Build scan event
        scan_event = {
            "@timestamp": scan.started_at.isoformat() if scan.started_at else None,
            "event": {
                "kind": "scan",
                "type": "security",
                "category": "vulnerability",
            },
            "vulnscope": {
                "scan_id": str(scan.id),
                "target_id": str(scan.target_id),
                "scan_name": scan.name,
                "status": scan.status.value,
            },
            "findings": {
                "total": len(findings),
                "critical": critical,
                "high": high,
                "medium": len([f for f in findings if f.severity == Severity.MEDIUM]),
                "low": len([f for f in findings if f.severity == Severity.LOW]),
            },
        }
        
        # Send to Elasticsearch
        self.send_event(scan_event)
        
        return {
            "status": "alert_created",
            "scan_id": str(scan.id),
            "index": self.index,
        }
    
    def send_findings(self, findings: List[Finding]) -> Dict[str, Any]:
        """Send individual findings to Elasticsearch"""
        sent_count = 0
        
        for finding in findings:
            event = {
                "@timestamp": finding.discovered_at.isoformat() if finding.discovered_at else None,
                "event": {
                    "kind": "finding",
                    "type": "vulnerability",
                },
                "vulnscope": {
                    "finding_id": str(finding.id),
                    "title": finding.title,
                    "description": finding.description,
                    "severity": finding.severity.value,
                    "type": finding.vulnerability_type.value,
                    "cwe_id": finding.cwe_id,
                    "cve_id": finding.cve_id,
                    "remediation": finding.remediation,
                },
            }
            
            result = self.send_event(event)
            if result.get("status") == "indexed":
                sent_count += 1
        
        return {
            "status": "completed",
            "findings_indexed": sent_count,
        }
    
    def create_kibana_visualization(self) -> Dict[str, Any]:
        """Create Kibana visualization configuration"""
        vis_config = {
            "title": "VulnScope Findings",
            "type": "histogram",
            "params": {
                "series": [
                    {
                        "id": "critical",
                        "color": "#dc3545",
                        "metrics": [{"type": "count"}],
                    },
                    {
                        "id": "high",
                        "color": "#fd7e14",
                        "metrics": [{"type": "count"}],
                    },
                ],
                "axis_formatter": "number",
                "bar_color": "#6e4c13",
            },
        }
        
        return {
            "status": "created",
            "visualization": vis_config,
        }


class ObservabilityManager:
    """Manage observability across SIEM systems"""
    
    def __init__(self):
        self.adapters: Dict[str, SIEMAdapter] = {}
    
    def register_adapter(self, name: str, adapter: SIEMAdapter):
        """Register a SIEM adapter"""
        self.adapters[name.lower()] = adapter
    
    def send_to_all(self, event: Dict[str, Any]) -> Dict[str, Any]:
        """Send event to all registered SIEM systems"""
        results = {}
        
        for name, adapter in self.adapters.items():
            result = adapter.send_event(event)
            results[name] = result
        
        return results
    
    def create_scan_observability(self, scan: Scan, findings: List[Finding],
                                config: Dict[str, Any]) -> Dict[str, Any]:
        """Create observability events for a scan"""
        results = {}
        
        # Get systems from config
        systems = config.get("systems", list(self.adapters.keys()))
        
        for system in systems:
            adapter = self.adapters.get(system.lower())
            if adapter:
                result = adapter.create_alert(scan, findings)
                results[system] = result
        
        # Also send individual findings
        send_findings = config.get("send_findings", False)
        if send_findings:
            findings_results = {}
            for system in systems:
                adapter = self.adapters.get(system.lower())
                if adapter:
                    result = adapter.send_findings(findings)
                    findings_results[system] = result
            results["findings"] = findings_results
        
        return results


class WebhookNotifier:
    """Send notifications via webhooks"""
    
    def __init__(self, webhook_url: Optional[str] = None):
        self.webhook_url = webhook_url or os.getenv("WEBHOOK_URL")
    
    def send_notification(self, scan: Scan, findings: List[Finding],
                         message: str = "") -> Dict[str, Any]:
        """Send webhook notification"""
        if not self.webhook_url:
            return {"error": "Missing webhook URL"}
        
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        
        payload = {
            "text": message or f"VulnScope scan completed: {scan.name}",
            "attachments": [
                {
                    "color": "danger" if critical > 0 else "warning" if high > 0 else "good",
                    "fields": [
                        {"title": "Scan", "value": scan.name, "short": True},
                        {"title": "Target", "value": str(scan.target_id), "short": True},
                        {"title": "Findings", "value": str(len(findings)), "short": True},
                        {"title": "Critical", "value": str(critical), "short": True},
                        {"title": "High", "value": str(high), "short": True},
                    ],
                }
            ],
        }
        
        # This would send webhook in real implementation
        return {
            "status": "sent",
            "payload": payload,
        }
