"""
VulnScope - Report Exporters
Export findings in various formats (JSON, XML, HTML, SARIF, CSV)
"""

import json
import csv
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from io import StringIO

from ..core.models import Finding, Scan, Target, Severity, Report


class Exporter(ABC):
    """Base class for exporters"""
    
    @property
    @abstractmethod
    def format(self) -> str:
        """Return export format"""
        pass
    
    @abstractmethod
    def export(self, findings: List[Finding], scan: Scan, 
               target: Target) -> str:
        """Export findings to string"""
        pass
    
    def export_to_file(self, findings: List[Finding], scan: Scan,
                      target: Target, output_path: str) -> str:
        """Export findings to file"""
        content = self.export(findings, scan, target)
        
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        
        with open(path, 'w') as f:
            f.write(content)
        
        return content


class JSONExporter(Exporter):
    """Export findings as JSON"""
    
    @property
    def format(self) -> str:
        return "json"
    
    def export(self, findings: List[Finding], scan: Scan, 
               target: Target) -> str:
        """Export findings as JSON"""
        report_data = {
            "report": {
                "id": str(scan.id),
                "title": scan.name,
                "generated_at": datetime.utcnow().isoformat(),
                "generated_by": "VulnScope",
            },
            "target": {
                "id": str(target.id),
                "name": target.name,
                "url": str(target.url),
            },
            "scan": {
                "id": str(scan.id),
                "scan_type": scan.scan_type,
                "status": scan.status.value,
                "started_at": scan.started_at.isoformat() if scan.started_at else None,
                "completed_at": scan.completed_at.isoformat() if scan.completed_at else None,
            },
            "summary": {
                "total_findings": len(findings),
                "by_severity": {
                    "critical": len([f for f in findings if f.severity == Severity.CRITICAL]),
                    "high": len([f for f in findings if f.severity == Severity.HIGH]),
                    "medium": len([f for f in findings if f.severity == Severity.MEDIUM]),
                    "low": len([f for f in findings if f.severity == Severity.LOW]),
                    "info": len([f for f in findings if f.severity == Severity.INFO]),
                }
            },
            "findings": [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "description": f.description,
                    "severity": f.severity.value,
                    "vulnerability_type": f.vulnerability_type.value,
                    "status": f.status.value,
                    "cwe_id": f.cwe_id,
                    "cve_id": f.cve_id,
                    "remediation": f.remediation,
                    "evidence": f.evidence,
                    "discovered_at": f.discovered_at.isoformat() if f.discovered_at else None,
                }
                for f in findings
            ]
        }
        
        return json.dumps(report_data, indent=2)


class XMLExporter(Exporter):
    """Export findings as XML"""
    
    @property
    def format(self) -> str:
        return "xml"
    
    def export(self, findings: List[Finding], scan: Scan, 
               target: Target) -> str:
        """Export findings as XML"""
        root = ET.Element("vulnscope-report")
        
        # Add metadata
        metadata = ET.SubElement(root, "metadata")
        ET.SubElement(metadata, "id").text = str(scan.id)
        ET.SubElement(metadata, "title").text = scan.name
        ET.SubElement(metadata, "generated_at").text = datetime.utcnow().isoformat()
        
        # Add target
        target_elem = ET.SubElement(root, "target")
        ET.SubElement(target_elem, "id").text = str(target.id)
        ET.SubElement(target_elem, "name").text = target.name
        ET.SubElement(target_elem, "url").text = str(target.url)
        
        # Add summary
        summary = ET.SubElement(root, "summary")
        ET.SubElement(summary, "total").text = str(len(findings))
        
        severities = ET.SubElement(summary, "by_severity")
        for sev in Severity:
            count = len([f for f in findings if f.severity == sev])
            ET.SubElement(severities, sev.value).text = str(count)
        
        # Add findings
        findings_elem = ET.SubElement(root, "findings")
        
        for finding in findings:
            finding_elem = ET.SubElement(findings_elem, "finding")
            ET.SubElement(finding_elem, "id").text = str(finding.id)
            ET.SubElement(finding_elem, "title").text = finding.title
            ET.SubElement(finding_elem, "description").text = finding.description
            ET.SubElement(finding_elem, "severity").text = finding.severity.value
            ET.SubElement(finding_elem, "type").text = finding.vulnerability_type.value
            ET.SubElement(finding_elem, "cwe_id").text = finding.cwe_id or ""
            ET.SubElement(finding_elem, "cve_id").text = finding.cve_id or ""
            ET.SubElement(finding_elem, "remediation").text = finding.remediation or ""
            
            if finding.evidence:
                evidence_elem = ET.SubElement(finding_elem, "evidence")
                for key, value in finding.evidence.items():
                    ET.SubElement(evidence_elem, key).text = str(value)
        
        # Pretty print
        xml_str = ET.tostring(root, encoding='unicode')
        
        # Add XML declaration and formatting
        return '<?xml version="1.0" encoding="UTF-8"?>\n' + self._prettify(xml_str)
    
    def _prettify(self, xml_str: str) -> str:
        """Prettify XML string"""
        try:
            root = ET.fromstring(xml_str)
            return ET.tostring(root, encoding='unicode', pretty_print=True)
        except:
            return xml_str


class HTMLExporter(Exporter):
    """Export findings as HTML"""
    
    @property
    def format(self) -> str:
        return "html"
    
    def export(self, findings: List[Finding], scan: Scan, 
               target: Target) -> str:
        """Export findings as HTML"""
        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnScope Report - {scan.name}</title>
    <style>
        body {{
            font-family: Arial, sans-serif;
            margin: 0;
            padding: 20px;
            background-color: #f5f5f5;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: white;
            padding: 30px;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        h1 {{
            color: #333;
            border-bottom: 3px solid #007bff;
            padding-bottom: 10px;
        }}
        h2 {{
            color: #555;
            margin-top: 30px;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin: 20px 0;
        }}
        .stat-card {{
            padding: 20px;
            border-radius: 8px;
            text-align: center;
        }}
        .stat-card.critical {{
            background-color: #dc3545;
            color: white;
        }}
        .stat-card.high {{
            background-color: #fd7e14;
            color: white;
        }}
        .stat-card.medium {{
            background-color: #ffc107;
            color: black;
        }}
        .stat-card.low {{
            background-color: #28a745;
            color: white;
        }}
        .stat-card.info {{
            background-color: #17a2b8;
            color: white;
        }}
        .stat-value {{
            font-size: 36px;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 14px;
            text-transform: uppercase;
        }}
        .finding {{
            border: 1px solid #ddd;
            border-radius: 8px;
            padding: 20px;
            margin: 15px 0;
            background-color: white;
        }}
        .finding.critical {{
            border-left: 5px solid #dc3545;
        }}
        .finding.high {{
            border-left: 5px solid #fd7e14;
        }}
        .finding.medium {{
            border-left: 5px solid #ffc107;
        }}
        .finding.low {{
            border-left: 5px solid #28a745;
        }}
        .finding.info {{
            border-left: 5px solid #17a2b8;
        }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 10px;
        }}
        .finding-title {{
            font-size: 18px;
            font-weight: bold;
            color: #333;
        }}
        .severity-badge {{
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: bold;
            text-transform: uppercase;
        }}
        .severity-badge.critical {{
            background-color: #dc3545;
            color: white;
        }}
        .severity-badge.high {{
            background-color: #fd7e14;
            color: white;
        }}
        .severity-badge.medium {{
            background-color: #ffc107;
            color: black;
        }}
        .severity-badge.low {{
            background-color: #28a745;
            color: white;
        }}
        .severity-badge.info {{
            background-color: #17a2b8;
            color: white;
        }}
        .finding-meta {{
            color: #666;
            font-size: 12px;
            margin-top: 10px;
        }}
        .code-block {{
            background-color: #f8f9fa;
            padding: 10px;
            border-radius: 4px;
            font-family: monospace;
            overflow-x: auto;
            margin: 10px 0;
        }}
        .footer {{
            text-align: center;
            margin-top: 40px;
            color: #666;
            font-size: 12px;
        }}
    </style>
</head>
<body>
    <div class="container">
        <h1>VulnScope Security Report</h1>
        <p><strong>Target:</strong> {target.name} ({target.url})</p>
        <p><strong>Scan:</strong> {scan.name}</p>
        <p><strong>Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
        
        <h2>Summary</h2>
        <div class="summary">
            <div class="stat-card critical">
                <div class="stat-value">{len([f for f in findings if f.severity == Severity.CRITICAL])}</div>
                <div class="stat-label">Critical</div>
            </div>
            <div class="stat-card high">
                <div class="stat-value">{len([f for f in findings if f.severity == Severity.HIGH])}</div>
                <div class="stat-label">High</div>
            </div>
            <div class="stat-card medium">
                <div class="stat-value">{len([f for f in findings if f.severity == Severity.MEDIUM])}</div>
                <div class="stat-label">Medium</div>
            </div>
            <div class="stat-card low">
                <div class="stat-value">{len([f for f in findings if f.severity == Severity.LOW])}</div>
                <div class="stat-label">Low</div>
            </div>
            <div class="stat-card info">
                <div class="stat-value">{len([f for f in findings if f.severity == Severity.INFO])}</div>
                <div class="stat-label">Info</div>
            </div>
        </div>
        
        <h2>Findings</h2>
"""
        
        # Add findings
        for finding in findings:
            severity_class = finding.severity.value.lower()
            html += f"""
        <div class="finding {severity_class}">
            <div class="finding-header">
                <span class="finding-title</span>
                <span class="sever">{finding.title}ity-badge {severity_class}">{finding.severity.value}</span>
            </div>
            <p><strong>Type:</strong> {finding.vulnerability_type.value}</p>
            <p>{finding.description}</p>
"""
            if finding.evidence:
                html += f"""
            <p><strong>Evidence:</strong></p>
            <div class="code-block">{finding.evidence.get('payload', 'N/A')}</div>
"""
            if finding.remediation:
                html += f"""
            <p><strong>Remediation:</strong> {finding.remediation}</p>
"""
            if finding.cwe_id:
                html += f"""
            <p><strong>CWE:</strong> {finding.cwe_id}</p>
"""
            html += """
        </div>
"""
        
        html += f"""
        <div class="footer">
            <p>Generated by VulnScope - {datetime.utcnow().year}</p>
        </div>
    </div>
</body>
</html>
"""
        
        return html


class SARIFExporter(Exporter):
    """Export findings as SARIF (Static Analysis Results Interchange Format)"""
    
    @property
    def format(self) -> str:
        return "sarif"
    
    def export(self, findings: List[Finding], scan: Scan, 
               target: Target) -> str:
        """Export findings as SARIF"""
        sarif = {
            "version": "2.1.0",
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
            "runs": [
                {
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
                            "ruleIndex": i,
                            "level": self._map_severity_to_sarif_level(f.severity),
                            "message": {
                                "text": f.title
                            },
                            "locations": [
                                {
                                    "physicalLocation": {
                                        "artifactLocation": {
                                            "uri": str(target.url),
                                        },
                                    }
                                }
                            ],
                        }
                        for i, f in enumerate(findings)
                    ]
                }
            ]
        }
        
        return json.dumps(sarif, indent=2)
    
    def _map_severity_to_sarif_level(self, severity: Severity) -> str:
        """Map severity to SARIF level"""
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping.get(severity, "note")


class CSVExporter(Exporter):
    """Export findings as CSV"""
    
    @property
    def format(self) -> str:
        return "csv"
    
    def export(self, findings: List[Finding], scan: Scan, 
               target: Target) -> str:
        """Export findings as CSV"""
        output = StringIO()
        writer = csv.writer(output)
        
        # Write header
        writer.writerow([
            "ID", "Title", "Description", "Severity", "Type",
            "Status", "CWE", "CVE", "Remediation", "Discovered At"
        ])
        
        # Write findings
        for finding in findings:
            writer.writerow([
                str(finding.id),
                finding.title,
                finding.description.replace('\n', ' '),
                finding.severity.value,
                finding.vulnerability_type.value,
                finding.status.value,
                finding.cwe_id or "",
                finding.cve_id or "",
                finding.remediation or "",
                finding.discovered_at.isoformat() if finding.discovered_at else "",
            ])
        
        return output.getvalue()


# Export factory
class ExporterFactory:
    """Factory for creating exporters"""
    
    _exporters = {
        "json": JSONExporter,
        "xml": XMLExporter,
        "html": HTMLExporter,
        "sarif": SARIFExporter,
        "csv": CSVExporter,
    }
    
    @classmethod
    def get_exporter(cls, format: str) -> Optional[Exporter]:
        """Get exporter for format"""
        exporter_class = cls._exporters.get(format.lower())
        if exporter_class:
            return exporter_class()
        return None
    
    @classmethod
    def get_supported_formats(cls) -> List[str]:
        """Get list of supported formats"""
        return list(cls._exporters.keys())
