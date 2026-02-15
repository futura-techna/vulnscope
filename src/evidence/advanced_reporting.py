"""
VulnScope - Advanced Reporting Features
Advanced reporting: PDF export, trend analysis, vulnerability correlation, executive reports
"""

import json
import io
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
from datetime import datetime, timedelta
from abc import ABC, abstractmethod
from collections import defaultdict

from ..core.models import Finding, Scan, Target, Severity


# PDF Export using reportlab
try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle,
        PageBreak, Image as RLImage
    )
    from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False


@dataclass
class TrendData:
    """Data for trend analysis"""
    date: datetime
    count: int
    severity: Severity


@dataclass
class VulnerabilityRelation:
    """Relationship between vulnerabilities"""
    source_id: str
    target_id: str
    relation_type: str  # "similar", "same_component", "chained"


class PDFExporter:
    """
    Export findings as PDF report
    
    Features:
    - Professional PDF layout
    - Charts and graphs
    - Executive summary
    - Detailed findings
    """
    
    def __init__(self):
        self.styles = getSampleStyleSheet() if PDF_AVAILABLE else None
    
    def export(self, findings: List[Finding], scan: Scan,
               target: Target) -> bytes:
        """
        Export findings as PDF
        
        Args:
            findings: List of findings
            scan: Scan information
            target: Target information
            
        Returns:
            PDF bytes
        """
        if not PDF_AVAILABLE:
            raise ImportError("reportlab is required for PDF export")
        
        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter,
                                rightMargin=72, leftMargin=72,
                                topMargin=72, bottomMargin=18)
        
        # Build document
        story = []
        
        # Title
        title_style = ParagraphStyle(
            'CustomTitle',
            parent=self.styles['Heading1'],
            fontSize=24,
            textColor=colors.HexColor('#1a1a1a'),
            spaceAfter=30,
            alignment=TA_CENTER
        )
        story.append(Paragraph("VulnScope Security Report", title_style))
        story.append(Spacer(1, 20))
        
        # Summary
        story.extend(self._create_summary(findings, scan, target))
        story.append(Spacer(1, 20))
        
        # Findings by severity
        story.extend(self._create_severity_table(findings))
        story.append(Spacer(1, 20))
        
        # Detailed findings
        story.extend(self._create_detailed_findings(findings))
        
        # Build PDF
        doc.build(story)
        
        return buffer.getvalue()
    
    def _create_summary(self, findings: List[Finding], scan: Scan,
                       target: Target) -> List:
        """Create executive summary"""
        story = []
        
        # Target info
        story.append(Paragraph("Executive Summary", self.styles['Heading2']))
        story.append(Spacer(1, 10))
        
        summary_data = [
            ["Target", str(target.url)],
            ["Scan Name", scan.name],
            ["Scan Date", scan.started_at.strftime('%Y-%m-%d %H:%M') if scan.started_at else "N/A"],
            ["Total Findings", str(len(findings))],
        ]
        
        # Add severity counts
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = len([f for f in findings if f.severity == sev])
            summary_data.append([sev.value.upper(), str(count)])
        
        t = Table(summary_data, colWidths=[2*inch, 4*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        
        return story
    
    def _create_severity_table(self, findings: List[Finding]) -> List:
        """Create severity distribution table"""
        story = []
        
        story.append(Paragraph("Findings by Severity", self.styles['Heading2']))
        story.append(Spacer(1, 10))
        
        severity_counts = defaultdict(int)
        for f in findings:
            severity_counts[f.severity] += 1
        
        table_data = [["Severity", "Count", "Percentage"]]
        total = len(findings) or 1
        
        for sev in [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]:
            count = severity_counts[sev]
            pct = (count / total) * 100
            table_data.append([sev.value.upper(), str(count), f"{pct:.1f}%"])
        
        t = Table(table_data, colWidths=[2*inch, 1.5*inch, 1.5*inch])
        t.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.darkblue),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('PADDING', (0, 0), (-1, -1), 6),
        ]))
        story.append(t)
        
        return story
    
    def _create_detailed_findings(self, findings: List[Finding]) -> List:
        """Create detailed findings section"""
        story = []
        
        story.append(Paragraph("Detailed Findings", self.styles['Heading2']))
        story.append(Spacer(1, 10))
        
        # Sort by severity
        sorted_findings = sorted(
            findings,
            key=lambda f: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO].index(f.severity)
        )
        
        for i, finding in enumerate(sorted_findings, 1):
            # Finding title
            story.append(Paragraph(
                f"{i}. {finding.title}",
                self.styles['Heading3']
            ))
            
            # Severity badge
            severity_text = f"<b>{finding.severity.value.upper()}</b>"
            story.append(Paragraph(severity_text))
            story.append(Spacer(1, 5))
            
            # Details
            details = [
                ["Type", finding.vulnerability_type.value],
                ["Status", finding.status.value],
                ["CWE", finding.cwe_id or "N/A"],
                ["Description", finding.description[:200] + "..." if len(finding.description) > 200 else finding.description],
            ]
            
            t = Table(details, colWidths=[1.5*inch, 4.5*inch])
            t.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (0, -1), colors.lightgrey),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.grey),
                ('PADDING', (0, 0), (-1, -1), 4),
            ]))
            story.append(t)
            story.append(Spacer(1, 15))
        
        return story


class TrendAnalyzer:
    """
    Analyze vulnerability trends over time
    
    Features:
    - Track vulnerabilities over time
    - Identify patterns
    - Calculate risk trends
    """
    
    def __init__(self):
        self.historical_data: List[TrendData] = []
    
    def add_scan_results(self, findings: List[Finding], scan_date: datetime):
        """Add scan results to historical data"""
        for f in findings:
            self.historical_data.append(TrendData(
                date=scan_date,
                count=1,
                severity=f.severity
            ))
    
    def get_trend(self, days: int = 30) -> Dict[str, Any]:
        """
        Get vulnerability trend for specified period
        
        Args:
            days: Number of days to analyze
            
        Returns:
            Trend analysis
        """
        cutoff = datetime.utcnow() - timedelta(days=days)
        recent_data = [d for d in self.historical_data if d.date >= cutoff]
        
        if not recent_data:
            return {"message": "No data available"}
        
        # Group by date
        by_date = defaultdict(lambda: defaultdict(int))
        for d in recent_data:
            by_date[d.date.date()][d.severity] += 1
        
        # Calculate trends
        dates = sorted(by_date.keys())
        if len(dates) < 2:
            return {
                "data": list(by_date.items()),
                "total_findings": len(recent_data),
                "period_days": days,
                "dates_analyzed": len(dates)
            }
        
        first_half = dates[:len(dates)//2]
        second_half = dates[len(dates)//2:]
        
        first_count = sum(sum(by_date[d].values()) for d in first_half)
        second_count = sum(sum(by_date[d].values()) for d in second_half)
        
        trend_direction = "increasing" if second_count > first_count else "decreasing"
        change_pct = abs((second_count - first_count) / first_count * 100) if first_count else 0
        
        return {
            "period_days": days,
            "total_findings": len(recent_data),
            "trend_direction": trend_direction,
            "change_percentage": change_pct,
            "data": {str(k): dict(v) for k, v in by_date.items()},
            "dates_analyzed": len(dates)
        }
    
    def get_severity_trends(self) -> Dict[str, List[Dict]]:
        """Get severity-specific trends"""
        trends = {}
        
        for severity in Severity:
            severity_data = [
                {
                    "date": d.date,
                    "count": sum(1 for x in self.historical_data 
                               if x.date == d.date and x.severity == severity)
                }
                for d in self.historical_data
            ]
            trends[severity.value] = severity_data
        
        return trends


class VulnerabilityCorrelator:
    """
    Correlate vulnerabilities to identify patterns and chains
    
    Features:
    - Find similar vulnerabilities
    - Identify vulnerability chains
    - Group by components
    """
    
    def __init__(self):
        self.correlations: List[VulnerabilityRelation] = []
    
    def correlate(self, findings: List[Finding]) -> Dict[str, Any]:
        """
        Find correlations between vulnerabilities
        
        Args:
            findings: List of findings
            
        Returns:
            Correlation analysis
        """
        correlations = {
            "similar": self._find_similar(findings),
            "chained": self._find_chains(findings),
            "by_component": self._group_by_component(findings),
            "by_cwe": self._group_by_cwe(findings)
        }
        
        return correlations
    
    def _find_similar(self, findings: List[Finding]) -> List[Dict]:
        """Find similar vulnerabilities"""
        similar = []
        
        for i, f1 in enumerate(findings):
            for f2 in findings[i+1:]:
                # Check if similar type
                if f1.vulnerability_type == f2.vulnerability_type:
                    # Check if same endpoint (compare UUIDs)
                    if f1.endpoint_id and f2.endpoint_id and f1.endpoint_id == f2.endpoint_id:
                        similar.append({
                            "type": "same_endpoint",
                            "vuln1": str(f1.id),
                            "vuln2": str(f2.id)
                        })
        
        return similar
    
    def _find_chains(self, findings: List[Finding]) -> List[Dict]:
        """Find potential vulnerability chains"""
        chains = []
        
        # Common attack chains
        chain_patterns = [
            # Information disclosure -> Auth bypass -> Data exfiltration
            (["INFORMATION_DISCLOSURE", "AUTH_BYPASS"], "auth_bypass_chain"),
            # XSS -> CSRF -> Session hijacking
            (["XSS", "CSRF"], "session_hijack_chain"),
            # SSRF -> Internal recon -> RCE
            (["SSRF", "COMMAND_INJECTION"], "rce_chain"),
        ]
        
        vuln_types = {f.vulnerability_type.value for f in findings}
        
        for pattern, chain_name in chain_patterns:
            if all(vt in vuln_types for vt in pattern):
                chains.append({
                    "name": chain_name,
                    "pattern": pattern,
                    "risk": "high"
                })
        
        return chains
    
    def _group_by_component(self, findings: List[Finding]) -> Dict[str, List[str]]:
        """Group vulnerabilities by component"""
        components = defaultdict(list)
        
        for f in findings:
            # Extract component from endpoint
            endpoint_id = f.endpoint_id
            if endpoint_id:
                # endpoint_id is now a UUID, use the finding's title or id as component
                component = str(endpoint_id)[:8]  # Use first 8 chars of UUID
            else:
                component = "unknown"
            components[component].append(str(f.id))
        
        return dict(components)
    
    def _group_by_cwe(self, findings: List[Finding]) -> Dict[str, List[str]]:
        """Group vulnerabilities by CWE"""
        cwe_groups = defaultdict(list)
        
        for f in findings:
            if f.cwe_id:
                cwe_groups[f.cwe_id].append(str(f.id))
        
        return dict(cwe_groups)


class ExecutiveReportGenerator:
    """
    Generate executive-level reports
    
    Features:
    - High-level summary
    - Risk metrics
    - Recommendations
    - Non-technical language
    """
    
    def generate(self, findings: List[Finding], scan: Scan,
                 target: Target) -> Dict[str, Any]:
        """
        Generate executive report
        
        Args:
            findings: List of findings
            scan: Scan information
            target: Target information
            
        Returns:
            Executive report data
        """
        
        # Calculate risk score
        risk_score = self._calculate_risk_score(findings)
        
        # Get top issues
        top_issues = self._get_top_issues(findings)
        
        # Generate recommendations
        recommendations = self._generate_recommendations(findings)
        
        # Calculate compliance impact
        compliance_impact = self._calculate_compliance_impact(findings)
        
        return {
            "report_date": datetime.utcnow().isoformat(),
            "target": {
                "name": target.name,
                "url": str(target.url)
            },
            "scan_info": {
                "name": scan.name,
                "date": scan.started_at.isoformat() if scan.started_at else None,
                "type": scan.scan_type
            },
            "executive_summary": {
                "total_findings": len(findings),
                "risk_score": risk_score,
                "risk_level": self._get_risk_level(risk_score),
                "critical_issues": len([f for f in findings if f.severity == Severity.CRITICAL]),
                "high_issues": len([f for f in findings if f.severity == Severity.HIGH]),
                "remediation_estimate": self._estimate_remediation_time(findings)
            },
            "top_issues": top_issues,
            "recommendations": recommendations,
            "compliance_impact": compliance_impact
        }
    
    def _calculate_risk_score(self, findings: List[Finding]) -> float:
        """Calculate overall risk score (0-100)"""
        if not findings:
            return 0
        
        weights = {
            Severity.CRITICAL: 10,
            Severity.HIGH: 7,
            Severity.MEDIUM: 4,
            Severity.LOW: 2,
            Severity.INFO: 1
        }
        
        total_weight = sum(weights.get(f.severity, 1) for f in findings)
        max_weight = len(findings) * 10
        
        return round((total_weight / max_weight) * 100, 1)
    
    def _get_risk_level(self, score: float) -> str:
        """Get risk level from score"""
        if score >= 80:
            return "Critical"
        elif score >= 60:
            return "High"
        elif score >= 40:
            return "Medium"
        elif score >= 20:
            return "Low"
        else:
            return "Minimal"
    
    def _get_top_issues(self, findings: List[Finding], limit: int = 5) -> List[Dict]:
        """Get top issues by severity"""
        sorted_findings = sorted(
            findings,
            key=lambda f: [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO].index(f.severity)
        )
        
        return [
            {
                "title": f.title,
                "severity": f.severity.value,
                "type": f.vulnerability_type.value,
                "cwe": f.cwe_id
            }
            for f in sorted_findings[:limit]
        ]
    
    def _generate_recommendations(self, findings: List[Finding]) -> List[str]:
        """Generate recommendations based on findings"""
        recommendations = []
        
        # Group by vulnerability type
        vuln_types = defaultdict(int)
        for f in findings:
            vuln_types[f.vulnerability_type] += 1
        
        # Generate specific recommendations
        if vuln_types.get("XSS"):
            recommendations.append(
                "Implement Content Security Policy (CSP) headers and input validation"
            )
        
        if vuln_types.get("SQL_INJECTION"):
            recommendations.append(
                "Use parameterized queries or ORM for all database operations"
            )
        
        if vuln_types.get("AUTH_BYPASS"):
            recommendations.append(
                "Implement multi-factor authentication and review authorization logic"
            )
        
        if vuln_types.get("SSRF"):
            recommendations.append(
                "Validate and sanitize all URL inputs, restrict internal network access"
            )
        
        if not recommendations:
            recommendations.append("Continue regular security assessments")
        
        return recommendations
    
    def _calculate_compliance_impact(self, findings: List[Finding]) -> Dict[str, str]:
        """Calculate compliance impact"""
        impact = {}
        
        critical_count = len([f for f in findings if f.severity == Severity.CRITICAL])
        high_count = len([f for f in findings if f.severity == Severity.HIGH])
        
        # PCI-DSS
        if critical_count > 0:
            impact["PCI-DSS"] = "Non-compliant - Critical vulnerabilities found"
        elif high_count > 5:
            impact["PCI-DSS"] = "At risk - Multiple high issues"
        else:
            impact["PCI-DSS"] = "Compliant"
        
        # HIPAA
        if critical_count > 0:
            impact["HIPAA"] = "Breach risk - PHI may be exposed"
        else:
            impact["HIPAA"] = "Compliant"
        
        # SOC2
        if high_count > 0:
            impact["SOC2"] = "Control failure risk"
        else:
            impact["SOC2"] = "Compliant"
        
        return impact
    
    def _estimate_remediation_time(self, findings: List[Finding]) -> str:
        """Estimate remediation time"""
        critical = len([f for f in findings if f.severity == Severity.CRITICAL])
        high = len([f for f in findings if f.severity == Severity.HIGH])
        medium = len([f for f in findings if f.severity == Severity.MEDIUM])
        
        hours = (critical * 4) + (high * 2) + (medium * 1)
        
        if hours > 40:
            return f"~{hours // 8} days"
        elif hours > 8:
            return f"~{hours} hours"
        else:
            return f"~{hours} hours"


# Export factory
class AdvancedExporterFactory:
    """Factory for advanced exporters"""
    
    @staticmethod
    def get_pdf_exporter() -> Optional[PDFExporter]:
        """Get PDF exporter"""
        if PDF_AVAILABLE:
            return PDFExporter()
        return None
    
    @staticmethod
    def get_trend_analyzer() -> TrendAnalyzer:
        """Get trend analyzer"""
        return TrendAnalyzer()
    
    @staticmethod
    def get_correlator() -> VulnerabilityCorrelator:
        """Get vulnerability correlator"""
        return VulnerabilityCorrelator()
    
    @staticmethod
    def get_executive_generator() -> ExecutiveReportGenerator:
        """Get executive report generator"""
        return ExecutiveReportGenerator()
