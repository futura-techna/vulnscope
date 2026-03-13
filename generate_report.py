#!/usr/bin/env python3
"""
VulnScope - Report Generator
Generate a report from scan_results.json
"""

import json
import sys
from datetime import datetime
from pathlib import Path

# Add src to path
sys.path.insert(0, str(Path(__file__).parent))

from src.evidence.exporters import ExporterFactory


def load_scan_results(filepath: str = "scan_results.json") -> dict:
    """Load scan results from JSON file"""
    with open(filepath, 'r') as f:
        return json.load(f)


def create_findings_from_scan(scan_data: dict) -> list:
    """Convert scan results to finding objects"""
    from src.core.models import Finding, Severity, VulnerabilityType, Status
    from uuid import UUID
    
    findings = []
    for item in scan_data.get('findings', []):
        # Map severity
        severity_map = {
            'Critical': Severity.CRITICAL,
            'High': Severity.HIGH,
            'Medium': Severity.MEDIUM,
            'Low': Severity.LOW,
            'Info': Severity.INFO,
        }
        
        # Map vulnerability type
        vuln_type_map = {
            'Missing Security Header': VulnerabilityType.CONFIGURATION,
            'Information Disclosure': VulnerabilityType.INFO_DISCLOSURE,
            'CORS': VulnerabilityType.CORS,
            'XSS': VulnerabilityType.XSS,
            'SQL Injection': VulnerabilityType.SQLI,
            'SSRF': VulnerabilityType.SSRF,
            'IDOR': VulnerabilityType.IDOR,
            'CSRF': VulnerabilityType.CSRF,
        }
        
        finding = Finding(
            id=UUID(item['id']),
            title=item['title'],
            description=item.get('description', ''),
            severity=severity_map.get(item['severity'], Severity.INFO),
            vulnerability_type=vuln_type_map.get(item['type'], VulnerabilityType.OTHER),
            status=Status.OPEN,
            cwe_id=item.get('cwe', ''),
            remediation=item.get('remediation', ''),
        )
        findings.append(finding)
    
    return findings


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate VulnScope report')
    parser.add_argument('--format', '-f', choices=['json', 'html', 'csv', 'sarif', 'xml', 'pdf'], 
                        default='html', help='Report format (default: html)')
    parser.add_argument('--output', '-o', default=None, help='Output file path')
    parser.add_argument('--input', '-i', default='scan_results.json', help='Input scan results file')
    
    args = parser.parse_args()
    
    # Load scan results
    print(f"Loading scan results from {args.input}...")
    scan_data = load_scan_results(args.input)
    
    # Create findings
    findings = create_findings_from_scan(scan_data)
    
    # Create scan and target objects
    from src.core.models import Scan, Target
    from uuid import uuid4
    
    target = Target(
        id=uuid4(),
        name=scan_data['target'],
        url=scan_data['target'],
    )
    
    scan = Scan(
        id=uuid4(),
        target_id=target.id,
        name=f"Scan of {scan_data['target']}",
        scan_type="full",
    )
    
    # Get exporter
    exporter = ExporterFactory.get_exporter(args.format)
    if not exporter:
        print(f"Error: Unsupported format '{args.format}'")
        sys.exit(1)
    
    # Generate output path
    if args.output:
        output_path = args.output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        extension = 'sarif.json' if args.format == 'sarif' else args.format
        if args.format == 'pdf':
            extension = 'html'  # PDF exporter generates HTML
        output_path = f"vulnscope_report_{timestamp}.{extension}"
    
    # Export report
    print(f"Generating {args.format.upper()} report...")
    
    if args.format == 'pdf':
        # PDF exporter returns HTML
        content = exporter.export(findings, scan, target)
        with open(output_path, 'w') as f:
            f.write(content)
        print(f"Report saved to: {output_path}")
        print("Note: PDF format generates HTML. Use a browser to print to PDF.")
    else:
        content = exporter.export_to_file(findings, scan, target, output_path)
        print(f"Report saved to: {output_path}")
    
    # Print summary
    stats = scan_data.get('statistics', {})
    print(f"\n=== Report Summary ===")
    print(f"Target: {scan_data['target']}")
    print(f"Total Findings: {stats.get('total_findings', len(findings))}")
    print(f"  - Critical: {stats.get('critical', 0)}")
    print(f"  - High: {stats.get('high', 0)}")
    print(f"  - Medium: {stats.get('medium', 0)}")
    print(f"  - Low: {stats.get('low', 0)}")
    print(f"  - Info: {stats.get('info', 0)}")
    print(f"\nReport generated successfully: {output_path}")
    
    return output_path


if __name__ == '__main__':
    main()