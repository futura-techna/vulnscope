#!/usr/bin/env python3
"""
VulnScope - Standalone Report Generator
Generate a report from scan_results.json without external dependencies
"""

import json
import sys
from datetime import datetime
from pathlib import Path


def load_scan_results(filepath: str = "scan_results.json") -> dict:
    """Load scan results from JSON file"""
    with open(filepath, 'r') as f:
        return json.load(f)


def generate_html_report(scan_data: dict) -> str:
    """Generate HTML report from scan data"""
    
    target = scan_data.get('target', 'Unknown')
    scan_date = scan_data.get('scan_date', datetime.utcnow().isoformat())
    findings = scan_data.get('findings', [])
    stats = scan_data.get('statistics', {})
    site_info = scan_data.get('site_info', {})
    
    # Severity colors
    severity_colors = {
        'Critical': '#dc3545',
        'High': '#fd7e14',
        'Medium': '#ffc107',
        'Low': '#28a745',
        'Info': '#17a2b8',
    }
    
    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>VulnScope Report - {target}</title>
    <style>
        * {{
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }}
        body {{
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            padding: 20px;
        }}
        .container {{
            max-width: 1200px;
            margin: 0 auto;
            background-color: #ffffff;
            border-radius: 16px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            overflow: hidden;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 40px;
            text-align: center;
        }}
        .header h1 {{
            font-size: 2.5em;
            margin-bottom: 10px;
            text-shadow: 2px 2px 4px rgba(0,0,0,0.2);
        }}
        .header p {{
            opacity: 0.9;
            font-size: 1.1em;
        }}
        .content {{
            padding: 40px;
        }}
        h2 {{
            color: #333;
            margin-bottom: 20px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }}
        .meta-info {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin-bottom: 30px;
        }}
        .meta-info p {{
            margin: 8px 0;
            color: #555;
        }}
        .meta-info strong {{
            color: #333;
        }}
        .summary {{
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(150px, 1fr));
            gap: 20px;
            margin: 30px 0;
        }}
        .stat-card {{
            padding: 25px;
            border-radius: 12px;
            text-align: center;
            color: white;
            box-shadow: 0 4px 15px rgba(0,0,0,0.1);
            transition: transform 0.3s ease;
        }}
        .stat-card:hover {{
            transform: translateY(-5px);
        }}
        .stat-card.critical {{ background: linear-gradient(135deg, #dc3545, #c82333); }}
        .stat-card.high {{ background: linear-gradient(135deg, #fd7e14, #e06c0d); }}
        .stat-card.medium {{ background: linear-gradient(135deg, #ffc107, #e0a800); color: #333; }}
        .stat-card.low {{ background: linear-gradient(135deg, #28a745, #218838); }}
        .stat-card.info {{ background: linear-gradient(135deg, #17a2b8, #138496); }}
        .stat-value {{
            font-size: 3em;
            font-weight: bold;
        }}
        .stat-label {{
            font-size: 0.9em;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-top: 5px;
        }}
        .findings-section {{
            margin-top: 40px;
        }}
        .finding {{
            border-radius: 12px;
            padding: 25px;
            margin: 20px 0;
            background-color: white;
            box-shadow: 0 2px 10px rgba(0,0,0,0.05);
            border-left: 5px solid #ccc;
            transition: box-shadow 0.3s ease;
        }}
        .finding:hover {{
            box-shadow: 0 5px 20px rgba(0,0,0,0.1);
        }}
        .finding.critical {{ border-left-color: #dc3545; }}
        .finding.high {{ border-left-color: #fd7e14; }}
        .finding.medium {{ border-left-color: #ffc107; }}
        .finding.low {{ border-left-color: #28a745; }}
        .finding.info {{ border-left-color: #17a2b8; }}
        .finding-header {{
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 15px;
            flex-wrap: wrap;
            gap: 10px;
        }}
        .finding-title {{
            font-size: 1.3em;
            font-weight: 600;
            color: #333;
        }}
        .severity-badge {{
            padding: 8px 20px;
            border-radius: 25px;
            font-size: 0.85em;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 1px;
            color: white;
        }}
        .severity-badge.critical {{ background-color: #dc3545; }}
        .severity-badge.high {{ background-color: #fd7e14; }}
        .severity-badge.medium {{ background-color: #ffc107; color: #333; }}
        .severity-badge.low {{ background-color: #28a745; }}
        .severity-badge.info {{ background-color: #17a2b8; }}
        .finding-body p {{
            margin: 10px 0;
            color: #555;
            line-height: 1.6;
        }}
        .finding-body strong {{
            color: #333;
        }}
        .tag {{
            display: inline-block;
            background-color: #e9ecef;
            padding: 4px 12px;
            border-radius: 15px;
            font-size: 0.85em;
            margin-right: 8px;
            color: #495057;
        }}
        .remediation {{
            background-color: #d4edda;
            border: 1px solid #c3e6cb;
            border-radius: 8px;
            padding: 15px;
            margin-top: 15px;
        }}
        .remediation-title {{
            color: #155724;
            font-weight: bold;
            margin-bottom: 8px;
        }}
        .footer {{
            text-align: center;
            padding: 30px;
            background-color: #f8f9fa;
            color: #666;
            font-size: 0.9em;
        }}
        .ssl-section, .headers-section {{
            background-color: #f8f9fa;
            padding: 20px;
            border-radius: 8px;
            margin: 20px 0;
        }}
        .check-item {{
            display: flex;
            align-items: center;
            margin: 10px 0;
        }}
        .check-item .icon {{
            margin-right: 10px;
            font-size: 1.2em;
        }}
        .check-item.success .icon {{ color: #28a745; }}
        .check-item.warning .icon {{ color: #ffc107; }}
        .check-item.error .icon {{ color: #dc3545; }}
        @media print {{
            body {{
                background: white;
                padding: 0;
            }}
            .container {{
                box-shadow: none;
            }}
            .finding {{
                page-break-inside: avoid;
            }}
        }}
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ VulnScope Security Report</h1>
            <p>Comprehensive Security Assessment</p>
        </div>
        
        <div class="content">
            <div class="meta-info">
                <p><strong>🎯 Target:</strong> {target}</p>
                <p><strong>📅 Scan Date:</strong> {scan_date}</p>
                <p><strong>📄 Generated:</strong> {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}</p>
            </div>
            
            <h2>📊 Executive Summary</h2>
            <div class="summary">
                <div class="stat-card critical">
                    <div class="stat-value">{stats.get('critical', 0)}</div>
                    <div class="stat-label">Critical</div>
                </div>
                <div class="stat-card high">
                    <div class="stat-value">{stats.get('high', 0)}</div>
                    <div class="stat-label">High</div>
                </div>
                <div class="stat-card medium">
                    <div class="stat-value">{stats.get('medium', 0)}</div>
                    <div class="stat-label">Medium</div>
                </div>
                <div class="stat-card low">
                    <div class="stat-value">{stats.get('low', 0)}</div>
                    <div class="stat-label">Low</div>
                </div>
                <div class="stat-card info">
                    <div class="stat-value">{stats.get('info', 0)}</div>
                    <div class="stat-label">Info</div>
                </div>
            </div>
            
            <h2>🔒 Security Configuration</h2>
            <div class="ssl-section">
                <h3 style="margin-bottom: 15px;">SSL/TLS Status</h3>
"""
    
    # Add SSL info
    ssl_info = site_info.get('ssl', {})
    if ssl_info:
        https_status = '✅' if ssl_info.get('https') else '❌'
        tls_version = ssl_info.get('tls_version', 'N/A')
        cert_valid = '✅ Valid' if ssl_info.get('certificate_valid') else '❌ Invalid'
        
        html += f"""
                <div class="check-item success">
                    <span class="icon">{https_status}</span>
                    <span>HTTPS: {'Enabled' if ssl_info.get('https') else 'Disabled'}</span>
                </div>
                <div class="check-item success">
                    <span class="icon">🔐</span>
                    <span>TLS Version: {tls_version}</span>
                </div>
                <div class="check-item success">
                    <span class="icon">📜</span>
                    <span>Certificate: {cert_valid}</span>
                </div>
"""
    
    html += """
            </div>
            
            <h2>🔍 Findings</h2>
            <div class="findings-section">
"""
    
    # Add findings
    for finding in findings:
        severity = finding.get('severity', 'Info')
        severity_class = severity.lower()
        color = severity_colors.get(severity, '#17a2b8')
        
        html += f"""
                <div class="finding {severity_class}">
                    <div class="finding-header">
                        <span class="finding-title">{finding.get('title', 'Unknown Finding')}</span>
                        <span class="severity-badge {severity_class}">{severity}</span>
                    </div>
                    <div class="finding-body">
                        <p><strong>Type:</strong> {finding.get('type', 'N/A')}</p>
                        <p>{finding.get('description', '')}</p>
"""
        
        if finding.get('owasp'):
            html += f"""
                        <p><span class="tag">OWASP: {finding.get('owasp')}</span></p>
"""
        
        if finding.get('cwe'):
            html += f"""
                        <p><span class="tag">CWE: {finding.get('cwe')}</span></p>
"""
        
        if finding.get('remediation'):
            html += f"""
                        <div class="remediation">
                            <div class="remediation-title">✅ Remediation</div>
                            <p>{finding.get('remediation')}</p>
                        </div>
"""
        
        html += """
                    </div>
                </div>
"""
    
    html += f"""
            </div>
        </div>
        
        <div class="footer">
            <p>Generated by VulnScope - Security Assessment Platform</p>
            <p>© {datetime.utcnow().year} VulnScope. All rights reserved.</p>
        </div>
    </div>
</body>
</html>
"""
    
    return html


def generate_json_report(scan_data: dict) -> str:
    """Generate JSON report"""
    report = {
        "report": {
            "generated_at": datetime.utcnow().isoformat(),
            "generated_by": "VulnScope",
        },
        "target": scan_data.get('target'),
        "scan_date": scan_data.get('scan_date'),
        "summary": scan_data.get('statistics', {}),
        "findings": scan_data.get('findings', []),
        "site_info": scan_data.get('site_info', {}),
    }
    return json.dumps(report, indent=2)


def generate_csv_report(scan_data: dict) -> str:
    """Generate CSV report"""
    lines = ["ID,Title,Type,Severity,Description,OWASP,CWE,Remediation"]
    
    for f in scan_data.get('findings', []):
        description = f.get('description', '').replace(',', ';').replace('\n', ' ')
        line = f"{f.get('id', '')},{f.get('title', '')},{f.get('type', '')},{f.get('severity', '')},{description},{f.get('owasp', '')},{f.get('cwe', '')},{f.get('remediation', '')}"
        lines.append(line)
    
    return '\n'.join(lines)


def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Generate VulnScope report')
    parser.add_argument('--format', '-f', choices=['json', 'html', 'csv'], 
                        default='html', help='Report format (default: html)')
    parser.add_argument('--output', '-o', default=None, help='Output file path')
    parser.add_argument('--input', '-i', default='scan_results.json', help='Input scan results file')
    
    args = parser.parse_args()
    
    # Load scan results
    print(f"📂 Loading scan results from {args.input}...")
    scan_data = load_scan_results(args.input)
    
    # Generate output path
    if args.output:
        output_path = args.output
    else:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        output_path = f"vulnscope_report_{timestamp}.{args.format}"
    
    # Generate report
    print(f"📝 Generating {args.format.upper()} report...")
    
    if args.format == 'html':
        content = generate_html_report(scan_data)
    elif args.format == 'json':
        content = generate_json_report(scan_data)
    elif args.format == 'csv':
        content = generate_csv_report(scan_data)
    
    # Save report
    with open(output_path, 'w') as f:
        f.write(content)
    
    # Print summary
    stats = scan_data.get('statistics', {})
    print(f"\n{'='*50}")
    print("📊 REPORT SUMMARY")
    print(f"{'='*50}")
    print(f"🎯 Target: {scan_data.get('target')}")
    print(f"📋 Total Findings: {stats.get('total_findings', 0)}")
    print(f"   🔴 Critical: {stats.get('critical', 0)}")
    print(f"   🟠 High: {stats.get('high', 0)}")
    print(f"   🟡 Medium: {stats.get('medium', 0)}")
    print(f"   🟢 Low: {stats.get('low', 0)}")
    print(f"   🔵 Info: {stats.get('info', 0)}")
    print(f"\n✅ Report saved to: {output_path}")
    print(f"{'='*50}")
    
    return output_path


if __name__ == '__main__':
    main()