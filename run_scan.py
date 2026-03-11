#!/usr/bin/env python3
"""
VulnScope - Security Scan Runner
Analyse de sécurité complète d'une URL cible
"""

import sys
import json
from datetime import datetime
from urllib.parse import urlparse
import requests
from uuid import uuid4

# Check for BeautifulSoup
try:
    from bs4 import BeautifulSoup
    HAS_BS4 = True
except ImportError:
    HAS_BS4 = False


def print_banner():
    """Print VulnScope banner"""
    print("""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║   ██╗   ██╗██╗   ██╗███╗   ██╗███████╗██████╗               ║
║   ██║   ██║██║   ██║████╗  ██║██╔════╝██╔══██╗               ║
║   ██║   ██║██║   ██║██╔██╗ ██║█████╗  ██████╔╝               ║
║   ╚██╗ ██╔╝██║   ██║██║╚██╗██║██╔══╝  ██╔══██╗               ║
║    ╚████╔╝ ╚██████╔╝██║ ╚████║███████╗██║  ██║               ║
║     ╚═══╝   ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═╝  ╚═╝               ║
║                                                              ║
║   Dynamic Application Security Testing Platform              ║
║   Version 1.0.0                                              ║
╚══════════════════════════════════════════════════════════════╝
""")


def check_url_accessible(url: str) -> dict:
    """Check if URL is accessible and gather basic info"""
    print(f"\n[*] Vérification de l'accessibilité de {url}")
    
    result = {
        'accessible': False,
        'status_code': None,
        'headers': {},
        'server': None,
        'technologies': [],
        'error': None
    }
    
    try:
        response = requests.get(
            url, 
            timeout=30,
            headers={'User-Agent': 'VulnScope/1.0 Security Scanner'},
            allow_redirects=True
        )
        result['accessible'] = True
        result['status_code'] = response.status_code
        result['headers'] = dict(response.headers)
        result['server'] = response.headers.get('Server', 'Unknown')
        
        # Detect technologies from headers
        if 'x-vercel' in response.headers:
            result['technologies'].append('Vercel')
        if 'x-powered-by' in response.headers:
            result['technologies'].append(f"Powered by: {response.headers['x-powered-by']}")
        
        print(f"    ✓ URL accessible - Status: {response.status_code}")
        print(f"    ✓ Serveur: {result['server']}")
        
    except Exception as e:
        result['error'] = str(e)
        print(f"    ✗ Erreur: {e}")
    
    return result


def analyze_headers(headers: dict) -> list:
    """Analyze HTTP headers for security issues"""
    findings = []
    
    print("\n[*] Analyse des en-têtes HTTP de sécurité")
    
    # Security headers to check
    security_headers = {
        'Strict-Transport-Security': {
            'severity': 'Medium',
            'title': 'Missing HSTS Header',
            'description': 'HTTP Strict Transport Security (HSTS) header is not set. This allows downgrade attacks and cookie hijacking.',
            'owasp': 'A05:2021 - Security Misconfiguration',
            'cwe': 'CWE-319'
        },
        'Content-Security-Policy': {
            'severity': 'Medium',
            'title': 'Missing Content-Security-Policy Header',
            'description': 'Content-Security-Policy (CSP) header is not set. This increases XSS risk.',
            'owasp': 'A05:2021 - Security Misconfiguration',
            'cwe': 'CWE-1021'
        },
        'X-Content-Type-Options': {
            'severity': 'Low',
            'title': 'Missing X-Content-Type-Options Header',
            'description': 'X-Content-Type-Options header is not set. Browser may MIME-sniff content.',
            'owasp': 'A05:2021 - Security Misconfiguration',
            'cwe': 'CWE-116'
        },
        'X-Frame-Options': {
            'severity': 'Low',
            'title': 'Missing X-Frame-Options Header',
            'description': 'X-Frame-Options header is not set. Page may be vulnerable to clickjacking.',
            'owasp': 'A05:2021 - Security Misconfiguration',
            'cwe': 'CWE-1021'
        },
        'X-XSS-Protection': {
            'severity': 'Low',
            'title': 'Missing X-XSS-Protection Header',
            'description': 'X-XSS-Protection header is not set. Legacy XSS filter not enabled.',
            'owasp': 'A05:2021 - Security Misconfiguration',
            'cwe': 'CWE-79'
        },
        'Referrer-Policy': {
            'severity': 'Low',
            'title': 'Missing Referrer-Policy Header',
            'description': 'Referrer-Policy header is not set. May leak sensitive URLs.',
            'owasp': 'A05:2021 - Security Misconfiguration',
            'cwe': 'CWE-116'
        },
        'Permissions-Policy': {
            'severity': 'Low',
            'title': 'Missing Permissions-Policy Header',
            'description': 'Permissions-Policy header is not set. Browser features not restricted.',
            'owasp': 'A05:2021 - Security Misconfiguration',
            'cwe': 'CWE-1021'
        }
    }
    
    headers_lower = {k.lower(): v for k, v in headers.items()}
    
    for header, info in security_headers.items():
        if header.lower() not in headers_lower:
            findings.append({
                'id': str(uuid4()),
                'type': 'Missing Security Header',
                'severity': info['severity'],
                'title': info['title'],
                'description': info['description'],
                'owasp': info['owasp'],
                'cwe': info['cwe'],
                'remediation': f'Add {header} header to responses'
            })
            print(f"    ✗ {info['title']} [{info['severity']}]")
        else:
            print(f"    ✓ {header} présent")
    
    # Check for information disclosure
    info_headers = ['Server', 'X-Powered-By', 'X-AspNet-Version', 'X-Generator']
    for header in info_headers:
        if header in headers:
            findings.append({
                'id': str(uuid4()),
                'type': 'Information Disclosure',
                'severity': 'Info',
                'title': f'{header} Header Exposes Technology',
                'description': f'The {header} header reveals: {headers[header]}. This helps attackers target specific vulnerabilities.',
                'owasp': 'A01:2021 - Broken Access Control',
                'cwe': 'CWE-200',
                'remediation': f'Remove or obfuscate {header} header'
            })
            print(f"    ! {header} expose: {headers[header]}")
    
    return findings


def check_cookies(url: str, headers: dict) -> list:
    """Check cookie security settings"""
    findings = []
    
    print("\n[*] Analyse des cookies")
    
    if 'Set-Cookie' in headers:
        cookies = headers['Set-Cookie']
        print(f"    Cookies trouvés")
        
        # Check for Secure flag
        if 'Secure' not in cookies:
            findings.append({
                'id': str(uuid4()),
                'type': 'Cookie Security',
                'severity': 'Medium',
                'title': 'Cookie Without Secure Flag',
                'description': 'A cookie is set without the Secure flag. It can be transmitted over HTTP.',
                'owasp': 'A05:2021 - Security Misconfiguration',
                'cwe': 'CWE-614',
                'remediation': 'Add Secure flag to all cookies'
            })
            print(f"    ✗ Cookie sans flag Secure")
        
        # Check for HttpOnly flag
        if 'HttpOnly' not in cookies:
            findings.append({
                'id': str(uuid4()),
                'type': 'Cookie Security',
                'severity': 'Medium',
                'title': 'Cookie Without HttpOnly Flag',
                'description': 'A cookie is set without HttpOnly flag. It can be accessed via JavaScript.',
                'owasp': 'A05:2021 - Security Misconfiguration',
                'cwe': 'CWE-1004',
                'remediation': 'Add HttpOnly flag to session cookies'
            })
            print(f"    ✗ Cookie sans flag HttpOnly")
        
        # Check for SameSite
        if 'SameSite' not in cookies:
            findings.append({
                'id': str(uuid4()),
                'type': 'Cookie Security',
                'severity': 'Low',
                'title': 'Cookie Without SameSite Attribute',
                'description': 'A cookie is set without SameSite attribute. CSRF protection is weaker.',
                'owasp': 'A01:2021 - Broken Access Control',
                'cwe': 'CWE-1275',
                'remediation': 'Add SameSite=Strict or SameSite=Lax to cookies'
            })
            print(f"    ! Cookie sans attribut SameSite")
    else:
        print(f"    ✓ Aucun cookie défini sur la page principale")
    
    return findings


def check_ssl_tls(url: str) -> dict:
    """Check SSL/TLS configuration"""
    print("\n[*] Analyse SSL/TLS")
    
    result = {
        'https': False,
        'tls_version': None,
        'certificate_valid': False,
        'findings': []
    }
    
    parsed = urlparse(url)
    
    if parsed.scheme == 'https':
        result['https'] = True
        print(f"    ✓ HTTPS activé")
        
        # Check certificate
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((parsed.netloc, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=parsed.netloc) as ssock:
                    cert = ssock.getpeercert()
                    result['certificate_valid'] = True
                    result['tls_version'] = ssock.version()
                    print(f"    ✓ Certificat valide")
                    print(f"    ✓ TLS Version: {result['tls_version']}")
                    
        except Exception as e:
            result['findings'].append({
                'id': str(uuid4()),
                'type': 'SSL/TLS',
                'severity': 'High',
                'title': 'SSL Certificate Issue',
                'description': f'SSL certificate verification failed: {str(e)}',
                'owasp': 'A02:2021 - Cryptographic Failures',
                'cwe': 'CWE-295'
            })
            print(f"    ✗ Problème de certificat: {e}")
    else:
        result['findings'].append({
            'id': str(uuid4()),
            'type': 'SSL/TLS',
            'severity': 'High',
            'title': 'No HTTPS',
            'description': 'Site is not using HTTPS. All traffic is unencrypted.',
            'owasp': 'A02:2021 - Cryptographic Failures',
            'cwe': 'CWE-319'
        })
        print(f"    ✗ HTTPS non activé")
    
    return result


def crawl_site(url: str, max_pages: int = 20) -> dict:
    """Crawl the site to discover endpoints"""
    print(f"\n[*] Crawling du site (max {max_pages} pages)")
    
    result = {
        'pages': [],
        'endpoints': [],
        'forms': [],
        'links': [],
        'external_links': [],
        'errors': []
    }
    
    if not HAS_BS4:
        print("    ! BeautifulSoup non disponible - skip crawling")
        return result
    
    visited = set()
    to_visit = [url]
    base_domain = urlparse(url).netloc
    
    session = requests.Session()
    session.headers.update({
        'User-Agent': 'VulnScope/1.0 Security Scanner'
    })
    
    while to_visit and len(visited) < max_pages:
        current_url = to_visit.pop(0)
        
        if current_url in visited:
            continue
        
        visited.add(current_url)
        print(f"    → {current_url}")
        
        try:
            response = session.get(current_url, timeout=15, allow_redirects=True)
            
            page_info = {
                'url': current_url,
                'status': response.status_code,
                'content_type': response.headers.get('Content-Type', ''),
                'size': len(response.content)
            }
            result['pages'].append(page_info)
            
            if 'text/html' in response.headers.get('Content-Type', ''):
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Find forms
                for form in soup.find_all('form'):
                    action = form.get('action', '')
                    method = form.get('method', 'GET').upper()
                    inputs = []
                    
                    for inp in form.find_all(['input', 'textarea', 'select']):
                        inputs.append({
                            'name': inp.get('name', ''),
                            'type': inp.get('type', 'text'),
                            'value': inp.get('value', '')
                        })
                    
                    form_info = {
                        'action': action,
                        'method': method,
                        'inputs': inputs,
                        'page': current_url
                    }
                    result['forms'].append(form_info)
                    print(f"        Formulaire trouvé: {method} {action}")
                
                # Find links
                for link in soup.find_all('a', href=True):
                    href = link['href']
                    if href.startswith('#') or href.startswith('javascript:'):
                        continue
                    full_url = href if href.startswith('http') else f"{urlparse(url).scheme}://{base_domain}{href}"
                    
                    link_domain = urlparse(full_url).netloc
                    
                    if link_domain == base_domain:
                        if full_url not in visited:
                            to_visit.append(full_url)
                        result['links'].append(full_url)
                    else:
                        if full_url not in result['external_links']:
                            result['external_links'].append(full_url)
                
                # Find scripts
                for script in soup.find_all('script', src=True):
                    result['endpoints'].append({
                        'type': 'script',
                        'url': script['src'],
                        'page': current_url
                    })
                    
        except Exception as e:
            result['errors'].append({
                'url': current_url,
                'error': str(e)
            })
    
    print(f"\n    ✓ Pages crawlées: {len(result['pages'])}")
    print(f"    ✓ Formulaires trouvés: {len(result['forms'])}")
    print(f"    ✓ Liens internes: {len(result['links'])}")
    print(f"    ✓ Liens externes: {len(result['external_links'])}")
    
    return result


def check_xss(url: str) -> list:
    """Check for XSS vulnerabilities"""
    print("\n[*] Test XSS (Cross-Site Scripting)")
    
    findings = []
    
    try:
        # Test reflected XSS on error pages
        test_url = f"{url}?test=<script>alert(1)</script>"
        response = requests.get(test_url, timeout=10)
        
        if '<script>alert(1)</script>' in response.text:
            findings.append({
                'id': str(uuid4()),
                'type': 'XSS',
                'severity': 'High',
                'title': 'Reflected XSS Vulnerability',
                'description': 'User input is reflected without proper sanitization. An attacker could inject malicious scripts.',
                'url': test_url,
                'payload': '<script>alert(1)</script>',
                'owasp': 'A03:2021 - Injection',
                'cwe': 'CWE-79',
                'remediation': 'Sanitize and encode all user input before rendering'
            })
            print(f"    ✗ XSS réfléchi détecté!")
        else:
            print(f"    ✓ Pas de XSS réfléchi détecté sur la page principale")
            
    except Exception as e:
        print(f"    ! Erreur lors du test XSS: {e}")
    
    return findings


def check_security_misconfiguration(url: str, headers: dict) -> list:
    """Check for security misconfigurations"""
    print("\n[*] Vérification des configurations de sécurité")
    
    findings = []
    
    # Check for common sensitive files
    sensitive_paths = [
        '/.env',
        '/.git/config',
        '/.htaccess',
        '/web.config',
        '/robots.txt',
        '/sitemap.xml',
        '/.DS_Store',
        '/package.json',
        '/composer.json',
        '/api/',
        '/api/v1',
        '/admin',
        '/login',
        '/register',
        '/debug',
    ]
    
    print(f"    Recherche de fichiers sensibles...")
    
    for path in sensitive_paths:
        try:
            test_url = f"{url.rstrip('/')}{path}"
            response = requests.get(test_url, timeout=5, allow_redirects=False)
            
            if response.status_code == 200:
                if path in ['/.env', '/.git/config', '/.htaccess', '/web.config']:
                    findings.append({
                        'id': str(uuid4()),
                        'type': 'Sensitive File Exposure',
                        'severity': 'High',
                        'title': f'Sensitive File Exposed: {path}',
                        'description': f'The sensitive file {path} is publicly accessible.',
                        'url': test_url,
                        'owasp': 'A01:2021 - Broken Access Control',
                        'cwe': 'CWE-538',
                        'remediation': f'Restrict access to {path}'
                    })
                    print(f"    ✗ Fichier sensible exposé: {path}")
                else:
                    print(f"    → {path} (Status: 200)")
            elif response.status_code in [301, 302]:
                print(f"    → {path} (Redirect)")
                
        except:
            pass
    
    return findings


def check_cors(url: str) -> list:
    """Check CORS configuration"""
    print("\n[*] Vérification CORS")
    
    findings = []
    
    # Test CORS with various origins
    test_origins = [
        'https://evil.com',
        'http://localhost',
        'null'
    ]
    
    for origin in test_origins:
        try:
            response = requests.options(
                url,
                headers={
                    'Origin': origin,
                    'Access-Control-Request-Method': 'GET',
                    'Access-Control-Request-Headers': 'Content-Type'
                },
                timeout=10
            )
            
            cors_header = response.headers.get('Access-Control-Allow-Origin', '')
            
            if cors_header == '*':
                findings.append({
                    'id': str(uuid4()),
                    'type': 'CORS',
                    'severity': 'Medium',
                    'title': 'Overly Permissive CORS Policy',
                    'description': 'The server allows requests from any origin (Access-Control-Allow-Origin: *).',
                    'owasp': 'A01:2021 - Broken Access Control',
                    'cwe': 'CWE-942',
                    'remediation': 'Restrict CORS to trusted origins only'
                })
                print(f"    ! CORS trop permissif: *")
                break
            elif cors_header == origin or cors_header == 'null':
                findings.append({
                    'id': str(uuid4()),
                    'type': 'CORS',
                    'severity': 'Medium',
                    'title': 'CORS Reflects Origin',
                    'description': f'The server reflects the Origin header: {cors_header}',
                    'owasp': 'A01:2021 - Broken Access Control',
                    'cwe': 'CWE-942',
                    'remediation': 'Validate and whitelist allowed origins'
                })
                print(f"    ! CORS reflète l'origine: {origin}")
                
        except Exception as e:
            pass
    
    if not findings:
        print(f"    ✓ Configuration CORS correcte")
    
    return findings


def run_comprehensive_scan(target_url: str) -> dict:
    """Run comprehensive security scan"""
    print_banner()
    print(f"[*] Démarrage de l'analyse de sécurité")
    print(f"[*] Cible: {target_url}")
    print(f"[*] Date: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    
    scan_result = {
        'target': target_url,
        'scan_date': datetime.now().isoformat(),
        'findings': [],
        'statistics': {
            'total_findings': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0,
            'info': 0
        },
        'site_info': {},
        'crawl_results': {}
    }
    
    # Step 1: Check accessibility
    access_result = check_url_accessible(target_url)
    scan_result['site_info']['accessibility'] = access_result
    
    if not access_result['accessible']:
        print("\n[!] Impossible d'accéder à l'URL cible")
        return scan_result
    
    # Step 2: SSL/TLS check
    ssl_result = check_ssl_tls(target_url)
    scan_result['site_info']['ssl'] = ssl_result
    scan_result['findings'].extend(ssl_result.get('findings', []))
    
    # Step 3: Header analysis
    header_findings = analyze_headers(access_result['headers'])
    scan_result['findings'].extend(header_findings)
    
    # Step 4: Cookie analysis
    cookie_findings = check_cookies(target_url, access_result['headers'])
    scan_result['findings'].extend(cookie_findings)
    
    # Step 5: Crawl site
    crawl_result = crawl_site(target_url)
    scan_result['crawl_results'] = crawl_result
    
    # Step 6: XSS tests
    xss_findings = check_xss(target_url)
    scan_result['findings'].extend(xss_findings)
    
    # Step 7: Security misconfiguration
    config_findings = check_security_misconfiguration(target_url, access_result['headers'])
    scan_result['findings'].extend(config_findings)
    
    # Step 8: CORS check
    cors_findings = check_cors(target_url)
    scan_result['findings'].extend(cors_findings)
    
    # Calculate statistics
    for finding in scan_result['findings']:
        severity = finding.get('severity', 'Info').lower()
        if severity == 'critical':
            scan_result['statistics']['critical'] += 1
        elif severity == 'high':
            scan_result['statistics']['high'] += 1
        elif severity == 'medium':
            scan_result['statistics']['medium'] += 1
        elif severity == 'low':
            scan_result['statistics']['low'] += 1
        else:
            scan_result['statistics']['info'] += 1
    
    scan_result['statistics']['total_findings'] = len(scan_result['findings'])
    
    return scan_result


def print_results(result: dict):
    """Print formatted scan results"""
    print("\n")
    print("=" * 80)
    print("                        RAPPORT D'ANALYSE VULNSCOPE")
    print("=" * 80)
    
    print(f"\n📋 INFORMATIONS GÉNÉRALES")
    print("-" * 40)
    print(f"   URL analysée: {result['target']}")
    print(f"   Date: {result['scan_date']}")
    
    # Site info
    if 'site_info' in result:
        access = result['site_info'].get('accessibility', {})
        print(f"   Statut HTTP: {access.get('status_code', 'N/A')}")
        print(f"   Serveur: {access.get('server', 'N/A')}")
        print(f"   Technologies: {', '.join(access.get('technologies', ['Non détecté']))}")
        
        ssl = result['site_info'].get('ssl', {})
        print(f"   HTTPS: {'✓ Activé' if ssl.get('https') else '✗ Non activé'}")
        print(f"   TLS: {ssl.get('tls_version', 'N/A')}")
    
    # Statistics
    stats = result['statistics']
    print(f"\n📊 STATISTIQUES")
    print("-" * 40)
    print(f"   Total des findings: {stats['total_findings']}")
    print(f"   ┌─────────────────────────────────────┐")
    print(f"   │ Critical: {stats['critical']:3d}                      │")
    print(f"   │ High:     {stats['high']:3d}                      │")
    print(f"   │ Medium:   {stats['medium']:3d}                      │")
    print(f"   │ Low:      {stats['low']:3d}                      │")
    print(f"   │ Info:     {stats['info']:3d}                      │")
    print(f"   └─────────────────────────────────────┘")
    
    # Crawl results
    crawl = result.get('crawl_results', {})
    if crawl:
        print(f"\n🔍 RÉSULTATS DU CRAWLING")
        print("-" * 40)
        print(f"   Pages découvertes: {len(crawl.get('pages', []))}")
        print(f"   Formulaires: {len(crawl.get('forms', []))}")
        print(f"   Liens internes: {len(crawl.get('links', []))}")
        print(f"   Liens externes: {len(crawl.get('external_links', []))}")
    
    # Detailed findings
    if result['findings']:
        print(f"\n🔴 VULNÉRABILITÉS ET PROBLÈMES DÉTECTÉS")
        print("=" * 80)
        
        # Sort by severity
        severity_order = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3, 'info': 4}
        sorted_findings = sorted(
            result['findings'], 
            key=lambda x: severity_order.get(x.get('severity', 'info').lower(), 5)
        )
        
        for i, finding in enumerate(sorted_findings, 1):
            severity = finding.get('severity', 'Info')
            severity_icons = {
                'Critical': '🔴',
                'High': '🟠',
                'Medium': '🟡',
                'Low': '🔵',
                'Info': '⚪'
            }
            icon = severity_icons.get(severity, '⚪')
            
            print(f"\n   [{i}] {icon} {finding.get('title', 'Unknown')}")
            print(f"       Type: {finding.get('type', 'N/A')}")
            print(f"       Sévérité: {severity}")
            print(f"       OWASP: {finding.get('owasp', 'N/A')}")
            print(f"       CWE: {finding.get('cwe', 'N/A')}")
            print(f"       Description: {finding.get('description', 'N/A')}")
            if finding.get('url'):
                print(f"       URL: {finding.get('url')}")
            if finding.get('remediation'):
                print(f"       Remédiation: {finding.get('remediation')}")
    else:
        print(f"\n✅ Aucune vulnérabilité majeure détectée!")
    
    # Risk score
    stats = result['statistics']
    risk_score = 100 - (stats['critical'] * 25 + stats['high'] * 10 + stats['medium'] * 5 + stats['low'] * 1)
    risk_score = max(0, min(100, risk_score))
    
    print(f"\n📈 SCORE DE SÉCURITÉ")
    print("-" * 40)
    
    if risk_score >= 90:
        grade = 'A'
        color = '🟢'
    elif risk_score >= 80:
        grade = 'B'
        color = '🟢'
    elif risk_score >= 70:
        grade = 'C'
        color = '🟡'
    elif risk_score >= 60:
        grade = 'D'
        color = '🟠'
    else:
        grade = 'F'
        color = '🔴'
    
    print(f"   Score: {risk_score}/100")
    print(f"   Note: {color} {grade}")
    
    print("\n" + "=" * 80)
    print("                         FIN DU RAPPORT VULNSCOPE")
    print("=" * 80 + "\n")


def main():
    """Main entry point"""
    target_url = "https://maths-plus-plus.vercel.app/"
    
    # Run scan
    result = run_comprehensive_scan(target_url)
    
    # Print results
    print_results(result)
    
    # Save to JSON
    output_file = "/home/cisse/vulnscope/scan_results.json"
    with open(output_file, 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2, ensure_ascii=False, default=str)
    
    print(f"📄 Résultats complets sauvegardés dans: {output_file}")
    
    return result


if __name__ == "__main__":
    main()