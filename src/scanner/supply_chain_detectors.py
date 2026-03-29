"""
VulnScope - Software Supply Chain Security Detectors
Detectors for SCA (Software Composition Analysis), vulnerable dependencies, and supply chain security
"""

import re
import json
import xml.etree.ElementTree as ET
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set
from pathlib import Path

from ..core.models import Endpoint, Finding, Severity, VulnerabilityType, Status


class SupplyChainDetector(Detector):
    """Software Supply Chain Security detector for SCA"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.VULNERABLE_DEPENDENCY
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # Known vulnerable patterns for common packages
    VULNERABLE_PATTERNS = {
        # JavaScript/Node.js
        'lodash': {
            'versions': ['<4.17.21'],
            'cve': 'CVE-2021-23337',
            'description': 'Prototype Pollution in lodash',
        },
        'moment': {
            'versions': ['<2.29.4'],
            'cve': 'CVE-2022-31129',
            'description': 'Path traversal in moment.js',
        },
        'axios': {
            'versions': ['<0.21.1'],
            'cve': 'CVE-2020-28168',
            'description': 'SSRF in axios',
        },
        'minimist': {
            'versions': ['<1.2.6'],
            'cve': 'CVE-2021-44906',
            'description': 'Prototype Pollution in minimist',
        },
        'express': {
            'versions': ['<4.17.3'],
            'cve': 'CVE-2022-24999',
            'description': 'Open redirect in express',
        },
        'jsonwebtoken': {
            'versions': ['<9.0.0'],
            'cve': 'CVE-2022-23529',
            'description': 'JWT algorithm confusion',
        },
        # Python
        'django': {
            'versions': ['<3.2.20', '<4.1.10'],
            'cve': 'CVE-2023-36053',
            'description': 'Potential denial of service in Django',
        },
        'flask': {
            'versions': ['<2.2.5'],
            'cve': 'CVE-2023-30861',
            'description': 'Cookie exposure in Flask',
        },
        'requests': {
            'versions': ['<2.31.0'],
            'cve': 'CVE-2023-32681',
            'description': 'Unintended leak of Proxy-Authorization header',
        },
        'urllib3': {
            'versions': ['<1.26.17', '<2.0.6'],
            'cve': 'CVE-2023-43804',
            'description': 'Proxy credential leakage in urllib3',
        },
        'pillow': {
            'versions': ['<9.3.0'],
            'cve': 'CVE-2022-45198',
            'description': 'Arbitrary code execution in Pillow',
        },
        'numpy': {
            'versions': ['<1.22.0'],
            'cve': 'CVE-2021-41496',
            'description': 'Buffer overflow in numpy',
        },
        'pyyaml': {
            'versions': ['<6.0'],
            'cve': 'CVE-2020-14343',
            'description': 'Arbitrary code execution in PyYAML',
        },
        'jinja2': {
            'versions': ['<3.1.2'],
            'cve': 'CVE-2024-22195',
            'description': 'XSS in Jinja2',
        },
        # Java
        'spring-boot': {
            'versions': ['<2.7.18', '<3.0.12', '<3.1.5'],
            'cve': 'CVE-2023-20873',
            'description': 'RCE in Spring Boot',
        },
        'log4j': {
            'versions': ['<2.17.1'],
            'cve': 'CVE-2021-44228',
            'description': 'Log4Shell RCE vulnerability',
        },
        'commons-fileupload': {
            'versions': ['<1.5'],
            'cve': 'CVE-2023-24998',
            'description': 'Arbitrary file upload in Commons FileUpload',
        },
        # Go
        'yaml': {
            'versions': ['<v0.5.10'],
            'cve': 'CVE-2022-28948',
            'description': 'Unmarshal of arbitrary types in go-yaml',
        },
    }
    
    # Files to check for dependencies
    DEPENDENCY_FILES = {
        'package.json': 'npm',
        'package-lock.json': 'npm',
        'requirements.txt': 'pip',
        'Pipfile': 'pip',
        'Pipfile.lock': 'pip',
        'pom.xml': 'maven',
        'build.gradle': 'gradle',
        'go.mod': 'go',
        'go.sum': 'go',
        'Gemfile': 'ruby',
        'Gemfile.lock': 'ruby',
        'Cargo.toml': 'rust',
        'composer.json': 'php',
    }
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect supply chain vulnerabilities"""
        findings = []
        
        # This detector works on dependency files, not endpoints
        # In a real implementation, this would parse package files
        # For now, we return an empty list as it requires file access
        
        return findings
    
    def detect_from_file(self, file_path: str, content: str) -> List[Finding]:
        """Detect vulnerabilities from dependency file content"""
        findings = []
        
        file_name = Path(file_path).name.lower()
        package_manager = self.DEPENDENCY_FILES.get(file_name)
        
        if not package_manager:
            return findings
        
        if package_manager == 'npm':
            findings.extend(self._check_npm_dependencies(content))
        elif package_manager == 'pip':
            findings.extend(self._check_pip_dependencies(content))
        elif package_manager == 'maven':
            findings.extend(self._check_maven_dependencies(content))
        elif package_manager == 'go':
            findings.extend(self._check_go_dependencies(content))
        
        return findings
    
    def _check_npm_dependencies(self, content: str) -> List[Finding]:
        """Check npm/package.json dependencies"""
        findings = []
        
        try:
            data = json.loads(content)
            dependencies = {}
            dependencies.update(data.get('dependencies', {}))
            dependencies.update(data.get('devDependencies', {}))
            
            for package, version in dependencies.items():
                if package in self.VULNERABLE_PATTERNS:
                    vuln_info = self.VULNERABLE_PATTERNS[package]
                    finding = Finding(
                        scan_id="",
                        target_id="",
                        endpoint_id="",
                        vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                        severity=Severity.CRITICAL,
                        title=f"Vulnerable npm Dependency - {package}@{version}",
                        description=f"Package '{package}' version '{version}' is vulnerable. "
                                   f"{vuln_info['description']}. "
                                   f"Reference: {vuln_info['cve']}",
                        evidence={
                            'package': package,
                            'version': version,
                            'cve': vuln_info['cve'],
                            'ecosystem': 'npm',
                        },
                        status=Status.PENDING,
                    )
                    findings.append(finding)
        
        except json.JSONDecodeError:
            pass
        
        return findings
    
    def _check_pip_requirements(self, content: str) -> List[Finding]:
        """Check Python requirements.txt"""
        findings = []
        
        for line in content.split('\n'):
            line = line.strip()
            if not line or line.startswith('#') or line.startswith('-'):
                continue
            
            # Parse package==version or package>=version
            match = re.match(r'([a-zA-Z0-9\-_]+)([=<>!~]+)(.+)', line)
            if match:
                package = match.group(1).lower()
                version = match.group(3)
                
                if package in self.VULNERABLE_PATTERNS:
                    vuln_info = self.VULNERABLE_PATTERNS[package]
                    finding = Finding(
                        scan_id="",
                        target_id="",
                        endpoint_id="",
                        vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                        severity=Severity.CRITICAL,
                        title=f"Vulnerable Python Dependency - {package}=={version}",
                        description=f"Package '{package}' version '{version}' is vulnerable. "
                                   f"{vuln_info['description']}. "
                                   f"Reference: {vuln_info['cve']}",
                        evidence={
                            'package': package,
                            'version': version,
                            'cve': vuln_info['cve'],
                            'ecosystem': 'pip',
                        },
                        status=Status.PENDING,
                    )
                    findings.append(finding)
        
        return findings
    
    def _check_maven_dependencies(self, content: str) -> List[Finding]:
        """Check Maven pom.xml dependencies"""
        findings = []
        
        try:
            root = ET.fromstring(content)
            ns = {'maven': 'http://maven.apache.org/POM/4.0.0'}
            
            for dependency in root.findall('.//maven:dependency', ns):
                group_id = dependency.find('maven:groupId', ns)
                artifact_id = dependency.find('maven:artifactId', ns)
                version = dependency.find('maven:version', ns)
                
                if artifact_id is not None:
                    pkg_name = artifact_id.text
                    
                    if pkg_name in self.VULNERABLE_PATTERNS:
                        vuln_info = self.VULNERABLE_PATTERNS[pkg_name]
                        ver = version.text if version is not None else 'unknown'
                        
                        finding = Finding(
                            scan_id="",
                            target_id="",
                            endpoint_id="",
                            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                            severity=Severity.CRITICAL,
                            title=f"Vulnerable Maven Dependency - {pkg_name}:{ver}",
                            description=f"Maven dependency '{pkg_name}' version '{ver}' is vulnerable. "
                                       f"{vuln_info['description']}. "
                                       f"Reference: {vuln_info['cve']}",
                            evidence={
                                'package': pkg_name,
                                'version': ver,
                                'cve': vuln_info['cve'],
                                'ecosystem': 'maven',
                            },
                            status=Status.PENDING,
                        )
                        findings.append(finding)
        
        except ET.ParseError:
            pass
        
        return findings
    
    def _check_go_dependencies(self, content: str) -> List[Finding]:
        """Check Go go.mod dependencies"""
        findings = []
        
        for line in content.split('\n'):
            line = line.strip()
            
            # Parse require package version
            match = re.match(r'([a-zA-Z0-9\-./]+)\s+v?([0-9.]+)', line)
            if match:
                package = match.group(1)
                version = match.group(2)
                
                # Check against known vulnerable packages
                for vuln_pkg, vuln_info in self.VULNERABLE_PATTERNS.items():
                    if vuln_pkg in package.lower():
                        finding = Finding(
                            scan_id="",
                            target_id="",
                            endpoint_id="",
                            vulnerability_type=VulnerabilityType.VULNERABLE_DEPENDENCY,
                            severity=Severity.CRITICAL,
                            title=f"Vulnerable Go Dependency - {package}@{version}",
                            description=f"Go module '{package}' version '{version}' may be vulnerable. "
                                       f"{vuln_info['description']}. "
                                       f"Reference: {vuln_info['cve']}",
                            evidence={
                                'package': package,
                                'version': version,
                                'cve': vuln_info['cve'],
                                'ecosystem': 'go',
                            },
                            status=Status.PENDING,
                        )
                        findings.append(finding)
        
        return findings
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any]) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )


class SupplyChainIntegrityDetector(Detector):
    """Supply Chain Integrity and provenance verification"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.SUPPLY_CHAIN_COMPROMISE
    
    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL
    
    # Indicators of supply chain compromise
    SUSPICIOUS_PATTERNS = [
        # Typosquatting common packages
        r'(?:requsts|requets|requesmts)',
        r'(?:expres|exress)',
        r'(?:jquerty|jquerry)',
        r'(?:underscoe|underscre)',
    ]
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect potential supply chain compromises"""
        findings = []
        
        # This would typically check package registries
        # For now, return empty as it requires external API access
        
        return findings
    
    def detect_from_package_name(self, package_name: str) -> List[Finding]:
        """Check if package name suggests typosquatting or supply chain attack"""
        findings = []
        
        package_lower = package_name.lower()
        
        for pattern in self.SUSPICIOUS_PATTERNS:
            if re.search(pattern, package_lower):
                finding = Finding(
                    scan_id="",
                    target_id="",
                    endpoint_id="",
                    vulnerability_type=VulnerabilityType.SUPPLY_CHAIN_COMPROMISE,
                    severity=Severity.CRITICAL,
                    title=f"Potential Typosquatting Attack - {package_name}",
                    description=f"Package name '{package_name}' appears to be a typosquatting attempt "
                               f"of a legitimate package. This could be a supply chain attack.",
                    evidence={
                        'package': package_name,
                        'pattern_matched': pattern,
                    },
                    status=Status.PENDING,
                )
                findings.append(finding)
        
        return findings
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any]) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )


class DependencyConfusionDetector(Detector):
    """Detect Dependency Confusion attacks"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.SUPPLY_CHAIN_COMPROMISE
    
    @property
    def severity(self) -> Severity:
        return Severity.CRITICAL
    
    # Internal package patterns
    INTERNAL_PATTERNS = [
        r'@internal/',
        r'@company/',
        r'@corp/',
        r'@private/',
        r'my-corp-',
        r'company-',
    ]
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect potential dependency confusion vulnerabilities"""
        findings = []
        
        # This would typically scan package.json or similar files
        # for internal packages without proper scope verification
        
        return findings
    
    def check_dependency_confusion(self, package_name: str, registries: List[str]) -> List[Finding]:
        """Check if internal package might be vulnerable to dependency confusion"""
        findings = []
        
        package_lower = package_name.lower()
        
        for pattern in self.INTERNAL_PATTERNS:
            if pattern.replace(r'/', '').replace(r'-', '') in package_lower.replace('/', '').replace('-', ''):
                # Check if package is registered in public registry
                finding = Finding(
                    scan_id="",
                    target_id="",
                    endpoint_id="",
                    vulnerability_type=VulnerabilityType.SUPPLY_CHAIN_COMPROMISE,
                    severity=Severity.HIGH,
                    title=f"Potential Dependency Confusion - {package_name}",
                    description=f"Package '{package_name}' appears to be an internal package. "
                               f"Verify it's not available in public registries to prevent "
                               f"dependency confusion attacks.",
                    evidence={
                        'package': package_name,
                        'pattern': pattern,
                    },
                    status=Status.PENDING,
                )
                findings.append(finding)
                break
        
        return findings
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any]) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )
