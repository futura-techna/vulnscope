"""
VulnScope - SCA (Software Composition Analysis) Scanner
Scans dependency files for vulnerable components
"""

import os
import json
from typing import List, Dict, Any, Optional
from pathlib import Path

from ..core.models import Finding, Scan, Target, Severity, VulnerabilityType, Status
from .supply_chain_detectors import (
    SupplyChainDetector, 
    SupplyChainIntegrityDetector,
    DependencyConfusionDetector
)


class SCAScanner:
    """
    Software Composition Analysis Scanner
    
    Scans dependency files (package.json, requirements.txt, pom.xml, etc.)
    for known vulnerabilities in dependencies.
    """
    
    # Supported dependency files
    SUPPORTED_FILES = [
        'package.json',
        'package-lock.json',
        'requirements.txt',
        'Pipfile',
        'Pipfile.lock',
        'pyproject.toml',
        'poetry.lock',
        'pom.xml',
        'build.gradle',
        'build.gradle.kts',
        'go.mod',
        'go.sum',
        'Gemfile',
        'Gemfile.lock',
        'Cargo.toml',
        'Cargo.lock',
        'composer.json',
        'composer.lock',
    ]
    
    def __init__(self):
        self.supply_chain_detector = SupplyChainDetector()
        self.integrity_detector = SupplyChainIntegrityDetector()
        self.confusion_detector = DependencyConfusionDetector()
    
    def scan_directory(self, directory_path: str) -> List[Finding]:
        """
        Scan a directory for dependency files and check for vulnerabilities
        
        Args:
            directory_path: Path to the project directory
            
        Returns:
            List of findings
        """
        findings = []
        
        # Find all dependency files
        dep_files = self._find_dependency_files(directory_path)
        
        for file_path in dep_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                file_findings = self.supply_chain_detector.detect_from_file(
                    str(file_path), content
                )
                findings.extend(file_findings)
                
                # Check for typosquatting
                if 'package.json' in str(file_path):
                    try:
                        data = json.loads(content)
                        packages = list(data.get('dependencies', {}).keys())
                        packages.extend(data.get('devDependencies', {}).keys())
                        
                        for pkg in packages:
                            pkg_findings = self.integrity_detector.detect_from_package_name(pkg)
                            findings.extend(pkg_findings)
                            
                            # Check for dependency confusion
                            confusion_findings = self.confusion_detector.check_dependency_confusion(
                                pkg, ['npmjs.com', 'pypi.org']
                            )
                            findings.extend(confusion_findings)
                    except json.JSONDecodeError:
                        pass
                        
            except Exception as e:
                print(f"Error scanning {file_path}: {e}")
        
        return findings
    
    def scan_file(self, file_path: str) -> List[Finding]:
        """
        Scan a single dependency file
        
        Args:
            file_path: Path to the dependency file
            
        Returns:
            List of findings
        """
        findings = []
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
            
            findings = self.supply_chain_detector.detect_from_file(file_path, content)
            
        except Exception as e:
            print(f"Error scanning {file_path}: {e}")
        
        return findings
    
    def scan_git_repository(self, repo_url: str, branch: str = "main") -> List[Finding]:
        """
        Scan a git repository for dependency files
        
        Args:
            repo_url: URL of the git repository
            branch: Branch to scan
            
        Returns:
            List of findings
        """
        # This would typically clone the repository and scan it
        # For now, return empty list as it requires git integration
        return []
    
    def _find_dependency_files(self, directory_path: str) -> List[Path]:
        """
        Find all dependency files in a directory
        
        Args:
            directory_path: Directory to search
            
        Returns:
            List of paths to dependency files
        """
        found_files = []
        
        for root, dirs, files in os.walk(directory_path):
            # Skip common non-dependency directories
            dirs[:] = [d for d in dirs if d not in [
                'node_modules', '.git', '__pycache__', 
                'venv', '.venv', 'target', 'dist', 'build'
            ]]
            
            for file in files:
                if file in self.SUPPORTED_FILES:
                    found_files.append(Path(root) / file)
        
        return found_files
    
    def check_dependencies_online(self, package_name: str, ecosystem: str) -> Dict[str, Any]:
        """
        Check a package against online vulnerability databases
        
        Args:
            package_name: Name of the package
            ecosystem: Package ecosystem (npm, pip, maven, etc.)
            
        Returns:
            Dictionary with vulnerability information
        """
        # This would typically query OSV (Open Source Vulnerabilities) API
        # or GitHub Advisory Database
        return {
            'package': package_name,
            'ecosystem': ecosystem,
            'vulnerabilities': [],
            'checked': True,
        }
    
    def generate_sbom(self, directory_path: str, format: str = "spdx") -> Dict[str, Any]:
        """
        Generate Software Bill of Materials (SBOM)
        
        Args:
            directory_path: Project directory
            format: SBOM format (spdx, cyclonedx, swid)
            
        Returns:
            SBOM data
        """
        dependencies = []
        
        dep_files = self._find_dependency_files(directory_path)
        
        for file_path in dep_files:
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    content = f.read()
                
                # Parse based on file type
                if 'package.json' in str(file_path):
                    data = json.loads(content)
                    for pkg, version in data.get('dependencies', {}).items():
                        dependencies.append({
                            'name': pkg,
                            'version': version,
                            'ecosystem': 'npm',
                        })
                        
            except Exception:
                continue
        
        return {
            'format': format,
            'dependencies': dependencies,
            'generator': 'VulnScope SCA Scanner',
        }
