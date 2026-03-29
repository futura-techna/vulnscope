"""
VulnScope - Advanced Cloud Security Detectors
Detects cloud infrastructure misconfigurations, IAM issues, and cloud-specific vulnerabilities
"""

import re
import json
from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional, Set
from enum import Enum
import requests

from ..core.models import Endpoint, Finding, Severity, VulnerabilityType, Status


class CloudProvider(str, Enum):
    """Cloud providers"""
    AWS = "AWS"
    AZURE = "AZURE"
    GCP = "GCP"
    ALIBABA = "ALIBABA"
    DIGITALOCEAN = "DIGITALOCEAN"
    LINODE = "LINODE"
    HEROKU = "HEROKU"


class Detector(ABC):
    """Base class for vulnerability detectors"""
    
    @property
    @abstractmethod
    def vulnerability_type(self) -> VulnerabilityType:
        pass
    
    @property
    @abstractmethod
    def severity(self) -> Severity:
        pass
    
    @abstractmethod
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        pass


class AWSMisconfigurationDetector(Detector):
    """Detect AWS-specific misconfigurations"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.CLOUD_MISCONFIGURATION
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # AWS metadata endpoints
    AWS_METADATA_ENDPOINTS = [
        '169.254.169.254',
        'http://169.254.169.254/latest/meta-data/',
        'http://169.254.169.254/latest/user-data/',
    ]
    
    # AWS bucket patterns
    AWS_BUCKET_PATTERNS = [
        r's3\.amazonaws\.com/([a-zA-Z0-9\-]+)',
        r's3-\w+\.amazonaws\.com/([a-zA-Z0-9\-]+)',
        r'([a-zA-Z0-9\-]+)\.s3\.amazonaws\.com',
        r'([a-zA-Z0-9\-]+)\.s3-\w+\.amazonaws\.com',
    ]
    
    # AWS service endpoints
    AWS_SERVICE_INDICATORS = [
        'dynamodb',
        'kinesis',
        'lambda',
        'ec2',
        'rds',
        'elasticache',
        'elasticsearch',
        'redshift',
        'sns',
        'sqs',
        'cloudformation',
        'ssm',
        'secrets-manager',
    ]
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect AWS misconfigurations"""
        findings = []
        
        url = endpoint.url.lower()
        
        # Check for metadata service exposure
        findings.extend(self._check_metadata_exposure(endpoint, session))
        
        # Check for S3 bucket exposure
        findings.extend(self._check_s3_exposure(endpoint, session))
        
        # Check for IAM credential exposure
        findings.extend(self._check_credential_exposure(endpoint, session))
        
        # Check for unencrypted services
        findings.extend(self._check_encryption_status(endpoint, session))
        
        return findings
    
    def _check_metadata_exposure(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check for AWS metadata service exposure"""
        findings = []
        
        for metadata_endpoint in self.AWS_METADATA_ENDPOINTS:
            if metadata_endpoint in endpoint.url:
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="AWS Metadata Service Exposure",
                    description=f"Endpoint may allow access to AWS metadata service ({metadata_endpoint}). "
                              f"This can expose IAM credentials, instance information, and other sensitive data.",
                    evidence={
                        'url': endpoint.url,
                        'metadata_endpoint': metadata_endpoint,
                        'risk': 'Can expose IAM role credentials, sensitive environment data',
                    }
                )
                findings.append(finding)
                break
        
        return findings
    
    def _check_s3_exposure(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check for S3 bucket exposure"""
        findings = []
        
        response_text = ""
        try:
            response = session.get(endpoint.url, timeout=10)
            response_text = response.text
        except Exception:
            return findings
        
        for pattern in self.AWS_BUCKET_PATTERNS:
            matches = re.findall(pattern, response_text)
            
            for bucket_name in matches:
                # Try to check if bucket is publicly accessible
                bucket_url = f"https://{bucket_name}.s3.amazonaws.com"
                try:
                    bucket_response = session.head(bucket_url, timeout=5)
                    if bucket_response.status_code == 200:
                        finding = self._create_finding(
                            endpoint=endpoint,
                            title=f"Publicly Accessible S3 Bucket Detected - {bucket_name}",
                            description=f"S3 bucket '{bucket_name}' appears to be publicly accessible. "
                                      f"Verify bucket policies and ensure proper access controls.",
                            evidence={
                                'url': endpoint.url,
                                'bucket_name': bucket_name,
                                'bucket_url': bucket_url,
                            }
                        )
                        findings.append(finding)
                except Exception:
                    pass
        
        return findings
    
    def _check_credential_exposure(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check for leaked AWS credentials"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            text = response.text
            
            # AWS credential patterns
            aws_key_pattern = r'AKIA[0-9A-Z]{16}'
            aws_secret_pattern = r'aws_secret_access_key\s*=\s*[A-Za-z0-9/+=]{40}'
            
            if re.search(aws_key_pattern, text):
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Potential AWS Access Key Exposure",
                    description="AWS access key found in response. "
                              "AWS credentials should never be exposed in code or responses.",
                    evidence={'url': endpoint.url},
                    severity=Severity.CRITICAL,
                )
                findings.append(finding)
            
            if re.search(aws_secret_pattern, text):
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Potential AWS Secret Key Exposure",
                    description="AWS secret key pattern found in response. "
                              "Secret keys should be managed through AWS Secrets Manager.",
                    evidence={'url': endpoint.url},
                    severity=Severity.CRITICAL,
                )
                findings.append(finding)
        
        except Exception:
            pass
        
        return findings
    
    def _check_encryption_status(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check for encryption of data at rest"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            
            # Check for unencrypted service connections
            unencrypted_services = [
                ('rds', 'Use encrypted RDS instances'),
                ('dynamodb', 'Enable DynamoDB encryption at rest'),
                ('s3', 'Enable S3 bucket encryption'),
            ]
            
            for service, remediation in unencrypted_services:
                if service in endpoint.url.lower():
                    if 'encrypt' not in response.headers:
                        finding = self._create_finding(
                            endpoint=endpoint,
                            title=f"Unencrypted {service.upper()} Service Access",
                            description=f"AWS {service.upper()} appears unencrypted. {remediation}",
                            evidence={'url': endpoint.url, 'service': service},
                            severity=Severity.HIGH,
                        )
                        findings.append(finding)
        
        except Exception:
            pass
        
        return findings
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any],
                       severity: Severity = None) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=severity or self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )


class AzureMisconfigurationDetector(Detector):
    """Detect Azure-specific misconfigurations"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.CLOUD_MISCONFIGURATION
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # Azure metadata endpoint
    AZURE_METADATA_ENDPOINT = 'http://169.254.169.254/metadata/instance'
    
    # Azure blob storage patterns
    AZURE_BLOB_PATTERNS = [
        r'\.blob\.core\.windows\.net/([a-zA-Z0-9\-]+)',
    ]
    
    # Azure service indicators
    AZURE_SERVICE_INDICATORS = [
        'vault.azure.net',
        'database.windows.net',
        'mysql.database.azure.com',
        'postgres.database.azure.com',
        'cosmosdb.azure.com',
        'servicebus.windows.net',
        'eventhubs.windows.net',
    ]
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect Azure misconfigurations"""
        findings = []
        
        # Check for metadata service exposure
        findings.extend(self._check_metadata_exposure(endpoint, session))
        
        # Check for blob storage exposure
        findings.extend(self._check_blob_exposure(endpoint, session))
        
        # Check for unencrypted services
        findings.extend(self._check_azure_encryption(endpoint, session))
        
        # Check for RBAC issues
        findings.extend(self._check_rbac_config(endpoint, session))
        
        return findings
    
    def _check_metadata_exposure(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check for Azure metadata service exposure"""
        findings = []
        
        if self.AZURE_METADATA_ENDPOINT in endpoint.url:
            finding = self._create_finding(
                endpoint=endpoint,
                title="Azure Metadata Service Exposure",
                description=f"Endpoint may expose Azure metadata service. "
                          f"This can leak managed identity tokens and other sensitive data.",
                evidence={'url': endpoint.url},
            )
            findings.append(finding)
        
        return findings
    
    def _check_blob_exposure(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check for Azure blob storage exposure"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            text = response.text
            
            for pattern in self.AZURE_BLOB_PATTERNS:
                matches = re.findall(pattern, text)
                
                for container in matches:
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title=f"Azure Blob Storage Reference Detected - {container}",
                        description=f"Azure blob container '{container}' referenced. "
                                  f"Verify container is not publicly accessible.",
                        evidence={'url': endpoint.url, 'container': container},
                    )
                    findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def _check_azure_encryption(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check Azure encryption settings"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            headers = response.headers
            
            # Check for encryption in transit
            if not endpoint.url.startswith('https://'):
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Unencrypted Azure Service Access",
                    description="Azure service accessed over HTTP. Use HTTPS only.",
                    evidence={'url': endpoint.url},
                )
                findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def _check_rbac_config(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check Azure RBAC configuration"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            
            # Check for overly permissive roles
            if 'owner' in response.text.lower() or 'contributor' in response.text.lower():
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="Potential Overly Permissive Azure RBAC",
                    description="Response suggests Owner or Contributor roles in use. "
                              f"Apply principle of least privilege.",
                    evidence={'url': endpoint.url},
                    severity=Severity.HIGH,
                )
                findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any],
                       severity: Severity = None) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=severity or self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )


class GCPMisconfigurationDetector(Detector):
    """Detect GCP-specific misconfigurations"""
    
    @property
    def vulnerability_type(self) -> VulnerabilityType:
        return VulnerabilityType.CLOUD_MISCONFIGURATION
    
    @property
    def severity(self) -> Severity:
        return Severity.HIGH
    
    # GCP metadata endpoints
    GCP_METADATA_ENDPOINTS = [
        'http://metadata.google.internal',
        'http://169.254.169.254/computeMetadata/v1/',
    ]
    
    # GCP storage patterns
    GCP_BUCKET_PATTERNS = [
        r'storage\.googleapis\.com/([a-zA-Z0-9\-_.]+)',
        r'gs://([a-zA-Z0-9\-_.]+)',
    ]
    
    # GCP service indicators
    GCP_SERVICE_INDICATORS = [
        'cloudfunctions.net',
        'appspot.com',
        'cloudendpoints.appspot.com',
        'cloudsql.googleapis.com',
        'firestore.googleapis.com',
        'logging.googleapis.com',
    ]
    
    def detect(self, endpoint: Endpoint, session) -> List[Finding]:
        """Detect GCP misconfigurations"""
        findings = []
        
        # Check for metadata service exposure
        findings.extend(self._check_metadata_exposure(endpoint, session))
        
        # Check for bucket exposure
        findings.extend(self._check_bucket_exposure(endpoint, session))
        
        # Check IAM misconfigurations
        findings.extend(self._check_iam_config(endpoint, session))
        
        return findings
    
    def _check_metadata_exposure(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check for GCP metadata service exposure"""
        findings = []
        
        for metadata_endpoint in self.GCP_METADATA_ENDPOINTS:
            if metadata_endpoint in endpoint.url:
                finding = self._create_finding(
                    endpoint=endpoint,
                    title="GCP Metadata Service Exposure",
                    description=f"Endpoint may expose GCP metadata service. "
                              f"This can leak service account tokens and instance information.",
                    evidence={'url': endpoint.url},
                )
                findings.append(finding)
        
        return findings
    
    def _check_bucket_exposure(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check for GCP bucket exposure"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            text = response.text
            
            for pattern in self.GCP_BUCKET_PATTERNS:
                matches = re.findall(pattern, text)
                
                for bucket in matches:
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title=f"GCP Storage Bucket Reference Detected - {bucket}",
                        description=f"GCP bucket '{bucket}' referenced. "
                                  f"Verify bucket permissions are properly restricted.",
                        evidence={'url': endpoint.url, 'bucket': bucket},
                    )
                    findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def _check_iam_config(self, endpoint: Endpoint, session) -> List[Finding]:
        """Check GCP IAM configuration"""
        findings = []
        
        try:
            response = session.get(endpoint.url, timeout=10)
            text = response.text
            
            # Check for overly permissive roles
            dangerous_roles = [
                'Editor',
                'Owner',
                'Storage Admin',
                'Compute Admin',
            ]
            
            for role in dangerous_roles:
                if role.lower() in text.lower():
                    finding = self._create_finding(
                        endpoint=endpoint,
                        title=f"Overly Permissive GCP Role - {role}",
                        description=f"Role '{role}' detected. "
                                  f"Apply principle of least privilege.",
                        evidence={'url': endpoint.url, 'role': role},
                    )
                    findings.append(finding)
        except Exception:
            pass
        
        return findings
    
    def _create_finding(self, endpoint: Endpoint, title: str,
                       description: str, evidence: Dict[str, Any],
                       severity: Severity = None) -> Finding:
        """Create a standardized finding"""
        return Finding(
            scan_id="",
            target_id=endpoint.target_id,
            endpoint_id=str(endpoint.id),
            vulnerability_type=self.vulnerability_type,
            severity=severity or self.severity,
            title=title,
            description=description,
            evidence=evidence,
            status=Status.PENDING,
        )
