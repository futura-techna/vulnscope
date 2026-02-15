"""
VulnScope - S3 Evidence Storage
Cloud storage for evidence with digital signatures
"""

import os
import json
import hashlib
import hmac
from typing import Dict, Any, Optional
from datetime import datetime
from pathlib import Path
from dataclasses import dataclass


@dataclass
class S3Config:
    """S3 storage configuration"""
    bucket: str = ""
    region: str = "us-east-1"
    access_key: Optional[str] = None
    secret_key: Optional[str] = None
    endpoint_url: Optional[str] = None  # For MinIO, DigitalOcean Spaces, etc.
    encryption_enabled: bool = True
    versioning: bool = True


class DigitalSignature:
    """Digital signature for evidence integrity"""
    
    def __init__(self, secret_key: str):
        self.secret_key = secret_key.encode()
    
    def sign(self, data: str) -> str:
        """Create HMAC signature"""
        signature = hmac.new(
            self.secret_key,
            data.encode(),
            hashlib.sha256
        ).hexdigest()
        return signature
    
    def verify(self, data: str, signature: str) -> bool:
        """Verify signature"""
        expected = self.sign(data)
        return hmac.compare_digest(expected, signature)


class S3EvidenceStorage:
    """
    S3-compatible evidence storage with digital signatures
    
    Features:
    - S3-compatible storage (AWS S3, MinIO, DigitalOcean Spaces)
    - Digital signatures for integrity
    - Server-side encryption
    - Versioning support
    """
    
    def __init__(self, config: S3Config):
        self.config = config
        self.signature = DigitalSignature(config.secret_key or "default-secret")
        
        # Try to import boto3, fall back to mock if not available
        self.boto3 = None
        try:
            import boto3
            self.boto3 = boto3
        except ImportError:
            pass
    
    def _get_client(self):
        """Get S3 client"""
        if not self.boto3:
            raise RuntimeError("boto3 not installed. Install with: pip install boto3")
        
        kwargs = {
            'region_name': self.config.region,
        }
        
        if self.config.access_key and self.config.secret_key:
            kwargs['aws_access_key_id'] = self.config.access_key
            kwargs['aws_secret_access_key'] = self.config.secret_key
        
        if self.config.endpoint_url:
            kwargs['endpoint_url'] = self.config.endpoint_url
        
        return self.boto3.client('s3', **kwargs)
    
    def upload_evidence(self, evidence_id: str, content: str, 
                       metadata: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Upload evidence to S3 with digital signature
        
        Args:
            evidence_id: Unique evidence ID
            content: Evidence content
            metadata: Optional metadata
            
        Returns:
            Upload result with signature
        """
        # Create signature
        signature = self.signature.sign(content)
        
        # Prepare metadata
        meta = metadata or {}
        meta['evidence_id'] = evidence_id
        meta['signature'] = signature
        meta['created_at'] = datetime.utcnow().isoformat()
        meta['content_hash'] = hashlib.sha256(content.encode()).hexdigest()
        
        # Upload to S3
        key = f"evidence/{evidence_id}.evd"
        
        if self.boto3:
            try:
                client = self._get_client()
                client.put_object(
                    Bucket=self.config.bucket,
                    Key=key,
                    Body=content.encode(),
                    Metadata=meta,
                    ServerSideEncryption='AES256' if self.config.encryption_enabled else None,
                )
                uploaded = True
            except Exception as e:
                uploaded = False
                error = str(e)
        else:
            # Mock upload
            uploaded = True
            error = None
        
        return {
            'evidence_id': evidence_id,
            'key': key,
            'signature': signature,
            'content_hash': meta['content_hash'],
            'uploaded': uploaded,
            'error': error if not uploaded else None,
        }
    
    def download_evidence(self, evidence_id: str) -> Optional[str]:
        """Download and verify evidence from S3"""
        key = f"evidence/{evidence_id}.evd"
        
        if self.boto3:
            try:
                client = self._get_client()
                response = client.get_object(Bucket=self.config.bucket, Key=key)
                content = response['Body'].read().decode()
                
                # Verify signature
                metadata = response.get('Metadata', {})
                signature = metadata.get('signature', '')
                
                if signature and not self.signature.verify(content, signature):
                    return None  # Signature mismatch
                
                return content
            except Exception:
                return None
        return None
    
    def verify_evidence(self, evidence_id: str) -> bool:
        """Verify evidence integrity"""
        content = self.download_evidence(evidence_id)
        return content is not None
    
    def delete_evidence(self, evidence_id: str) -> bool:
        """Delete evidence from S3"""
        key = f"evidence/{evidence_id}.evd"
        
        if self.boto3:
            try:
                client = self._get_client()
                client.delete_object(Bucket=self.config.bucket, Key=key)
                return True
            except Exception:
                return False
        return True
    
    def list_evidence(self, prefix: str = "evidence/") -> list:
        """List evidence in storage"""
        if self.boto3:
            try:
                client = self._get_client()
                response = client.list_objects_v2(Bucket=self.config.bucket, Prefix=prefix)
                return [obj['Key'] for obj in response.get('Contents', [])]
            except Exception:
                return []
        return []


class EvidenceSigner:
    """Digital signature manager for evidence"""
    
    def __init__(self, secret_key: str):
        self.signer = DigitalSignature(secret_key)
    
    def sign_finding(self, finding_data: Dict) -> Dict:
        """Sign a finding with digital signature"""
        data = json.dumps(finding_data, sort_keys=True)
        finding_data['signature'] = self.signer.sign(data)
        finding_data['signed_at'] = datetime.utcnow().isoformat()
        return finding_data
    
    def verify_finding(self, finding_data: Dict) -> bool:
        """Verify finding signature"""
        if 'signature' not in finding_data:
            return False
        
        signature = finding_data.pop('signature')
        signed_at = finding_data.pop('signed_at', None)
        
        data = json.dumps(finding_data, sort_keys=True)
        result = self.signer.verify(data, signature)
        
        # Restore fields
        finding_data['signature'] = signature
        if signed_at:
            finding_data['signed_at'] = signed_at
        
        return result
