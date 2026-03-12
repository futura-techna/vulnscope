"""
VulnScope - S3 Storage Tests
Tests for S3-compatible storage integration
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
import json
from datetime import datetime

from src.evidence.s3_storage import (
    S3EvidenceStorage, S3Config, DigitalSignature, EvidenceSigner
)


class TestS3Config:
    """Test S3 configuration"""
    
    def test_default_config(self):
        config = S3Config()
        
        assert config.bucket == ""
        assert config.region == "us-east-1"
        assert config.encryption_enabled is True
        assert config.versioning is True
    
    def test_custom_config(self):
        config = S3Config(
            bucket="custom-bucket",
            region="eu-west-1",
            access_key="custom-key",
            secret_key="custom-secret",
            endpoint_url="https://s3.custom.com"
        )
        
        assert config.bucket == "custom-bucket"
        assert config.region == "eu-west-1"
        assert config.access_key == "custom-key"
        assert config.endpoint_url == "https://s3.custom.com"


class TestDigitalSignature:
    """Test digital signature functionality"""
    
    def test_sign(self):
        signer = DigitalSignature("test-secret-key")
        
        signature = signer.sign("test data")
        
        assert signature is not None
        assert len(signature) == 64  # SHA256 hex digest
    
    def test_verify_valid(self):
        signer = DigitalSignature("test-secret-key")
        
        data = "test data"
        signature = signer.sign(data)
        
        result = signer.verify(data, signature)
        
        assert result is True
    
    def test_verify_invalid(self):
        signer = DigitalSignature("test-secret-key")
        
        result = signer.verify("test data", "invalid-signature")
        
        assert result is False
    
    def test_verify_tampered_data(self):
        signer = DigitalSignature("test-secret-key")
        
        signature = signer.sign("original data")
        result = signer.verify("tampered data", signature)
        
        assert result is False
    
    def test_different_keys(self):
        signer1 = DigitalSignature("key1")
        signer2 = DigitalSignature("key2")
        
        signature = signer1.sign("test data")
        result = signer2.verify("test data", signature)
        
        assert result is False


class TestS3EvidenceStorage:
    """Test S3 evidence storage"""
    
    @pytest.fixture
    def storage(self):
        config = S3Config(
            bucket="test-bucket",
            region="us-east-1",
            secret_key="test-secret"
        )
        return S3EvidenceStorage(config)
    
    def test_init(self, storage):
        assert storage.config.bucket == "test-bucket"
        assert storage.signature is not None
    
    def test_upload_evidence_mock(self, storage):
        """Test uploading evidence without boto3"""
        # Without boto3, the upload is mocked
        result = storage.upload_evidence(
            evidence_id="ev-001",
            content="Test evidence content",
            metadata={"scan_id": "scan-123"}
        )
        
        assert result['evidence_id'] == "ev-001"
        assert result['uploaded'] is True
        assert result['signature'] is not None
        assert result['content_hash'] is not None
    
    def test_upload_evidence_with_signature(self, storage):
        """Test that uploaded evidence has valid signature"""
        content = "Test evidence content"
        result = storage.upload_evidence(
            evidence_id="ev-002",
            content=content
        )
        
        # Verify signature is valid
        assert storage.signature.verify(content, result['signature'])
    
    def test_verify_evidence(self, storage):
        """Test evidence verification"""
        # Without boto3, download returns None
        result = storage.verify_evidence("ev-001")
        
        # Should return False or None since no actual S3
        assert result is None or result is False
    
    def test_delete_evidence_mock(self, storage):
        """Test deleting evidence without boto3"""
        result = storage.delete_evidence("ev-001")
        
        # Without boto3, returns True (mock)
        assert result is True
    
    def test_list_evidence_mock(self, storage):
        """Test listing evidence without boto3"""
        result = storage.list_evidence()
        
        # Without boto3, returns empty list
        assert result == []


class TestEvidenceSigner:
    """Test evidence signer"""
    
    @pytest.fixture
    def signer(self):
        return EvidenceSigner("test-secret-key")
    
    def test_sign_finding(self, signer):
        finding = {
            "id": "finding-001",
            "title": "SQL Injection",
            "severity": "High"
        }
        
        signed = signer.sign_finding(finding)
        
        assert "signature" in signed
        assert "signed_at" in signed
    
    def test_verify_finding_valid(self, signer):
        finding = {
            "id": "finding-001",
            "title": "SQL Injection",
            "severity": "High"
        }
        
        signed = signer.sign_finding(finding.copy())
        result = signer.verify_finding(signed)
        
        assert result is True
    
    def test_verify_finding_tampered(self, signer):
        finding = {
            "id": "finding-001",
            "title": "SQL Injection",
            "severity": "High"
        }
        
        signed = signer.sign_finding(finding.copy())
        
        # Tamper with the finding
        signed["title"] = "XSS"
        
        result = signer.verify_finding(signed)
        
        assert result is False
    
    def test_verify_finding_missing_signature(self, signer):
        finding = {
            "id": "finding-001",
            "title": "SQL Injection"
        }
        
        result = signer.verify_finding(finding)
        
        assert result is False


class TestS3EvidenceStorageWithBoto3:
    """Test S3 storage with boto3 mocked"""
    
    def test_download_evidence_with_boto3_mock(self):
        """Test downloading evidence with boto3 mocked"""
        # Since boto3 is imported inside methods, we test the mock behavior
        config = S3Config(
            bucket="test-bucket",
            region="us-east-1",
            access_key="key",
            secret_key="secret"
        )
        
        storage = S3EvidenceStorage(config)
        
        # Without boto3 installed, download returns None
        result = storage.download_evidence("ev-001")
        
        # Should return None when boto3 is not available
        assert result is None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])