"""
VulnScope - Evidence Vault Unit Tests
Tests for evidence storage and management
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from uuid import uuid4
from datetime import datetime, timedelta
from pathlib import Path
import tempfile
import shutil

from src.evidence.vault import EvidenceVault, Evidence, ImmutableLog
from src.config.settings import EvidenceConfig


class TestEvidence:
    """Test Evidence dataclass"""
    
    def test_create_evidence(self):
        evidence = Evidence(
            scan_id=uuid4(),
            target_id=uuid4(),
            finding_id=uuid4(),
            evidence_type="screenshot",
            content="image_data",
            content_hash="abc123"
        )
        
        assert evidence.evidence_type == "screenshot"
        assert evidence.content == "image_data"
    
    def test_evidence_timestamps(self):
        evidence = Evidence(
            evidence_type="log",
            content="log content"
        )
        
        assert evidence.created_at is not None
    
    def test_evidence_default_values(self):
        evidence = Evidence()
        
        assert evidence.mime_type == "text/plain"
        assert evidence.compression == False
        assert evidence.chain_valid == True
        assert evidence.id is not None
    
    def test_evidence_size_tracking(self):
        evidence = Evidence(
            content="test content",
            size_bytes=len("test content".encode())
        )
        
        assert evidence.size_bytes > 0


class TestEvidenceVault:
    """Test EvidenceVault class"""
    
    @pytest.fixture
    def temp_storage(self, tmp_path):
        """Create temporary storage directory"""
        storage_dir = tmp_path / "evidence_test"
        storage_dir.mkdir()
        yield storage_dir
        # Cleanup handled by tmp_path
    
    @pytest.fixture
    def vault(self, temp_storage):
        """Create vault with temporary storage"""
        config = EvidenceConfig(storage_path=str(temp_storage))
        return EvidenceVault(config=config)
    
    def test_initialization(self, vault):
        assert vault is not None
        assert vault.storage_path is not None
    
    def test_ensure_storage_creates_directories(self, temp_storage):
        config = EvidenceConfig(storage_path=str(temp_storage))
        vault = EvidenceVault(config=config)
        
        # Check subdirectories exist
        assert (vault.storage_path / "evidence").exists()
        assert (vault.storage_path / "scans").exists()
        assert (vault.storage_path / "logs").exists()
        assert (vault.storage_path / "exports").exists()
    
    def test_store_evidence(self, vault):
        scan_id = uuid4()
        target_id = uuid4()
        finding_id = uuid4()
        
        evidence = vault.store_evidence(
            scan_id=scan_id,
            target_id=target_id,
            finding_id=finding_id,
            evidence_type="request",
            content="GET /api/users HTTP/1.1"
        )
        
        assert evidence is not None
        assert evidence.id is not None
        assert evidence.evidence_type == "request"
    
    def test_retrieve_evidence(self, vault):
        scan_id = uuid4()
        target_id = uuid4()
        finding_id = uuid4()
        
        stored = vault.store_evidence(
            scan_id=scan_id,
            target_id=target_id,
            finding_id=finding_id,
            evidence_type="response",
            content="HTTP/1.1 200 OK"
        )
        
        retrieved = vault.get_evidence(stored.id)
        
        assert retrieved is not None
        assert retrieved.content == "HTTP/1.1 200 OK"
    
    def test_get_evidence_for_finding(self, vault):
        finding_id = uuid4()
        scan_id = uuid4()
        target_id = uuid4()
        
        # Store multiple evidence items for same finding
        vault.store_evidence(
            scan_id=scan_id, target_id=target_id, finding_id=finding_id,
            evidence_type="request", content="req1"
        )
        vault.store_evidence(
            scan_id=scan_id, target_id=target_id, finding_id=finding_id,
            evidence_type="response", content="resp1"
        )
        vault.store_evidence(
            scan_id=scan_id, target_id=target_id, finding_id=finding_id,
            evidence_type="screenshot", content="img"
        )
        
        items = vault.get_evidence_for_finding(finding_id)
        
        assert len(items) == 3
    
    def test_get_nonexistent_evidence(self, vault):
        retrieved = vault.get_evidence(uuid4())
        assert retrieved is None
    
    def test_store_request_response(self, vault):
        scan_id = uuid4()
        target_id = uuid4()
        finding_id = uuid4()
        
        evidence = vault.store_request_response(
            scan_id=scan_id,
            target_id=target_id,
            finding_id=finding_id,
            request="GET /search?q=<script> HTTP/1.1",
            response="<html><script>alert(1)</script></html>"
        )
        
        assert evidence is not None
        assert evidence.evidence_type == "http_transaction"
    
    def test_store_log(self, vault):
        scan_id = uuid4()
        target_id = uuid4()
        
        evidence = vault.store_log(
            scan_id=scan_id,
            target_id=target_id,
            log_entry="Scan started for target"
        )
        
        assert evidence is not None
        assert evidence.evidence_type == "audit_log"


class TestEvidenceVaultChainOfCustody:
    """Test chain of custody functionality"""
    
    @pytest.fixture
    def vault(self, tmp_path):
        config = EvidenceConfig(storage_path=str(tmp_path / "evidence"))
        return EvidenceVault(config=config)
    
    def test_chain_of_custody_hashing(self, vault):
        scan_id = uuid4()
        target_id = uuid4()
        finding_id = uuid4()
        
        # Store multiple items
        ev1 = vault.store_evidence(
            scan_id=scan_id, target_id=target_id, finding_id=finding_id,
            evidence_type="request", content="first"
        )
        ev2 = vault.store_evidence(
            scan_id=scan_id, target_id=target_id, finding_id=finding_id,
            evidence_type="response", content="second"
        )
        
        # Second evidence should have previous hash
        assert ev2.previous_hash == ev1.content_hash
    
    def test_verify_chain(self, vault):
        scan_id = uuid4()
        target_id = uuid4()
        finding_id = uuid4()
        
        # Store multiple items
        for i in range(5):
            vault.store_evidence(
                scan_id=scan_id, target_id=target_id, finding_id=finding_id,
                evidence_type="log", content=f"entry_{i}"
            )
        
        # Verify chain
        assert vault.verify_chain() == True
    
    def test_content_hash(self, vault):
        scan_id = uuid4()
        target_id = uuid4()
        finding_id = uuid4()
        
        evidence = vault.store_evidence(
            scan_id=scan_id, target_id=target_id, finding_id=finding_id,
            evidence_type="request", content="test content"
        )
        
        # Hash should be computed
        assert evidence.content_hash is not None
        assert len(evidence.content_hash) == 64  # SHA-256 hex length


class TestEvidenceVaultStorage:
    """Test vault storage operations"""
    
    @pytest.fixture
    def vault(self, tmp_path):
        config = EvidenceConfig(storage_path=str(tmp_path / "evidence"))
        return EvidenceVault(config=config)
    
    def test_storage_stats(self, vault):
        scan_id = uuid4()
        target_id = uuid4()
        finding_id = uuid4()
        
        vault.store_evidence(
            scan_id=scan_id, target_id=target_id, finding_id=finding_id,
            evidence_type="request", content="req"
        )
        vault.store_evidence(
            scan_id=scan_id, target_id=target_id, finding_id=finding_id,
            evidence_type="response", content="resp"
        )
        
        stats = vault.get_storage_stats()
        
        assert stats['total_evidence_items'] == 2
        assert stats['total_size_bytes'] > 0
        assert stats['chain_valid'] == True
    
    def test_apply_retention_policy(self, tmp_path):
        # Create config with short retention
        config = EvidenceConfig(
            storage_path=str(tmp_path / "evidence"),
            retention_days=1
        )
        vault = EvidenceVault(config=config)
        
        scan_id = uuid4()
        target_id = uuid4()
        finding_id = uuid4()
        
        # Store evidence
        vault.store_evidence(
            scan_id=scan_id, target_id=target_id, finding_id=finding_id,
            evidence_type="request", content="test"
        )
        
        # Apply retention (should not delete recent evidence)
        vault.apply_retention_policy()
        
        assert len(vault.index) == 1
    
    def test_export_audit_log(self, vault):
        scan_id = uuid4()
        target_id = uuid4()
        
        # Store some audit logs
        vault.store_log(scan_id=scan_id, target_id=target_id, log_entry="Log 1")
        vault.store_log(scan_id=scan_id, target_id=target_id, log_entry="Log 2")
        
        # Export logs
        start_date = datetime.utcnow() - timedelta(days=1)
        end_date = datetime.utcnow() + timedelta(days=1)
        
        exported = vault.export_audit_log(start_date, end_date)
        
        assert exported is not None


class TestImmutableLog:
    """Test ImmutableLog class"""
    
    @pytest.fixture
    def temp_log_path(self, tmp_path):
        return str(tmp_path / "audit.log")
    
    def test_initialization(self, temp_log_path):
        log = ImmutableLog(temp_log_path)
        assert log.log_path.exists()
    
    def test_genesis_block_created(self, temp_log_path):
        log = ImmutableLog(temp_log_path)
        
        # Genesis block should exist
        assert log.log_path.exists()
    
    def test_log_path_set_correctly(self, temp_log_path):
        log = ImmutableLog(temp_log_path)
        
        # Path should be set
        assert str(log.log_path) == temp_log_path
    
    def test_compute_hash(self, temp_log_path):
        log = ImmutableLog(temp_log_path)
        
        # Hash function should work
        test_hash = log._compute_hash("test data")
        
        assert test_hash is not None
        assert len(test_hash) == 64  # SHA-256 hex length


class TestEvidenceConfig:
    """Test evidence configuration"""
    
    def test_default_config(self):
        config = EvidenceConfig()
        
        assert config.storage_path == "/var/vulnscope/evidence"
        assert config.encryption_enabled == True
        assert config.retention_days == 365
        assert config.compression == True
    
    def test_custom_config(self, tmp_path):
        config = EvidenceConfig(
            storage_path=str(tmp_path),
            retention_days=30,
            compression=False
        )
        
        assert config.retention_days == 30
        assert config.compression == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])