"""
VulnScope - Evidence Vault
Immutable storage for security evidence and audit logs
"""

import os
import json
import hashlib
import gzip
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
from pathlib import Path
from dataclasses import dataclass, field
from uuid import UUID, uuid4
import shutil

from ..core.models import Finding, Scan, Target
from ..core.exceptions import StorageError
from ..config.settings import EvidenceConfig


@dataclass
class Evidence:
    """Evidence item stored in vault"""
    id: UUID = field(default_factory=uuid4)
    scan_id: UUID = None
    target_id: UUID = None
    finding_id: UUID = None
    
    # Evidence data
    evidence_type: str = ""  # request, response, screenshot, log
    content: str = ""
    content_hash: str = ""
    mime_type: str = "text/plain"
    
    # Metadata
    created_at: datetime = field(default_factory=datetime.utcnow)
    size_bytes: int = 0
    compression: bool = False
    
    # Chain of custody
    previous_hash: str = ""
    chain_valid: bool = True


class EvidenceVault:
    """
    Immutable evidence storage with chain of custody
    
    Features:
    - Append-only storage (immutable)
    - Content hashing for integrity
    - Chain of custody tracking
    - Compression support
    - Retention policies
    - Search and retrieval
    """
    
    def __init__(self, config: EvidenceConfig = None):
        self.config = config or EvidenceConfig()
        self.storage_path = Path(self.config.storage_path)
        self._ensure_storage()
        
        # In-memory index for fast search
        self.index: Dict[str, Evidence] = {}
    
    def _ensure_storage(self):
        """Ensure storage directory exists"""
        self.storage_path.mkdir(parents=True, exist_ok=True)
        
        # Create subdirectories
        (self.storage_path / "evidence").mkdir(exist_ok=True)
        (self.storage_path / "scans").mkdir(exist_ok=True)
        (self.storage_path / "logs").mkdir(exist_ok=True)
        (self.storage_path / "exports").mkdir(exist_ok=True)
    
    def _compute_hash(self, content: str) -> str:
        """Compute SHA-256 hash of content"""
        return hashlib.sha256(content.encode()).hexdigest()
    
    def _get_evidence_path(self, evidence_id: UUID) -> Path:
        """Get file path for evidence"""
        return self.storage_path / "evidence" / f"{evidence_id}.evd"
    
    def store_evidence(self, scan_id: UUID, target_id: UUID,
                      finding_id: UUID, evidence_type: str,
                      content: str, mime_type: str = "text/plain") -> Evidence:
        """
        Store evidence in vault
        
        Args:
            scan_id: Scan ID
            target_id: Target ID
            finding_id: Finding ID
            evidence_type: Type of evidence
            content: Evidence content
            mime_type: MIME type of content
            
        Returns:
            Evidence object
        """
        # Create evidence
        evidence = Evidence(
            scan_id=scan_id,
            target_id=target_id,
            finding_id=finding_id,
            evidence_type=evidence_type,
            content=content,
            content_hash=self._compute_hash(content),
            mime_type=mime_type,
            size_bytes=len(content.encode()),
        )
        
        # Get previous hash for chain
        if self.index:
            last_evidence = list(self.index.values())[-1]
            evidence.previous_hash = last_evidence.content_hash
        
        # Compress if enabled
        if self.config.compression and evidence.size_bytes > 1024:
            compressed = gzip.compress(content.encode())
            evidence.content = compressed.decode('latin-1')  # Store as string
            evidence.compression = True
        
        # Save to disk
        evidence_path = self._get_evidence_path(evidence.id)
        
        with open(evidence_path, 'w') as f:
            json.dump({
                'id': str(evidence.id),
                'scan_id': str(evidence.scan_id),
                'target_id': str(evidence.target_id),
                'finding_id': str(evidence.finding_id),
                'evidence_type': evidence.evidence_type,
                'content': evidence.content,
                'content_hash': evidence.content_hash,
                'mime_type': evidence.mime_type,
                'created_at': evidence.created_at.isoformat(),
                'size_bytes': evidence.size_bytes,
                'compression': evidence.compression,
                'previous_hash': evidence.previous_hash,
            }, f, indent=2)
        
        # Update index
        self.index[str(evidence.id)] = evidence
        
        return evidence
    
    def store_request_response(self, scan_id: UUID, target_id: UUID,
                              finding_id: UUID, request: str, 
                              response: str) -> Evidence:
        """Store HTTP request/response pair"""
        content = json.dumps({
            'request': request,
            'response': response,
        }, indent=2)
        
        return self.store_evidence(
            scan_id=scan_id,
            target_id=target_id,
            finding_id=finding_id,
            evidence_type="http_transaction",
            content=content,
            mime_type="application/json"
        )
    
    def store_log(self, scan_id: UUID, target_id: UUID,
                 log_entry: str) -> Evidence:
        """Store audit log entry"""
        content = json.dumps({
            'timestamp': datetime.utcnow().isoformat(),
            'log': log_entry,
        }, indent=2)
        
        return self.store_evidence(
            scan_id=scan_id,
            target_id=target_id,
            finding_id=None,
            evidence_type="audit_log",
            content=content,
            mime_type="application/json"
        )
    
    def get_evidence(self, evidence_id: UUID) -> Optional[Evidence]:
        """Retrieve evidence by ID"""
        # Check index first
        if str(evidence_id) in self.index:
            return self.index[str(evidence_id)]
        
        # Load from disk
        evidence_path = self._get_evidence_path(evidence_id)
        
        if not evidence_path.exists():
            return None
        
        with open(evidence_path, 'r') as f:
            data = json.load(f)
        
        evidence = Evidence(
            id=UUID(data['id']),
            scan_id=UUID(data['scan_id']),
            target_id=UUID(data['target_id']),
            finding_id=UUID(data['finding_id']) if data.get('finding_id') else None,
            evidence_type=data['evidence_type'],
            content=data['content'],
            content_hash=data['content_hash'],
            mime_type=data['mime_type'],
            created_at=datetime.fromisoformat(data['created_at']),
            size_bytes=data['size_bytes'],
            compression=data['compression'],
            previous_hash=data.get('previous_hash', ''),
        )
        
        # Decompress if needed
        if evidence.compression:
            decompressed = gzip.decompress(evidence.content.encode('latin-1'))
            evidence.content = decompressed.decode('utf-8')
        
        self.index[str(evidence_id)] = evidence
        return evidence
    
    def get_evidence_for_finding(self, finding_id: UUID) -> List[Evidence]:
        """Get all evidence for a finding"""
        evidence_list = []
        
        for evidence in self.index.values():
            if evidence.finding_id == finding_id:
                evidence_list.append(evidence)
        
        return evidence_list
    
    def verify_chain(self) -> bool:
        """Verify chain of custody"""
        sorted_evidence = sorted(
            self.index.values(),
            key=lambda e: e.created_at
        )
        
        for i, evidence in enumerate(sorted_evidence):
            if i == 0:
                continue
            
            if evidence.previous_hash != sorted_evidence[i-1].content_hash:
                evidence.chain_valid = False
                return False
        
        return True
    
    def apply_retention_policy(self):
        """Apply retention policy to evidence"""
        cutoff_date = datetime.utcnow() - timedelta(days=self.config.retention_days)
        
        for evidence_id, evidence in list(self.index.items()):
            if evidence.created_at < cutoff_date:
                # Delete old evidence
                evidence_path = self._get_evidence_path(evidence.id)
                if evidence_path.exists():
                    evidence_path.unlink()
                
                del self.index[evidence_id]
    
    def export_audit_log(self, start_date: datetime, 
                        end_date: datetime) -> str:
        """Export audit log for date range"""
        logs = []
        
        for evidence in self.index.values():
            if (evidence.evidence_type == "audit_log" and
                start_date <= evidence.created_at <= end_date):
                logs.append(evidence.content)
        
        return "\n".join(logs)
    
    def get_storage_stats(self) -> Dict[str, Any]:
        """Get storage statistics"""
        total_size = 0
        evidence_count = 0
        evidence_types: Dict[str, int] = {}
        
        for evidence in self.index.values():
            total_size += evidence.size_bytes
            evidence_count += 1
            evidence_types[evidence.evidence_type] = \
                evidence_types.get(evidence.evidence_type, 0) + 1
        
        return {
            'total_evidence_items': evidence_count,
            'total_size_bytes': total_size,
            'total_size_mb': total_size / (1024 * 1024),
            'evidence_types': evidence_types,
            'retention_days': self.config.retention_days,
            'chain_valid': self.verify_chain(),
        }


class ImmutableLog:
    """Append-only audit log with cryptographic chaining"""
    
    def __init__(self, log_path: str):
        self.log_path = Path(log_path)
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        
        # Initialize or load log
        if not self.log_path.exists():
            self._write_genesis_block()
    
    def _write_genesis_block(self):
        """Write genesis block"""
        block = {
            'index': 0,
            'timestamp': datetime.utcnow().isoformat(),
            'data': 'GENESIS',
            'previous_hash': '0' * 64,
            'hash': self._compute_hash('GENESIS' + '0' * 64),
        }
        
        with open(self.log_path, 'w') as f:
            json.dump(block, f, indent=2)
    
    def _compute_hash(self, data: str) -> str:
        """Compute hash for block"""
        return hashlib.sha256(data.encode()).hexdigest()
    
    def _get_last_hash(self) -> str:
        """Get hash of last block"""
        with open(self.log_path, 'r') as f:
            last_block = json.load(f)
        return last_block['hash']
    
    def append(self, data: str):
        """Append new entry to log"""
        # Read current log
        with open(self.log_path, 'r') as f:
            blocks = [json.load(f)]
        
        # Try to read as JSON array
        try:
            with open(self.log_path, 'r') as f:
                import json
                content = f.read()
                if content.strip().startswith('['):
                    blocks = json.loads(content)
                    if blocks:
                        last_block = blocks[-1]
                    else:
                        last_block = {'index': -1, 'hash': '0' * 64}
                else:
                    last_block = blocks[0] if blocks else {'index': -1, 'hash': '0' * 64}
        except:
            last_block = {'index': -1, 'hash': '0' * 64}
        
        # Create new block
        new_block = {
            'index': last_block.get('index', -1) + 1,
            'timestamp': datetime.utcnow().isoformat(),
            'data': data,
            'previous_hash': last_block.get('hash', '0' * 64),
        }
        new_block['hash'] = self._compute_hash(
            data + new_block['previous_hash']
        )
        
        # Append to file
        with open(self.log_path, 'a') as f:
            f.write('\n' + json.dumps(new_block))
    
    def verify(self) -> bool:
        """Verify log integrity"""
        try:
            with open(self.log_path, 'r') as f:
                content = f.read()
                if content.strip().startswith('['):
                    blocks = json.loads(content)
                else:
                    blocks = [json.loads(line) for line in content.strip().split('\n') if line]
            
            for i, block in enumerate(blocks):
                if i == 0:
                    continue
                
                expected_hash = self._compute_hash(
                    block['data'] + block['previous_hash']
                )
                
                if block['hash'] != expected_hash:
                    return False
            
            return True
        except Exception:
            return False
