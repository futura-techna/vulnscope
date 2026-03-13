"""
VulnScope - Report Storage
Persistent storage for generated reports
"""

import os
import json
from datetime import datetime
from pathlib import Path
from typing import Optional, Dict, Any
from uuid import UUID, uuid4


class ReportStorage:
    """Handles persistent storage of report files"""
    
    def __init__(self, storage_dir: str = None):
        """Initialize report storage"""
        if storage_dir:
            self.storage_dir = Path(storage_dir)
        else:
            # Default storage directory
            self.storage_dir = Path(os.environ.get(
                'VULNSCOPE_REPORTS_DIR',
                Path(__file__).parent.parent.parent / 'reports'
            ))
        
        # Create storage directory if it doesn't exist
        self.storage_dir.mkdir(parents=True, exist_ok=True)
        
        # Metadata file for tracking reports
        self.metadata_file = self.storage_dir / 'reports_metadata.json'
        self._metadata = self._load_metadata()
    
    def _load_metadata(self) -> Dict[str, Any]:
        """Load reports metadata from file"""
        if self.metadata_file.exists():
            try:
                with open(self.metadata_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, IOError):
                return {}
        return {}
    
    def _save_metadata(self):
        """Save reports metadata to file"""
        with open(self.metadata_file, 'w') as f:
            json.dump(self._metadata, f, indent=2, default=str)
    
    def save_report(self, report_id: UUID, content: str, format: str, 
                    scan_id: UUID, name: str) -> Dict[str, Any]:
        """Save a report to disk"""
        report_id_str = str(report_id)
        
        # Determine file extension
        extension = format.lower()
        if extension == 'sarif':
            extension = 'sarif.json'
        
        # Create filename
        filename = f"report_{report_id_str}.{extension}"
        filepath = self.storage_dir / filename
        
        # Write report content
        with open(filepath, 'w', encoding='utf-8') as f:
            f.write(content)
        
        # Get file size
        file_size = filepath.stat().st_size
        size_str = self._format_size(file_size)
        
        # Store metadata
        self._metadata[report_id_str] = {
            'id': report_id_str,
            'scan_id': str(scan_id),
            'name': name,
            'format': format,
            'filename': filename,
            'size': size_str,
            'file_size': file_size,
            'created_at': datetime.utcnow().isoformat(),
        }
        self._save_metadata()
        
        return self._metadata[report_id_str]
    
    def get_report(self, report_id: UUID) -> Optional[str]:
        """Get report content by ID"""
        report_id_str = str(report_id)
        
        if report_id_str not in self._metadata:
            return None
        
        metadata = self._metadata[report_id_str]
        filepath = self.storage_dir / metadata['filename']
        
        if not filepath.exists():
            return None
        
        with open(filepath, 'r', encoding='utf-8') as f:
            return f.read()
    
    def get_report_metadata(self, report_id: UUID) -> Optional[Dict[str, Any]]:
        """Get report metadata by ID"""
        return self._metadata.get(str(report_id))
    
    def list_reports(self) -> list:
        """List all reports"""
        return list(self._metadata.values())
    
    def delete_report(self, report_id: UUID) -> bool:
        """Delete a report"""
        report_id_str = str(report_id)
        
        if report_id_str not in self._metadata:
            return False
        
        metadata = self._metadata[report_id_str]
        filepath = self.storage_dir / metadata['filename']
        
        # Delete file
        if filepath.exists():
            filepath.unlink()
        
        # Remove from metadata
        del self._metadata[report_id_str]
        self._save_metadata()
        
        return True
    
    def _format_size(self, size_bytes: int) -> str:
        """Format file size in human readable format"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
    
    def get_storage_path(self) -> Path:
        """Get the storage directory path"""
        return self.storage_dir


# Global storage instance
_storage_instance: Optional[ReportStorage] = None


def get_report_storage() -> ReportStorage:
    """Get or create the global report storage instance"""
    global _storage_instance
    if _storage_instance is None:
        _storage_instance = ReportStorage()
    return _storage_instance