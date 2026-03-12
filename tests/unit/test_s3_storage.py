"""
VulnScope - S3 Storage Tests
Tests for S3-compatible storage integration
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
import io
from datetime import datetime

from src.evidence.s3_storage import (
    S3StorageClient, S3Config, StorageError
)


class TestS3Config:
    """Test S3 configuration"""
    
    def test_default_config(self):
        config = S3Config()
        
        assert config.endpoint_url is not None
        assert config.bucket_name is not None
        assert config.region == "us-east-1"
    
    def test_custom_config(self):
        config = S3Config(
            endpoint_url="https://s3.custom.com",
            bucket_name="custom-bucket",
            region="eu-west-1",
            access_key="custom-key",
            secret_key="custom-secret"
        )
        
        assert config.endpoint_url == "https://s3.custom.com"
        assert config.bucket_name == "custom-bucket"
        assert config.region == "eu-west-1"


class TestS3StorageClient:
    """Test S3 storage client"""
    
    @pytest.fixture
    def mock_s3_client(self):
        with patch('src.evidence.s3_storage.boto3.client') as mock:
            yield mock
    
    @pytest.fixture
    def storage_client(self, mock_s3_client):
        config = S3Config(
            endpoint_url="http://localhost:9000",
            bucket_name="test-bucket"
        )
        return S3StorageClient(config)
    
    def test_init(self, storage_client):
        assert storage_client.config.bucket_name == "test-bucket"
    
    def test_upload_file(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_s3_instance.upload_fileobj.return_value = None
        
        file_data = io.BytesIO(b"test content")
        result = storage_client.upload_file(
            file_data,
            key="reports/test-report.pdf",
            content_type="application/pdf"
        )
        
        assert result is not None
        mock_s3_instance.upload_fileobj.assert_called_once()
    
    def test_upload_file_with_metadata(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_s3_instance.upload_fileobj.return_value = None
        
        file_data = io.BytesIO(b"test content")
        result = storage_client.upload_file(
            file_data,
            key="reports/test-report.pdf",
            content_type="application/pdf",
            metadata={"scan_id": "scan-123", "created_by": "user-1"}
        )
        
        assert result is not None
    
    def test_download_file(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_body = Mock()
        mock_body.read.return_value = b"file content"
        mock_s3_instance.get_object.return_value = {
            "Body": mock_body,
            "ContentType": "application/pdf"
        }
        
        result = storage_client.download_file("reports/test-report.pdf")
        
        assert result is not None
        mock_s3_instance.get_object.assert_called_once()
    
    def test_download_nonexistent_file(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_s3_instance.get_object.side_effect = Exception("NoSuchKey")
        
        with pytest.raises(StorageError):
            storage_client.download_file("nonexistent-file.pdf")
    
    def test_delete_file(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_s3_instance.delete_object.return_value = {}
        
        result = storage_client.delete_file("reports/test-report.pdf")
        
        assert result is True
        mock_s3_instance.delete_object.assert_called_once()
    
    def test_list_files(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_s3_instance.list_objects_v2.return_value = {
            "Contents": [
                {"Key": "reports/report1.pdf", "Size": 1024},
                {"Key": "reports/report2.pdf", "Size": 2048}
            ]
        }
        
        result = storage_client.list_files(prefix="reports/")
        
        assert len(result) == 2
        assert result[0]["Key"] == "reports/report1.pdf"
    
    def test_list_empty_bucket(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_s3_instance.list_objects_v2.return_value = {}
        
        result = storage_client.list_files(prefix="reports/")
        
        assert result == []
    
    def test_generate_presigned_url(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_s3_instance.generate_presigned_url.return_value = (
            "https://s3.example.com/signed-url"
        )
        
        result = storage_client.generate_presigned_url(
            "reports/test-report.pdf",
            expiration=3600
        )
        
        assert result.startswith("https://")
        mock_s3_instance.generate_presigned_url.assert_called_once()
    
    def test_file_exists_true(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_s3_instance.head_object.return_value = {"ContentLength": 1024}
        
        result = storage_client.file_exists("reports/test-report.pdf")
        
        assert result is True
    
    def test_file_exists_false(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_s3_instance.head_object.side_effect = Exception("NotFound")
        
        result = storage_client.file_exists("nonexistent.pdf")
        
        assert result is False
    
    def test_get_file_metadata(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_s3_instance.head_object.return_value = {
            "ContentLength": 1024,
            "ContentType": "application/pdf",
            "LastModified": datetime.utcnow(),
            "Metadata": {"scan_id": "scan-123"}
        }
        
        result = storage_client.get_file_metadata("reports/test-report.pdf")
        
        assert result["ContentLength"] == 1024
        assert result["Metadata"]["scan_id"] == "scan-123"
    
    def test_copy_file(self, storage_client, mock_s3_client):
        mock_s3_instance = mock_s3_client.return_value
        mock_s3_instance.copy_object.return_value = {}
        
        result = storage_client.copy_file(
            "reports/source.pdf",
            "reports/destination.pdf"
        )
        
        assert result is True
        mock_s3_instance.copy_object.assert_called_once()


class TestStorageError:
    """Test storage error handling"""
    
    def test_storage_error_message(self):
        error = StorageError("Failed to upload file")
        
        assert "Failed to upload file" in str(error)
    
    def test_storage_error_with_details(self):
        error = StorageError(
            "Upload failed",
            details={"key": "test.pdf", "reason": "Access denied"}
        )
        
        assert error.details["key"] == "test.pdf"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])