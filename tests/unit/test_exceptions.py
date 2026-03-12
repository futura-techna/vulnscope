"""
VulnScope - Exceptions Unit Tests
Tests for custom exceptions
"""

import pytest
from src.core.exceptions import (
    VulnScopeError, ScanError, DiscoveryError,
    AuthenticationError, ConfigurationError,
    ValidationError, RateLimitError, StorageError
)


class TestVulnScopeError:
    """Test base VulnScopeError"""
    
    def test_base_exception(self):
        error = VulnScopeError("Test error")
        assert str(error) == "Test error"
    
    def test_inherits_from_exception(self):
        error = VulnScopeError("Test")
        assert isinstance(error, Exception)


class TestScanError:
    """Test ScanError"""
    
    def test_scan_error_message(self):
        error = ScanError("Scan failed")
        assert str(error) == "Scan failed"
    
    def test_scan_error_inherits_from_base(self):
        error = ScanError("Test")
        assert isinstance(error, VulnScopeError)
    
    def test_scan_error_with_details(self):
        error = ScanError("Scan failed", details={"endpoint": "/api/test"})
        assert error.details is not None


class TestDiscoveryError:
    """Test DiscoveryError"""
    
    def test_discovery_error_message(self):
        error = DiscoveryError("Discovery failed")
        assert str(error) == "Discovery failed"
    
    def test_discovery_error_inherits_from_base(self):
        error = DiscoveryError("Test")
        assert isinstance(error, VulnScopeError)


class TestAuthenticationError:
    """Test AuthenticationError"""
    
    def test_auth_error_message(self):
        error = AuthenticationError("Authentication failed")
        assert str(error) == "Authentication failed"
    
    def test_auth_error_inherits_from_base(self):
        error = AuthenticationError("Test")
        assert isinstance(error, VulnScopeError)


class TestConfigurationError:
    """Test ConfigurationError"""
    
    def test_config_error_message(self):
        error = ConfigurationError("Invalid configuration")
        assert str(error) == "Invalid configuration"
    
    def test_config_error_inherits_from_base(self):
        error = ConfigurationError("Test")
        assert isinstance(error, VulnScopeError)


class TestValidationError:
    """Test ValidationError"""
    
    def test_validation_error_message(self):
        error = ValidationError("Validation failed")
        assert str(error) == "Validation failed"
    
    def test_validation_error_inherits_from_base(self):
        error = ValidationError("Test")
        assert isinstance(error, VulnScopeError)
    
    def test_validation_error_with_field(self):
        error = ValidationError("Invalid field", field="url")
        assert error.field == "url"


class TestRateLimitError:
    """Test RateLimitError"""
    
    def test_rate_limit_error_message(self):
        error = RateLimitError("Rate limit exceeded")
        assert str(error) == "Rate limit exceeded"
    
    def test_rate_limit_error_inherits_from_base(self):
        error = RateLimitError("Test")
        assert isinstance(error, VulnScopeError)
    
    def test_rate_limit_error_with_retry_after(self):
        error = RateLimitError("Rate limited", retry_after=60)
        assert error.retry_after == 60


class TestStorageError:
    """Test StorageError"""
    
    def test_storage_error_message(self):
        error = StorageError("Storage failed")
        assert str(error) == "Storage failed"
    
    def test_storage_error_inherits_from_base(self):
        error = StorageError("Test")
        assert isinstance(error, VulnScopeError)
    
    def test_storage_error_with_path(self):
        error = StorageError("File not found", path="/var/data/file.db")
        assert error.path == "/var/data/file.db"


class TestExceptionHandling:
    """Test exception handling patterns"""
    
    def test_catch_specific_exception(self):
        with pytest.raises(ScanError):
            raise ScanError("Test error")
    
    def test_catch_base_exception(self):
        with pytest.raises(VulnScopeError):
            raise ScanError("Test error")
    
    def test_exception_context(self):
        try:
            raise ScanError("Scan failed")
        except VulnScopeError as e:
            assert "Scan failed" in str(e)


class TestVulnScopeErrorKwargs:
    """Test VulnScopeError with additional keyword arguments"""
    
    def test_error_with_multiple_kwargs(self):
        error = VulnScopeError(
            "Multiple attributes",
            code=500,
            detail="Internal server error",
            timestamp="2024-01-01"
        )
        
        assert error.message == "Multiple attributes"
        assert error.code == 500
        assert error.detail == "Internal server error"
        assert error.timestamp == "2024-01-01"
    
    def test_error_empty_message(self):
        error = VulnScopeError()
        assert str(error) == ""
    
    def test_error_with_none_message(self):
        error = VulnScopeError(None)
        # Should handle None gracefully
        assert error.message is None
    
    def test_error_str_representation(self):
        error = VulnScopeError("Test message")
        assert str(error) == "Test message"
    
    def test_error_repr(self):
        error = VulnScopeError("Test")
        repr_str = repr(error)
        assert "VulnScopeError" in repr_str


class TestExceptionInheritance:
    """Test exception inheritance chain"""
    
    def test_all_exceptions_inherit_from_vulnscope_error(self):
        from src.core.exceptions import StorageError
        
        exceptions = [
            ScanError("test"),
            DiscoveryError("test"),
            AuthenticationError("test"),
            ConfigurationError("test"),
            ValidationError("test"),
            RateLimitError("test"),
            StorageError("test")
        ]
        
        for exc in exceptions:
            assert isinstance(exc, VulnScopeError)
            assert isinstance(exc, Exception)
    
    def test_catch_all_with_base_class(self):
        """Test catching all VulnScope errors with base class"""
        errors = [
            ScanError("scan"),
            DiscoveryError("discovery"),
            AuthenticationError("auth"),
            ConfigurationError("config"),
            ValidationError("validation"),
            RateLimitError("rate"),
            StorageError("storage")
        ]
        
        for error in errors:
            try:
                raise error
            except VulnScopeError as e:
                assert str(e) in ["scan", "discovery", "auth", "config", "validation", "rate", "storage"]


class TestExceptionRaising:
    """Test various exception raising patterns"""
    
    def test_raise_scan_error_with_context(self):
        with pytest.raises(ScanError) as exc_info:
            try:
                result = 1 / 0
            except ZeroDivisionError:
                raise ScanError("Division error occurred")
        
        assert "Division error" in str(exc_info.value)
    
    def test_raise_validation_error_with_field_info(self):
        with pytest.raises(ValidationError) as exc_info:
            raise ValidationError("Invalid URL format", field="url", value="not-a-url")
        
        assert exc_info.value.field == "url"
        assert exc_info.value.value == "not-a-url"
    
    def test_raise_rate_limit_with_retry_info(self):
        with pytest.raises(RateLimitError) as exc_info:
            raise RateLimitError("Too many requests", retry_after=30, limit=100)
        
        assert exc_info.value.retry_after == 30
        assert exc_info.value.limit == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
