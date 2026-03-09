"""
VulnScope - Exceptions Unit Tests
Tests for custom exceptions
"""

import pytest
from src.core.exceptions import (
    VulnScopeError, ScanError, DiscoveryError,
    AuthenticationError, ConfigurationError,
    ValidationError, RateLimitError
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])