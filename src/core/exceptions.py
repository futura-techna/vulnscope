"""
VulnScope - Custom Exceptions
Exception classes for error handling
"""


class VulnScopeError(Exception):
    """Base exception for VulnScope"""
    
    def __init__(self, message: str = "", **kwargs):
        super().__init__(message)
        self.message = message
        # Store any additional keyword arguments
        for key, value in kwargs.items():
            setattr(self, key, value)
    
    def __str__(self):
        return self.message or super().__str__()


class ScanError(VulnScopeError):
    """Error during scan execution"""
    pass


class DiscoveryError(VulnScopeError):
    """Error during endpoint discovery"""
    pass


class AuthenticationError(VulnScopeError):
    """Authentication error"""
    pass


class RateLimitError(VulnScopeError):
    """Rate limit exceeded"""
    pass


class ConfigurationError(VulnScopeError):
    """Configuration error"""
    pass


class ValidationError(VulnScopeError):
    """Validation error"""
    pass


class StorageError(VulnScopeError):
    """Storage error"""
    pass