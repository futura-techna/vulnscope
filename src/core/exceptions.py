"""
VulnScope - Custom Exceptions
Exception classes for error handling
"""


class VulnScopeError(Exception):
    """Base exception for VulnScope"""
    pass


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
