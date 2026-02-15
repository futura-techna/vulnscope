"""
VulnScope - Core Module
Core data models and base classes
"""

from .models import (
    Vulnerability,
    Scan,
    Target,
    Endpoint,
    Finding,
    Severity,
    Status,
)
from .exceptions import (
    VulnScopeError,
    ScanError,
    DiscoveryError,
    AuthenticationError,
)

__all__ = [
    "Vulnerability",
    "Scan",
    "Target",
    "Endpoint",
    "Finding",
    "Severity",
    "Status",
    "VulnScopeError",
    "ScanError",
    "DiscoveryError",
    "AuthenticationError",
]
