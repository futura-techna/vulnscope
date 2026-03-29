"""
VulnScope - DAST Scanner Module
Dynamic Application Security Testing Engine
"""

from .scanner import Scanner, ScanResult, VulnerabilityFinder
from .detectors import (
    XSSDetector,
    SQLInjectionDetector,
    SSRDetector,
    IDORDetector,
    Detector,
)
from .cloud_detectors import (
    CloudSecurityDetector,
    IAMDetector,
    CryptographicHygieneDetector,
    ZeroTrustDetector,
    NetworkSecurityDetector,
)
from .supply_chain_detectors import (
    SupplyChainDetector,
    SupplyChainIntegrityDetector,
    DependencyConfusionDetector,
)
from .sca_scanner import SCAScanner
from .payloads import PayloadGenerator

__all__ = [
    "Scanner",
    "ScanResult",
    "VulnerabilityFinder",
    # Original detectors
    "XSSDetector",
    "SQLInjectionDetector",
    "SSRDetector",
    "IDORDetector",
    "Detector",
    # Cloud & IAM
    "CloudSecurityDetector",
    "IAMDetector",
    # Cryptographic Hygiene
    "CryptographicHygieneDetector",
    # Zero Trust
    "ZeroTrustDetector",
    # Network Security
    "NetworkSecurityDetector",
    # Supply Chain
    "SupplyChainDetector",
    "SupplyChainIntegrityDetector",
    "DependencyConfusionDetector",
    # SCA Scanner
    "SCAScanner",
    # Utils
    "PayloadGenerator",
]
