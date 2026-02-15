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
from .payloads import PayloadGenerator

__all__ = [
    "Scanner",
    "ScanResult",
    "VulnerabilityFinder",
    "XSSDetector",
    "SQLInjectionDetector",
    "SSRDetector",
    "IDORDetector",
    "Detector",
    "PayloadGenerator",
]
