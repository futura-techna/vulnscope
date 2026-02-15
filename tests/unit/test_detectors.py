"""
VulnScope - Detector Tests
"""

import pytest
from src.scanner.detectors import (
    XSSDetector, SQLInjectionDetector, SSRDetector, 
    IDORDetector, CSRFDetector
)
from src.core.models import Severity, VulnerabilityType


class TestXSSDetector:
    def test_detector_properties(self):
        detector = XSSDetector()
        assert detector.vulnerability_type == VulnerabilityType.XSS
        assert detector.severity == Severity.HIGH


class TestSQLInjectionDetector:
    def test_detector_properties(self):
        detector = SQLInjectionDetector()
        assert detector.vulnerability_type == VulnerabilityType.SQL_INJECTION
        assert detector.severity == Severity.CRITICAL


class TestSSRDetector:
    def test_detector_properties(self):
        detector = SSRDetector()
        assert detector.vulnerability_type == VulnerabilityType.SSRF
        assert detector.severity == Severity.HIGH


class TestIDORDetector:
    def test_detector_properties(self):
        detector = IDORDetector()
        assert detector.vulnerability_type == VulnerabilityType.IDOR
        assert detector.severity == Severity.MEDIUM


class TestCSRFDetector:
    def test_detector_properties(self):
        detector = CSRFDetector()
        assert detector.vulnerability_type == VulnerabilityType.CSRF
        assert detector.severity == Severity.HIGH


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
