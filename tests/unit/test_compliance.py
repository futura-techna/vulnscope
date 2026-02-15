"""
VulnScope - Compliance Tests
"""

import pytest
import uuid
from src.evidence.compliance import (
    PCICompliance, NIS2Compliance, SOC2Compliance,
    HIPAACompliance, ISO27001Compliance, ComplianceReport
)
from src.core.models import Finding, Severity, VulnerabilityType, Status


class TestPCICompliance:
    def test_compliant_without_findings(self):
        checker = PCICompliance()
        result = checker.check([])
        assert result["compliant"] == True
    
    def test_requirements(self):
        checker = PCICompliance()
        reqs = checker.requirements
        assert len(reqs) == 4


class TestComplianceReport:
    def test_supported_standards(self):
        report = ComplianceReport()
        standards = report.get_supported_standards()
        assert "PCI-DSS" in standards
        assert "NIS2" in standards
        assert "SOC2" in standards
        assert "HIPAA" in standards
        assert "ISO27001" in standards


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
