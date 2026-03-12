"""
VulnScope - Module Import Tests
"""

import pytest


class TestModules:
    """Test that all modules can be imported"""
    
    def test_scanner_detectors(self):
        from src.scanner.detectors import XSSDetector, SQLInjectionDetector
        assert XSSDetector is not None
        assert SQLInjectionDetector is not None
    
    def test_compliance(self):
        from src.evidence.compliance import ComplianceReport, PCICompliance
        report = ComplianceReport()
        assert "PCI-DSS" in report.get_supported_standards()
    
    def test_cicd(self):
        from src.integrations.cicd import SecurityGate, GitHubIntegration
        gate = SecurityGate()
        assert gate is not None
    
    def test_itsm(self):
        from src.integrations.itsm import JiraIntegration, TicketManager
        assert JiraIntegration is not None
    
    def test_siem(self):
        from src.integrations.siem import SplunkIntegration
        assert SplunkIntegration is not None
    
    def test_security(self):
        from src.utils.security import KillSwitch
        switch = KillSwitch()
        assert switch.is_active == True
    
    def test_websocket(self):
        from src.api.websocket import WebSocketManager
        assert WebSocketManager is not None
    
    @pytest.mark.skipif(
        __import__("importlib").util.find_spec("strawberry") is None,
        reason="strawberry not installed"
    )
    def test_graphql(self):
        from src.api.graphql import schema
        assert schema is not None
    
    def test_async_http(self):
        from src.utils.async_http import AsyncHTTPClient
        assert AsyncHTTPClient is not None
    
    def test_passive_proxy(self):
        from src.discovery.passive_proxy import PassiveScanner
        assert PassiveScanner is not None
    
    @pytest.mark.skip(reason="Streamlit dashboard module not installed")
    def test_dashboard(self):
        # Streamlit dashboard is optional and may not be installed
        pass
    
    def test_s3_storage(self):
        from src.evidence.s3_storage import S3EvidenceStorage
        assert S3EvidenceStorage is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
