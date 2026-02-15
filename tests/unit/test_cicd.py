"""
VulnScope - Integration Tests
"""

import pytest
from src.integrations.cicd import SecurityGate
from src.integrations.itsm import JiraIntegration, TicketManager
from src.core.models import Severity, VulnerabilityType


class TestSecurityGate:
    def test_generate_gate_config(self):
        gate = SecurityGate()
        config = gate.generate_gate_config()
        assert config["critical_threshold"] == 0
        assert config["high_threshold"] == 0


class TestJiraIntegration:
    def test_create_ticket(self):
        integration = JiraIntegration(
            url="https://jira.test.com",
            user="testuser",
            token="test-token",
            project_key="SEC"
        )
        assert integration.name == "Jira"


class TestTicketManager:
    def test_register_adapter(self):
        manager = TicketManager()
        adapter = JiraIntegration()
        manager.register_adapter("jira", adapter)
        assert "jira" in manager.adapters


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
