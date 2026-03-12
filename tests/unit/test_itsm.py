"""
VulnScope - ITSM Integration Unit Tests
Tests for Jira, ServiceNow integrations and ticket management
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime
from uuid import uuid4

from src.integrations.itsm import (
    JiraIntegration, ServiceNowIntegration,
    TicketManager
)
from src.core.models import Finding, Scan, Severity, VulnerabilityType, Status


class TestJiraIntegration:
    """Test Jira ITSM integration"""
    
    def test_initialization(self):
        """Test Jira initialization"""
        jira = JiraIntegration()
        assert jira.name == "Jira"
    
    def test_initialization_with_config(self):
        """Test Jira initialization with config"""
        jira = JiraIntegration(
            url="https://company.atlassian.net",
            user="admin@company.com",
            token="api-token",
            project_key="SEC"
        )
        
        assert jira.url == "https://company.atlassian.net"
        assert jira.user == "admin@company.com"
        assert jira.token == "api-token"
        assert jira.project_key == "SEC"
    
    def test_initialization_from_env(self):
        """Test Jira initialization from environment"""
        with patch.dict('os.environ', {
            'JIRA_URL': 'https://env.atlassian.net',
            'JIRA_USER': 'env@user.com',
            'JIRA_TOKEN': 'env-token',
            'JIRA_PROJECT_KEY': 'ENV'
        }):
            jira = JiraIntegration()
            assert jira.url == 'https://env.atlassian.net'
    
    def test_create_ticket_missing_config(self):
        """Test ticket creation with missing config"""
        jira = JiraIntegration()
        jira.url = None
        
        scan = Scan(id=uuid4(), target_id=uuid4(), name="Test")
        result = jira.create_ticket(scan, [])
        
        assert "error" in result
    
    def test_create_ticket_success(self):
        """Test successful ticket creation"""
        jira = JiraIntegration(
            url="https://company.atlassian.net",
            user="admin@company.com",
            token="api-token",
            project_key="SEC"
        )
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Security Scan",
            status=Status.COMPLETED,
            started_at=datetime.utcnow()
        )
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="SQL Injection",
                description="SQL injection found",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                cwe_id="CWE-89"
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="XSS",
                description="Cross-site scripting",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS
            ),
        ]
        
        result = jira.create_ticket(scan, findings)
        
        assert result["status"] == "created"
        assert "ticket_key" in result
        assert "ticket_url" in result
        assert result["findings_count"] == 2
        assert result["critical_count"] == 1
        assert result["high_count"] == 1
    
    def test_update_ticket(self):
        """Test updating ticket"""
        jira = JiraIntegration(
            url="https://company.atlassian.net",
            user="admin@company.com",
            token="api-token"
        )
        
        result = jira.update_ticket("SEC-123", "In Progress")
        
        assert result["status"] == "updated"
        assert result["ticket_id"] == "SEC-123"
        assert result["new_status"] == "In Progress"
    
    def test_update_ticket_missing_config(self):
        """Test update with missing config"""
        jira = JiraIntegration()
        jira.url = None
        
        result = jira.update_ticket("SEC-123", "Done")
        
        assert "error" in result
    
    def test_create_findings_tickets(self):
        """Test creating individual tickets for findings"""
        jira = JiraIntegration(
            url="https://company.atlassian.net",
            user="admin@company.com",
            token="api-token",
            project_key="SEC"
        )
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test Scan",
            status=Status.COMPLETED
        )
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="Critical Issue",
                description="Critical",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="High Issue",
                description="High",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="Low Issue",
                description="Low",
                severity=Severity.LOW,
                vulnerability_type=VulnerabilityType.INFO_LEAK
            ),
        ]
        
        tickets = jira.create_findings_tickets(scan, findings)
        
        # Should create tickets only for critical and high
        assert len(tickets) == 2
    
    def test_build_description(self):
        """Test Jira description formatting"""
        jira = JiraIntegration()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test Scan",
            status=Status.COMPLETED,
            started_at=datetime.utcnow()
        )
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="SQL Injection",
                description="SQL injection vulnerability",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION,
                cwe_id="CWE-89"
            ),
        ]
        
        description = jira._build_description(scan, findings)
        
        assert "VulnScope" in description
        assert "SQL Injection" in description
        assert "CRITICAL" in description


class TestServiceNowIntegration:
    """Test ServiceNow ITSM integration"""
    
    def test_initialization(self):
        """Test ServiceNow initialization"""
        sn = ServiceNowIntegration()
        assert sn.name == "ServiceNow"
    
    def test_initialization_with_config(self):
        """Test ServiceNow initialization with config"""
        sn = ServiceNowIntegration(
            instance="company",
            user="admin",
            password="password",
            table="incident"
        )
        
        assert sn.instance == "company"
        assert sn.user == "admin"
        assert sn.password == "password"
        assert sn.table == "incident"
        assert "company.service-now.com" in sn.api_url
    
    def test_initialization_from_env(self):
        """Test ServiceNow initialization from environment"""
        with patch.dict('os.environ', {
            'SERVICENOW_INSTANCE': 'env-instance',
            'SERVICENOW_USER': 'env-user',
            'SERVICENOW_PASSWORD': 'env-password'
        }):
            sn = ServiceNowIntegration()
            assert sn.instance == 'env-instance'
    
    def test_create_ticket_missing_config(self):
        """Test ticket creation with missing config"""
        sn = ServiceNowIntegration()
        sn.instance = None
        
        scan = Scan(id=uuid4(), target_id=uuid4(), name="Test")
        result = sn.create_ticket(scan, [])
        
        assert "error" in result
    
    def test_create_ticket_success(self):
        """Test successful ticket creation"""
        sn = ServiceNowIntegration(
            instance="company",
            user="admin",
            password="password"
        )
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Security Scan",
            status=Status.COMPLETED,
            started_at=datetime.utcnow()
        )
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="Critical Vulnerability",
                description="Critical issue found",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
        ]
        
        result = sn.create_ticket(scan, findings)
        
        assert result["status"] == "created"
        assert "ticket_number" in result
        assert "ticket_url" in result
    
    def test_update_ticket(self):
        """Test updating ServiceNow ticket"""
        sn = ServiceNowIntegration(
            instance="company",
            user="admin",
            password="password"
        )
        
        result = sn.update_ticket("INC0012345", "Resolved")
        
        assert result["status"] == "updated"
        assert result["ticket_id"] == "INC0012345"
    
    def test_create_findings_tickets(self):
        """Test creating tickets grouped by severity"""
        sn = ServiceNowIntegration(
            instance="company",
            user="admin",
            password="password"
        )
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test Scan",
            status=Status.COMPLETED
        )
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="Critical 1",
                description="Critical",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="Critical 2",
                description="Critical",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.XSS
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="High 1",
                description="High",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.CSRF
            ),
        ]
        
        tickets = sn.create_findings_tickets(scan, findings)
        
        # Should create one ticket for critical, one for high
        assert len(tickets) == 2
    
    def test_build_description(self):
        """Test ServiceNow description formatting"""
        sn = ServiceNowIntegration()
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test Scan",
            started_at=datetime.utcnow()
        )
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="XSS",
                description="XSS vulnerability",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS,
                remediation="Sanitize input"
            ),
        ]
        
        description = sn._build_description(scan, findings)
        
        assert "VulnScope" in description
        assert "XSS" in description
        assert "Remediation" in description


class TestTicketManager:
    """Test ticket manager"""
    
    def test_initialization(self):
        """Test manager initialization"""
        manager = TicketManager()
        assert len(manager.adapters) == 0
    
    def test_register_adapter(self):
        """Test registering adapter"""
        manager = TicketManager()
        jira = JiraIntegration(
            url="https://company.atlassian.net",
            user="admin",
            token="token",
            project_key="SEC"
        )
        
        manager.register_adapter("jira", jira)
        
        assert "jira" in manager.adapters
        assert manager.adapters["jira"] == jira
    
    def test_create_tickets(self):
        """Test creating tickets"""
        manager = TicketManager()
        
        mock_adapter = Mock()
        mock_adapter.create_ticket.return_value = {"status": "created"}
        
        manager.register_adapter("test", mock_adapter)
        
        scan = Scan(id=uuid4(), target_id=uuid4(), name="Test")
        findings = []
        
        result = manager.create_tickets(scan, findings, system="test")
        
        mock_adapter.create_ticket.assert_called_once()
    
    def test_create_tickets_unknown_system(self):
        """Test creating tickets with unknown system"""
        manager = TicketManager()
        
        scan = Scan(id=uuid4(), target_id=uuid4(), name="Test")
        
        result = manager.create_tickets(scan, [], system="unknown")
        
        assert "error" in result
    
    def test_create_auto_tickets(self):
        """Test auto ticket creation"""
        manager = TicketManager()
        
        mock_jira = Mock()
        mock_jira.create_ticket.return_value = {"status": "jira_created"}
        
        mock_sn = Mock()
        mock_sn.create_ticket.return_value = {"status": "sn_created"}
        
        manager.register_adapter("jira", mock_jira)
        manager.register_adapter("servicenow", mock_sn)
        
        scan = Scan(id=uuid4(), target_id=uuid4(), name="Test")
        findings = []
        
        tickets = manager.create_auto_tickets(
            scan, findings,
            {"systems": ["jira", "servicenow"]}
        )
        
        assert len(tickets) == 2
    
    def test_create_auto_tickets_default_system(self):
        """Test auto ticket creation with default system"""
        manager = TicketManager()
        
        mock_jira = Mock()
        mock_jira.create_ticket.return_value = {"status": "created"}
        
        manager.register_adapter("jira", mock_jira)
        
        scan = Scan(id=uuid4(), target_id=uuid4(), name="Test")
        
        tickets = manager.create_auto_tickets(scan, [], {})
        
        # Should use default system (jira)
        mock_jira.create_ticket.assert_called_once()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])