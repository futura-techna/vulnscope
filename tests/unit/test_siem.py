"""
VulnScope - SIEM Integration Unit Tests
Tests for Splunk, ELK integrations and webhook notifications
"""

import pytest
from unittest.mock import Mock, patch
from datetime import datetime
from uuid import uuid4

from src.integrations.siem import (
    SplunkIntegration, ELKIntegration,
    ObservabilityManager, WebhookNotifier
)
from src.core.models import Finding, Scan, Severity, VulnerabilityType, Status


class TestSplunkIntegration:
    """Test Splunk SIEM integration"""
    
    def test_initialization(self):
        """Test Splunk initialization"""
        splunk = SplunkIntegration()
        assert splunk.name == "Splunk"
    
    def test_initialization_with_config(self):
        """Test Splunk initialization with config"""
        splunk = SplunkIntegration(
            url="https://splunk.example.com",
            token="test-token",
            index="security"
        )
        
        assert splunk.url == "https://splunk.example.com"
        assert splunk.token == "test-token"
        assert splunk.index == "security"
    
    def test_initialization_from_env(self):
        """Test Splunk initialization from environment"""
        with patch.dict('os.environ', {
            'SPLUNK_URL': 'https://env-splunk.example.com',
            'SPLUNK_TOKEN': 'env-token',
            'SPLUNK_INDEX': 'env-index'
        }):
            splunk = SplunkIntegration()
            assert splunk.url == 'https://env-splunk.example.com'
    
    def test_send_event_missing_config(self):
        """Test send event with missing config"""
        splunk = SplunkIntegration()
        splunk.url = None
        
        result = splunk.send_event({"id": "test"})
        
        assert "error" in result
        assert "Missing" in result["error"]
    
    def test_send_event_success(self):
        """Test successful event send"""
        splunk = SplunkIntegration(
            url="https://splunk.example.com",
            token="test-token"
        )
        
        event = {
            "id": "event-123",
            "type": "test",
            "timestamp": 1700000000
        }
        
        result = splunk.send_event(event)
        
        assert result["status"] == "sent"
        assert result["event_id"] == "event-123"
    
    def test_create_alert(self):
        """Test creating Splunk alert"""
        splunk = SplunkIntegration(
            url="https://splunk.example.com",
            token="test-token"
        )
        
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
                description="SQLi found",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="XSS",
                description="XSS found",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS
            ),
        ]
        
        result = splunk.create_alert(scan, findings)
        
        assert result["status"] == "alert_created"
        assert result["critical_count"] == 1
        assert result["high_count"] == 1
    
    def test_send_findings(self):
        """Test sending individual findings"""
        splunk = SplunkIntegration(
            url="https://splunk.example.com",
            token="test-token"
        )
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="Finding 1",
                description="Test",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS,
                discovered_at=datetime.utcnow()
            ),
        ]
        
        result = splunk.send_findings(findings)
        
        assert result["status"] == "completed"
        assert result["findings_sent"] >= 0


class TestELKIntegration:
    """Test ELK SIEM integration"""
    
    def test_initialization(self):
        """Test ELK initialization"""
        elk = ELKIntegration()
        assert elk.name == "ELK"
    
    def test_initialization_with_config(self):
        """Test ELK initialization with config"""
        elk = ELKIntegration(
            url="https://elasticsearch.example.com",
            index="vulnscope",
            api_key="test-api-key"
        )
        
        assert elk.url == "https://elasticsearch.example.com"
        assert elk.index == "vulnscope"
        assert elk.api_key == "test-api-key"
    
    def test_send_event_missing_config(self):
        """Test send event with missing config"""
        elk = ELKIntegration()
        elk.url = None
        
        result = elk.send_event({"id": "test"})
        
        assert "error" in result
    
    def test_send_event_success(self):
        """Test successful event send"""
        elk = ELKIntegration(
            url="https://elasticsearch.example.com",
            api_key="test-key"
        )
        
        event = {
            "id": "event-456",
            "type": "test"
        }
        
        result = elk.send_event(event)
        
        assert result["status"] == "indexed"
        assert result["event_id"] == "event-456"
    
    def test_create_alert(self):
        """Test creating ELK alert"""
        elk = ELKIntegration(
            url="https://elasticsearch.example.com",
            api_key="test-key"
        )
        
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
                title="Critical Finding",
                description="Critical",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            ),
        ]
        
        result = elk.create_alert(scan, findings)
        
        assert result["status"] == "alert_created"
        assert result["scan_id"] == str(scan_id)
    
    def test_send_findings(self):
        """Test sending findings to ELK"""
        elk = ELKIntegration(
            url="https://elasticsearch.example.com",
            api_key="test-key"
        )
        
        scan_id = uuid4()
        target_id = uuid4()
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=scan_id,
                target_id=target_id,
                title="Finding",
                description="Test",
                severity=Severity.MEDIUM,
                vulnerability_type=VulnerabilityType.XSS,
                discovered_at=datetime.utcnow()
            ),
        ]
        
        result = elk.send_findings(findings)
        
        assert result["status"] == "completed"
    
    def test_create_kibana_visualization(self):
        """Test Kibana visualization creation"""
        elk = ELKIntegration()
        
        result = elk.create_kibana_visualization()
        
        assert result["status"] == "created"
        assert "visualization" in result
        assert result["visualization"]["title"] == "VulnScope Findings"


class TestObservabilityManager:
    """Test observability manager"""
    
    def test_initialization(self):
        """Test manager initialization"""
        manager = ObservabilityManager()
        assert len(manager.adapters) == 0
    
    def test_register_adapter(self):
        """Test registering adapter"""
        manager = ObservabilityManager()
        splunk = SplunkIntegration(
            url="https://splunk.example.com",
            token="test"
        )
        
        manager.register_adapter("splunk", splunk)
        
        assert "splunk" in manager.adapters
        assert manager.adapters["splunk"] == splunk
    
    def test_send_to_all(self):
        """Test sending to all adapters"""
        manager = ObservabilityManager()
        
        # Register mock adapters
        mock_splunk = Mock()
        mock_splunk.send_event.return_value = {"status": "sent"}
        
        mock_elk = Mock()
        mock_elk.send_event.return_value = {"status": "indexed"}
        
        manager.register_adapter("splunk", mock_splunk)
        manager.register_adapter("elk", mock_elk)
        
        event = {"id": "test-event"}
        results = manager.send_to_all(event)
        
        assert "splunk" in results
        assert "elk" in results
        mock_splunk.send_event.assert_called_once_with(event)
        mock_elk.send_event.assert_called_once_with(event)
    
    def test_create_scan_observability(self):
        """Test creating scan observability"""
        manager = ObservabilityManager()
        
        mock_splunk = Mock()
        mock_splunk.create_alert.return_value = {"status": "created"}
        
        manager.register_adapter("splunk", mock_splunk)
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Test",
            status=Status.COMPLETED
        )
        
        findings = []
        
        results = manager.create_scan_observability(
            scan, findings, {"systems": ["splunk"]}
        )
        
        assert "splunk" in results
        mock_splunk.create_alert.assert_called_once()
    
    def test_create_scan_observability_with_findings(self):
        """Test creating scan observability with findings"""
        manager = ObservabilityManager()
        
        mock_adapter = Mock()
        mock_adapter.create_alert.return_value = {"status": "created"}
        mock_adapter.send_findings.return_value = {"status": "sent"}
        
        manager.register_adapter("test", mock_adapter)
        
        scan = Scan(
            id=uuid4(),
            target_id=uuid4(),
            name="Test",
            status=Status.COMPLETED
        )
        
        findings = [
            Finding(
                id=uuid4(),
                scan_id=uuid4(),
                target_id=uuid4(),
                title="Test",
                description="Test",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS
            )
        ]
        
        results = manager.create_scan_observability(
            scan, findings,
            {"systems": ["test"], "send_findings": True}
        )
        
        mock_adapter.send_findings.assert_called_once()


class TestWebhookNotifier:
    """Test webhook notifications"""
    
    def test_initialization(self):
        """Test webhook initialization"""
        webhook = WebhookNotifier()
        assert webhook.webhook_url is None or isinstance(webhook.webhook_url, str)
    
    def test_initialization_with_url(self):
        """Test initialization with URL"""
        webhook = WebhookNotifier(webhook_url="https://hooks.example.com/webhook")
        assert webhook.webhook_url == "https://hooks.example.com/webhook"
    
    def test_send_notification_missing_url(self):
        """Test notification with missing URL"""
        webhook = WebhookNotifier()
        webhook.webhook_url = None
        
        scan = Scan(
            id=uuid4(),
            target_id=uuid4(),
            name="Test",
            status=Status.COMPLETED
        )
        
        result = webhook.send_notification(scan, [])
        
        assert "error" in result
    
    def test_send_notification_success(self):
        """Test successful notification"""
        webhook = WebhookNotifier(webhook_url="https://hooks.example.com/webhook")
        
        scan_id = uuid4()
        target_id = uuid4()
        
        scan = Scan(
            id=scan_id,
            target_id=target_id,
            name="Security Scan",
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
        ]
        
        result = webhook.send_notification(scan, findings)
        
        assert result["status"] == "sent"
        assert "payload" in result
        assert result["payload"]["text"] != ""
    
    def test_send_notification_custom_message(self):
        """Test notification with custom message"""
        webhook = WebhookNotifier(webhook_url="https://hooks.example.com/webhook")
        
        scan = Scan(
            id=uuid4(),
            target_id=uuid4(),
            name="Test",
            status=Status.COMPLETED
        )
        
        result = webhook.send_notification(scan, [], message="Custom alert message")
        
        assert result["status"] == "sent"
        assert result["payload"]["text"] == "Custom alert message"
    
    def test_notification_attachment_color(self):
        """Test notification attachment colors based on severity"""
        webhook = WebhookNotifier(webhook_url="https://hooks.example.com/webhook")
        
        scan = Scan(
            id=uuid4(),
            target_id=uuid4(),
            name="Test",
            status=Status.COMPLETED
        )
        
        # Critical findings - red/danger
        critical_findings = [
            Finding(
                id=uuid4(),
                scan_id=uuid4(),
                target_id=uuid4(),
                title="Critical",
                description="Critical",
                severity=Severity.CRITICAL,
                vulnerability_type=VulnerabilityType.SQL_INJECTION
            )
        ]
        
        result = webhook.send_notification(scan, critical_findings)
        assert result["payload"]["attachments"][0]["color"] == "danger"
        
        # High findings - warning
        high_findings = [
            Finding(
                id=uuid4(),
                scan_id=uuid4(),
                target_id=uuid4(),
                title="High",
                description="High",
                severity=Severity.HIGH,
                vulnerability_type=VulnerabilityType.XSS
            )
        ]
        
        result = webhook.send_notification(scan, high_findings)
        assert result["payload"]["attachments"][0]["color"] == "warning"
        
        # No critical/high - good
        low_findings = [
            Finding(
                id=uuid4(),
                scan_id=uuid4(),
                target_id=uuid4(),
                title="Low",
                description="Low",
                severity=Severity.LOW,
                vulnerability_type=VulnerabilityType.INFO_LEAK
            )
        ]
        
        result = webhook.send_notification(scan, low_findings)
        assert result["payload"]["attachments"][0]["color"] == "good"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])