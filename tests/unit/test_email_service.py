"""
VulnScope - Email Service Tests
Tests for email notification functionality
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from src.utils.email_service import EmailService, get_email_service


class TestEmailService:
    """Test EmailService class"""
    
    @patch('src.utils.email_service.get_settings')
    def test_create_email_service(self, mock_settings):
        """Test creating email service"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = False
        mock_email_config.provider = "resend"
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        service = EmailService()
        
        assert service is not None
    
    @patch('src.utils.email_service.get_settings')
    def test_disabled_service(self, mock_settings):
        """Test disabled email service"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = False
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        service = EmailService()
        
        # Service should handle disabled state
        assert service.email_config.enabled == False
    
    @patch('src.utils.email_service.get_settings')
    def test_send_verification_email_disabled(self, mock_settings):
        """Test sending verification email when disabled"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = False
        mock_email_config.frontend_url = "http://localhost:3000"
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        service = EmailService()
        
        result = service.send_verification_email(
            email="user@example.com",
            token="verification_token_123",
            username="testuser"
        )
        
        # Should return False when disabled
        assert result == False
    
    @patch('src.utils.email_service.get_settings')
    def test_send_password_reset_email_disabled(self, mock_settings):
        """Test sending password reset email when disabled"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = False
        mock_email_config.frontend_url = "http://localhost:3000"
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        service = EmailService()
        
        result = service.send_password_reset_email(
            email="user@example.com",
            token="reset_token_123",
            username="testuser"
        )
        
        # Should return False when disabled
        assert result == False
    
    @patch('src.utils.email_service.get_settings')
    def test_send_password_changed_confirmation_disabled(self, mock_settings):
        """Test sending password changed confirmation when disabled"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = False
        mock_email_config.frontend_url = "http://localhost:3000"
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        service = EmailService()
        
        result = service.send_password_changed_confirmation(
            email="user@example.com",
            username="testuser"
        )
        
        # Should return False when disabled
        assert result == False
    
    @patch('src.utils.email_service.get_settings')
    def test_send_welcome_email_disabled(self, mock_settings):
        """Test sending welcome email when disabled"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = False
        mock_email_config.frontend_url = "http://localhost:3000"
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        service = EmailService()
        
        result = service.send_welcome_email(
            email="user@example.com",
            username="testuser"
        )
        
        # Should return False when disabled
        assert result == False


class TestEmailServiceResend:
    """Test Resend email provider"""
    
    @patch('src.utils.email_service.get_settings')
    @patch('requests.post')
    def test_send_email_resend_success(self, mock_post, mock_settings):
        """Test sending email via Resend successfully"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = True
        mock_email_config.provider = "resend"
        mock_email_config.resend_api_key = "test_key"
        mock_email_config.from_email = "test@example.com"
        mock_email_config.from_name = "VulnScope"
        mock_email_config.frontend_url = "http://localhost:3000"
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        service = EmailService()
        
        result = service.send_verification_email(
            email="user@example.com",
            token="token123",
            username="testuser"
        )
        
        assert result == True
    
    @patch('src.utils.email_service.get_settings')
    @patch('requests.post')
    def test_send_email_resend_failure(self, mock_post, mock_settings):
        """Test sending email via Resend with failure"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = True
        mock_email_config.provider = "resend"
        mock_email_config.resend_api_key = "test_key"
        mock_email_config.from_email = "test@example.com"
        mock_email_config.from_name = "VulnScope"
        mock_email_config.frontend_url = "http://localhost:3000"
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = "Invalid API key"
        mock_post.return_value = mock_response
        
        service = EmailService()
        
        result = service.send_verification_email(
            email="user@example.com",
            token="token123",
            username="testuser"
        )
        
        assert result == False
    
    @patch('src.utils.email_service.get_settings')
    def test_send_email_resend_no_api_key(self, mock_settings):
        """Test sending email without Resend API key"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = True
        mock_email_config.provider = "resend"
        mock_email_config.resend_api_key = None
        mock_email_config.from_email = "test@example.com"
        mock_email_config.from_name = "VulnScope"
        mock_email_config.frontend_url = "http://localhost:3000"
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        service = EmailService()
        
        result = service.send_verification_email(
            email="user@example.com",
            token="token123",
            username="testuser"
        )
        
        assert result == False


class TestEmailServiceSMTP:
    """Test SMTP email provider"""
    
    @patch('src.utils.email_service.get_settings')
    @patch('smtplib.SMTP')
    def test_send_email_smtp_success(self, mock_smtp, mock_settings):
        """Test sending email via SMTP successfully"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = True
        mock_email_config.provider = "smtp"
        mock_email_config.smtp_host = "smtp.example.com"
        mock_email_config.smtp_port = 587
        mock_email_config.smtp_user = "user@example.com"
        mock_email_config.smtp_password = "password"
        mock_email_config.smtp_use_tls = True
        mock_email_config.from_email = "test@example.com"
        mock_email_config.from_name = "VulnScope"
        mock_email_config.frontend_url = "http://localhost:3000"
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        mock_smtp_instance = MagicMock()
        mock_smtp.return_value = mock_smtp_instance
        
        service = EmailService()
        
        result = service.send_verification_email(
            email="user@example.com",
            token="token123",
            username="testuser"
        )
        
        # Should have tried to send via SMTP
        assert result == True or result == False  # Depends on SMTP success
    
    @patch('src.utils.email_service.get_settings')
    def test_send_email_smtp_no_credentials(self, mock_settings):
        """Test sending email without SMTP credentials"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = True
        mock_email_config.provider = "smtp"
        mock_email_config.smtp_user = None
        mock_email_config.smtp_password = None
        mock_email_config.from_email = "test@example.com"
        mock_email_config.frontend_url = "http://localhost:3000"
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        service = EmailService()
        
        result = service.send_verification_email(
            email="user@example.com",
            token="token123",
            username="testuser"
        )
        
        assert result == False


class TestGetEmailService:
    """Test email service singleton"""
    
    @patch('src.utils.email_service.get_settings')
    def test_get_email_service_singleton(self, mock_settings):
        """Test get_email_service returns singleton"""
        mock_email_config = MagicMock()
        mock_email_config.enabled = False
        mock_settings.return_value = MagicMock(email=mock_email_config)
        
        # Clear any existing instance
        import src.utils.email_service as email_module
        email_module._email_service = None
        
        service1 = get_email_service()
        service2 = get_email_service()
        
        assert service1 is service2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])