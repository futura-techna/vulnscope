"""
VulnScope - Email Service Unit Tests
Tests for email sending functionality (Resend API and SMTP)
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime

from src.utils.email_service import EmailService, get_email_service


class TestEmailService:
    """Test EmailService class"""
    
    def test_initialization(self):
        """Test email service initialization"""
        with patch('src.utils.email_service.get_settings') as mock_settings:
            mock_settings.return_value = MagicMock(
                email=MagicMock(
                    enabled=True,
                    provider='resend',
                    resend_api_key='test-key',
                    from_email='test@example.com',
                    from_name='VulnScope',
                    frontend_url='http://localhost:3000'
                )
            )
            
            service = EmailService()
            assert service is not None
    
    @patch('src.utils.email_service.get_settings')
    def test_send_email_disabled(self, mock_settings):
        """Test that emails are not sent when disabled"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=False,
                provider='resend'
            )
        )
        
        service = EmailService()
        result = service._send_email(
            to_email="test@example.com",
            subject="Test",
            html_body="<p>Test</p>",
            text_body="Test"
        )
        
        assert result == False
    
    @patch('requests.post')
    @patch('src.utils.email_service.get_settings')
    def test_send_email_resend_success(self, mock_settings, mock_post):
        """Test successful email send via Resend API"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=True,
                provider='resend',
                resend_api_key='test-api-key',
                from_email='test@example.com',
                from_name='VulnScope'
            )
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_post.return_value = mock_response
        
        service = EmailService()
        result = service._send_email(
            to_email="recipient@example.com",
            subject="Test Subject",
            html_body="<p>Test body</p>",
            text_body="Test body"
        )
        
        assert result == True
        mock_post.assert_called_once()
        
        # Verify correct API endpoint and headers
        call_args = mock_post.call_args
        assert 'https://api.resend.com/emails' in str(call_args)
    
    @patch('requests.post')
    @patch('src.utils.email_service.get_settings')
    def test_send_email_resend_failure(self, mock_settings, mock_post):
        """Test failed email send via Resend API"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=True,
                provider='resend',
                resend_api_key='test-api-key',
                from_email='test@example.com',
                from_name='VulnScope'
            )
        )
        
        mock_response = MagicMock()
        mock_response.status_code = 400
        mock_response.text = 'Bad Request'
        mock_post.return_value = mock_response
        
        service = EmailService()
        result = service._send_email(
            to_email="recipient@example.com",
            subject="Test",
            html_body="<p>Test</p>",
            text_body="Test"
        )
        
        assert result == False
    
    @patch('requests.post')
    @patch('src.utils.email_service.get_settings')
    def test_send_email_resend_exception(self, mock_settings, mock_post):
        """Test email send with exception"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=True,
                provider='resend',
                resend_api_key='test-api-key',
                from_email='test@example.com',
                from_name='VulnScope'
            )
        )
        
        mock_post.side_effect = Exception("Connection error")
        
        service = EmailService()
        result = service._send_email(
            to_email="recipient@example.com",
            subject="Test",
            html_body="<p>Test</p>",
            text_body="Test"
        )
        
        assert result == False


class TestVerificationEmail:
    """Test verification email sending"""
    
    @patch.object(EmailService, '_send_email')
    @patch('src.utils.email_service.get_settings')
    def test_send_verification_email(self, mock_settings, mock_send):
        """Test sending verification email"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=True,
                frontend_url='http://localhost:3000'
            )
        )
        mock_send.return_value = True
        
        service = EmailService()
        result = service.send_verification_email(
            email="user@example.com",
            token="verification-token-123",
            username="testuser"
        )
        
        assert result == True
        mock_send.assert_called_once()
        
        # Verify email content
        call_args = mock_send.call_args
        assert call_args[0][0] == "user@example.com"
        assert "vérifi" in call_args[0][1].lower()


class TestPasswordResetEmail:
    """Test password reset email sending"""
    
    @patch.object(EmailService, '_send_email')
    @patch('src.utils.email_service.get_settings')
    def test_send_password_reset_email(self, mock_settings, mock_send):
        """Test sending password reset email"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=True,
                frontend_url='http://localhost:3000'
            )
        )
        mock_send.return_value = True
        
        service = EmailService()
        result = service.send_password_reset_email(
            email="user@example.com",
            token="reset-token-123",
            username="testuser"
        )
        
        assert result == True
        mock_send.assert_called_once()
        
        # Verify email content
        call_args = mock_send.call_args
        assert call_args[0][0] == "user@example.com"
        assert "réinitialisation" in call_args[0][1].lower()


class TestWelcomeEmail:
    """Test welcome email sending"""
    
    @patch.object(EmailService, '_send_email')
    @patch('src.utils.email_service.get_settings')
    def test_send_welcome_email(self, mock_settings, mock_send):
        """Test sending welcome email"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=True,
                frontend_url='http://localhost:3000'
            )
        )
        mock_send.return_value = True
        
        service = EmailService()
        result = service.send_welcome_email(
            email="user@example.com",
            username="testuser"
        )
        
        assert result == True
        mock_send.assert_called_once()
        
        # Verify email content
        call_args = mock_send.call_args
        assert call_args[0][0] == "user@example.com"
        assert "bienvenue" in call_args[0][1].lower()


class TestPasswordChangedConfirmation:
    """Test password changed confirmation email"""
    
    @patch.object(EmailService, '_send_email')
    @patch('src.utils.email_service.get_settings')
    def test_send_password_changed_confirmation(self, mock_settings, mock_send):
        """Test sending password changed confirmation"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=True,
                frontend_url='http://localhost:3000'
            )
        )
        mock_send.return_value = True
        
        service = EmailService()
        result = service.send_password_changed_confirmation(
            email="user@example.com",
            username="testuser"
        )
        
        assert result == True
        mock_send.assert_called_once()


class TestSMTPSending:
    """Test SMTP email sending"""
    
    @patch('smtplib.SMTP')
    @patch('src.utils.email_service.get_settings')
    def test_send_email_smtp_success(self, mock_settings, mock_smtp_class):
        """Test successful email send via SMTP"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=True,
                provider='smtp',
                smtp_host='smtp.example.com',
                smtp_port=587,
                smtp_user='user@example.com',
                smtp_password='password',
                smtp_use_tls=True,
                from_email='noreply@example.com',
                from_name='VulnScope'
            )
        )
        
        mock_smtp = MagicMock()
        mock_smtp_class.return_value = mock_smtp
        
        service = EmailService()
        result = service._send_email_smtp(
            to_email="recipient@example.com",
            subject="Test Subject",
            html_body="<p>Test</p>",
            text_body="Test"
        )
        
        assert result == True
        mock_smtp.starttls.assert_called_once()
        mock_smtp.login.assert_called_once()
        mock_smtp.sendmail.assert_called_once()
        mock_smtp.quit.assert_called_once()
    
    @patch('smtplib.SMTP')
    @patch('src.utils.email_service.get_settings')
    def test_send_email_smtp_failure(self, mock_settings, mock_smtp_class):
        """Test failed email send via SMTP"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=True,
                provider='smtp',
                smtp_host='smtp.example.com',
                smtp_port=587,
                smtp_user='user@example.com',
                smtp_password='password',
                smtp_use_tls=True
            )
        )
        
        mock_smtp_class.side_effect = Exception("SMTP connection failed")
        
        service = EmailService()
        result = service._send_email_smtp(
            to_email="recipient@example.com",
            subject="Test",
            html_body="<p>Test</p>",
            text_body="Test"
        )
        
        assert result == False


class TestGetEmailService:
    """Test singleton email service"""
    
    @patch('src.utils.email_service.get_settings')
    def test_get_email_service_singleton(self, mock_settings):
        """Test that get_email_service returns singleton"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(enabled=False)
        )
        
        # Reset singleton
        import src.utils.email_service as email_module
        email_module._email_service = None
        
        service1 = get_email_service()
        service2 = get_email_service()
        
        assert service1 is service2


class TestEmailContent:
    """Test email content generation"""
    
    @patch.object(EmailService, '_send_email')
    @patch('src.utils.email_service.get_settings')
    def test_verification_email_contains_token(self, mock_settings, mock_send):
        """Test that verification email contains the token"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=True,
                frontend_url='http://localhost:3000'
            )
        )
        mock_send.return_value = True
        
        service = EmailService()
        service.send_verification_email(
            email="user@example.com",
            token="test-token-abc123",
            username="testuser"
        )
        
        call_args = mock_send.call_args
        html_body = call_args[0][2]  # html_body is third argument
        
        # Token should be in the URL
        assert "test-token-abc123" in html_body
    
    @patch.object(EmailService, '_send_email')
    @patch('src.utils.email_service.get_settings')
    def test_email_contains_username(self, mock_settings, mock_send):
        """Test that email contains username"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(
                enabled=True,
                frontend_url='http://localhost:3000'
            )
        )
        mock_send.return_value = True
        
        service = EmailService()
        service.send_welcome_email(
            email="user@example.com",
            username="JohnDoe"
        )
        
        call_args = mock_send.call_args
        html_body = call_args[0][2]
        
        assert "JohnDoe" in html_body


if __name__ == "__main__":
    pytest.main([__file__, "-v"])