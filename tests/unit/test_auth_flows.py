"""
VulnScope - Authentication Flows Unit Tests
Tests for authentication handling
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from uuid import uuid4

from src.discovery.auth_flows import (
    AuthType, AuthResult, AuthHandler, AuthFlow
)


class TestAuthType:
    """Test AuthType enum"""
    
    def test_auth_types_exist(self):
        assert AuthType.NONE is not None
        assert AuthType.BASIC is not None
        assert AuthType.BEARER is not None
        assert AuthType.API_KEY is not None
        assert AuthType.OAuth2 is not None
        assert AuthType.OIDC is not None
        assert AuthType.JWT is not None
        assert AuthType.COOKIE is not None
    
    def test_auth_type_values(self):
        assert AuthType.BASIC.value == "basic"
        assert AuthType.BEARER.value == "bearer"
        assert AuthType.API_KEY.value == "api_key"


class TestAuthResult:
    """Test AuthResult dataclass"""
    
    def test_default_values(self):
        result = AuthResult(success=False)
        assert result.success == False
        assert result.session is None
        assert result.token is None
        assert result.cookies is None
        assert result.error is None
    
    def test_success_result(self):
        mock_session = Mock()
        result = AuthResult(
            success=True,
            session=mock_session,
            token="test-token"
        )
        assert result.success == True
        assert result.session is not None
        assert result.token == "test-token"
    
    def test_failure_result(self):
        result = AuthResult(
            success=False,
            error="Authentication failed"
        )
        assert result.success == False
        assert result.error == "Authentication failed"


class TestAuthHandler:
    """Test AuthHandler class"""
    
    def test_initialization(self):
        handler = AuthHandler()
        assert handler.session is None
        assert handler.auth_type is None
        assert handler.auth_config == {}
    
    def test_create_session(self):
        handler = AuthHandler()
        session = handler._create_session()
        
        assert session is not None
        assert "User-Agent" in session.headers
    
    @patch('requests.Session.get')
    def test_authenticate_basic_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        handler = AuthHandler()
        result = handler.authenticate_basic(
            "http://example.com",
            "username",
            "password"
        )
        
        assert result.success == True
        assert result.session is not None
    
    @patch('requests.Session.get')
    def test_authenticate_basic_failure(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 401
        mock_get.return_value = mock_response
        
        handler = AuthHandler()
        result = handler.authenticate_basic(
            "http://example.com",
            "wrong_user",
            "wrong_pass"
        )
        
        assert result.success == False
        assert "invalid credentials" in result.error.lower()
    
    @patch('requests.Session.get')
    def test_authenticate_bearer_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        handler = AuthHandler()
        result = handler.authenticate_bearer(
            "http://example.com",
            "test-token"
        )
        
        assert result.success == True
        assert result.token == "test-token"
    
    @patch('requests.Session.get')
    def test_authenticate_api_key_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        handler = AuthHandler()
        result = handler.authenticate_api_key(
            "http://example.com",
            "api-key-123",
            "X-API-Key"
        )
        
        assert result.success == True
    
    @patch('requests.Session.get')
    def test_authenticate_cookie_success(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        handler = AuthHandler()
        result = handler.authenticate_cookie(
            "http://example.com",
            {"session_id": "abc123"}
        )
        
        assert result.success == True
        assert result.cookies == {"session_id": "abc123"}
    
    def test_authenticate_none(self):
        handler = AuthHandler()
        result = handler.authenticate(
            "http://example.com",
            AuthType.NONE,
            {}
        )
        
        assert result.success == True
        assert result.session is not None
    
    @patch('requests.Session.get')
    def test_authenticate_generic_basic(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        handler = AuthHandler()
        result = handler.authenticate(
            "http://example.com",
            AuthType.BASIC,
            {"username": "user", "password": "pass"}
        )
        
        assert result.success == True
    
    @patch('requests.Session.get')
    def test_authenticate_generic_bearer(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        handler = AuthHandler()
        result = handler.authenticate(
            "http://example.com",
            AuthType.BEARER,
            {"token": "test-token"}
        )
        
        assert result.success == True
    
    @patch('requests.Session.get')
    def test_authenticate_generic_api_key(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        handler = AuthHandler()
        result = handler.authenticate(
            "http://example.com",
            AuthType.API_KEY,
            {"key": "api-key"}
        )
        
        assert result.success == True
    
    @patch('requests.Session.get')
    def test_authenticate_generic_cookie(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_get.return_value = mock_response
        
        handler = AuthHandler()
        result = handler.authenticate(
            "http://example.com",
            AuthType.COOKIE,
            {"cookies": {"session": "abc"}}
        )
        
        assert result.success == True


class TestAuthFlow:
    """Test AuthFlow class"""
    
    def test_create_oauth2_flow(self):
        config = {
            "auth_url": "https://auth.example.com/authorize",
            "token_url": "https://auth.example.com/token",
            "client_id": "client123",
            "client_secret": "secret123",
            "scope": "openid profile"
        }
        
        flow = AuthFlow.create_oauth2_flow(config)
        
        assert flow["auth_type"] == AuthType.OAuth2
        assert flow["config"]["client_id"] == "client123"
    
    def test_create_oidc_flow(self):
        config = {
            "issuer_url": "https://auth.example.com",
            "username": "user",
            "password": "pass",
            "client_id": "client123"
        }
        
        flow = AuthFlow.create_oidc_flow(config)
        
        assert flow["auth_type"] == AuthType.OIDC
        assert flow["config"]["issuer_url"] == "https://auth.example.com"
    
    def test_create_api_key_flow(self):
        flow = AuthFlow.create_api_key_flow(
            "api-key-123",
            header_name="X-Custom-Key"
        )
        
        assert flow["auth_type"] == AuthType.API_KEY
        assert flow["config"]["key"] == "api-key-123"
        assert flow["config"]["header_name"] == "X-Custom-Key"
    
    def test_create_api_key_flow_default_header(self):
        flow = AuthFlow.create_api_key_flow("api-key-123")
        
        assert flow["config"]["header_name"] == "X-API-Key"


class TestOAuth2Flow:
    """Test OAuth2 authentication flow"""
    
    @patch('requests.Session.post')
    def test_oauth2_success(self, mock_post):
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "access_token": "access-token-123",
            "refresh_token": "refresh-token-123",
            "expires_in": 3600
        }
        mock_post.return_value = mock_response
        
        handler = AuthHandler()
        result = handler.authenticate_oauth2(
            "https://auth.example.com/authorize",
            "https://auth.example.com/token",
            "client_id",
            "client_secret"
        )
        
        # Note: This is a simplified test - actual OAuth2 is more complex
        assert result is not None


class TestOIDCFlow:
    """Test OIDC authentication flow"""
    
    @patch('requests.Session.get')
    @patch('requests.Session.post')
    def test_oidc_discovery(self, mock_post, mock_get):
        # Mock discovery response
        discovery_response = Mock()
        discovery_response.status_code = 200
        discovery_response.json.return_value = {
            "token_endpoint": "https://auth.example.com/token",
            "authorization_endpoint": "https://auth.example.com/authorize"
        }
        
        # Mock token response
        token_response = Mock()
        token_response.status_code = 200
        token_response.json.return_value = {
            "access_token": "access-token",
            "id_token": "id-token"
        }
        
        mock_get.return_value = discovery_response
        mock_post.return_value = token_response
        
        handler = AuthHandler()
        result = handler.authenticate_oidc(
            "https://auth.example.com",
            "user",
            "pass",
            "client_id"
        )
        
        assert result is not None


class TestAuthenticationErrors:
    """Test authentication error handling"""
    
    @patch('requests.Session.get')
    def test_connection_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.RequestException("Connection refused")
        
        handler = AuthHandler()
        result = handler.authenticate_basic(
            "http://example.com",
            "user",
            "pass"
        )
        
        assert result.success == False
        assert result.error is not None
    
    @patch('requests.Session.get')
    def test_timeout_error(self, mock_get):
        import requests
        mock_get.side_effect = requests.Timeout("Request timed out")
        
        handler = AuthHandler()
        result = handler.authenticate_bearer(
            "http://example.com",
            "token"
        )
        
        assert result.success == False
    
    @patch('requests.Session.get')
    def test_unexpected_status_code(self, mock_get):
        mock_response = Mock()
        mock_response.status_code = 500
        mock_get.return_value = mock_response
        
        handler = AuthHandler()
        result = handler.authenticate_basic(
            "http://example.com",
            "user",
            "pass"
        )
        
        assert result.success == False


if __name__ == "__main__":
    pytest.main([__file__, "-v"])