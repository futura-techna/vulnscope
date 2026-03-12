"""
VulnScope - API Security Unit Tests
Tests for JWT authentication, rate limiting, input validation, authorization
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime, timedelta
from fastapi import HTTPException

from src.api.security import (
    JWTHandler, RateLimiter, InputValidator, AuthorizationHandler,
    User, Token, JWT_ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
)


class TestJWTHandler:
    """Test JWT token handling"""
    
    def test_initialization_default(self):
        """Test default initialization"""
        handler = JWTHandler()
        assert handler.algorithm == JWT_ALGORITHM
        assert handler.secret_key is not None
    
    def test_initialization_custom_secret(self):
        """Test initialization with custom secret"""
        handler = JWTHandler(secret_key="my-custom-secret")
        assert handler.secret_key == "my-custom-secret"
    
    def test_create_access_token(self):
        """Test access token creation"""
        handler = JWTHandler(secret_key="test-secret")
        
        token = handler.create_access_token({
            "sub": "testuser",
            "user_id": "123"
        })
        
        assert token is not None
        assert isinstance(token, str)
        assert len(token) > 0
    
    def test_create_access_token_with_expiry(self):
        """Test access token with custom expiry"""
        handler = JWTHandler(secret_key="test-secret")
        
        expiry = timedelta(minutes=60)
        token = handler.create_access_token(
            {"sub": "testuser"},
            expires_delta=expiry
        )
        
        assert token is not None
    
    def test_create_refresh_token(self):
        """Test refresh token creation"""
        handler = JWTHandler(secret_key="test-secret")
        
        token = handler.create_refresh_token({
            "sub": "testuser",
            "user_id": "123"
        })
        
        assert token is not None
        assert isinstance(token, str)
    
    def test_verify_token_valid(self):
        """Test valid token verification"""
        handler = JWTHandler(secret_key="test-secret")
        
        token = handler.create_access_token({
            "sub": "testuser",
            "user_id": "123",
            "roles": ["admin"]
        })
        
        payload = handler.verify_token(token)
        
        assert payload["sub"] == "testuser"
        assert payload["user_id"] == "123"
        assert payload["roles"] == ["admin"]
        assert payload["type"] == "access"
    
    def test_verify_token_invalid(self):
        """Test invalid token verification"""
        handler = JWTHandler(secret_key="test-secret")
        
        with pytest.raises(HTTPException) as exc_info:
            handler.verify_token("invalid.token.here")
        
        assert exc_info.value.status_code == 401
    
    def test_verify_token_wrong_secret(self):
        """Test token with wrong secret"""
        handler1 = JWTHandler(secret_key="secret1")
        handler2 = JWTHandler(secret_key="secret2")
        
        token = handler1.create_access_token({"sub": "testuser"})
        
        with pytest.raises(HTTPException):
            handler2.verify_token(token)
    
    def test_get_current_user(self):
        """Test getting current user from token"""
        handler = JWTHandler(secret_key="test-secret")
        
        token = handler.create_access_token({
            "sub": "testuser",
            "user_id": "123",
            "roles": ["admin", "developer"]
        })
        
        user = handler.get_current_user(token)
        
        assert isinstance(user, User)
        assert user.username == "testuser"
        assert user.id == "123"
        assert "admin" in user.roles
        assert "developer" in user.roles
    
    def test_get_current_user_missing_subject(self):
        """Test getting user from token without subject"""
        handler = JWTHandler(secret_key="test-secret")
        
        token = handler.create_access_token({
            "user_id": "123"
        })
        
        with pytest.raises(HTTPException):
            handler.get_current_user(token)


class TestRateLimiter:
    """Test rate limiting functionality"""
    
    def test_initialization(self):
        """Test rate limiter initialization"""
        limiter = RateLimiter()
        assert limiter.default_limit == 100
        assert limiter.default_window == 60
    
    def test_initialization_with_redis(self):
        """Test initialization with Redis client"""
        mock_redis = Mock()
        limiter = RateLimiter(redis_client=mock_redis)
        assert limiter.redis == mock_redis
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_redis_unavailable(self):
        """Test rate limit when Redis is unavailable"""
        limiter = RateLimiter()
        limiter._redis_available = False
        
        allowed, remaining = await limiter.check_rate_limit("test_key")
        
        assert allowed is True
        assert remaining == limiter.default_limit
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_redis_none(self):
        """Test rate limit when Redis returns None"""
        limiter = RateLimiter()
        limiter._get_redis = Mock(return_value=None)
        
        allowed, remaining = await limiter.check_rate_limit("test_key")
        
        assert allowed is True
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_under_limit(self):
        """Test rate limit under threshold"""
        mock_redis = Mock()
        mock_redis.get.return_value = "5"
        mock_redis.ttl.return_value = 30
        
        limiter = RateLimiter(redis_client=mock_redis)
        
        allowed, remaining = await limiter.check_rate_limit("test_key")
        
        assert allowed is True
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_over_limit(self):
        """Test rate limit over threshold"""
        mock_redis = Mock()
        mock_redis.get.return_value = "100"
        
        limiter = RateLimiter(redis_client=mock_redis)
        
        allowed, remaining = await limiter.check_rate_limit("test_key")
        
        assert allowed is False
        assert remaining == 0
    
    @pytest.mark.asyncio
    async def test_check_rate_limit_exception(self):
        """Test rate limit handles exceptions gracefully"""
        mock_redis = Mock()
        mock_redis.get.side_effect = Exception("Redis error")
        
        limiter = RateLimiter(redis_client=mock_redis)
        
        allowed, remaining = await limiter.check_rate_limit("test_key")
        
        # Should allow request on error
        assert allowed is True


class TestInputValidator:
    """Test input validation"""
    
    def test_validate_url_valid_http(self):
        """Test valid HTTP URL"""
        assert InputValidator.validate_url("http://example.com")
        assert InputValidator.validate_url("http://example.com/path")
        assert InputValidator.validate_url("http://example.com/path?query=1")
    
    def test_validate_url_valid_https(self):
        """Test valid HTTPS URL"""
        assert InputValidator.validate_url("https://example.com")
        assert InputValidator.validate_url("https://api.example.com/v1/users")
    
    def test_validate_url_valid_with_port(self):
        """Test valid URL with port"""
        assert InputValidator.validate_url("http://localhost:3000")
        assert InputValidator.validate_url("https://example.com:8443/api")
    
    def test_validate_url_valid_ip(self):
        """Test valid IP URL"""
        assert InputValidator.validate_url("http://192.168.1.1")
        assert InputValidator.validate_url("http://127.0.0.1:8080")
    
    def test_validate_url_invalid(self):
        """Test invalid URLs"""
        assert not InputValidator.validate_url("")
        assert not InputValidator.validate_url("not-a-url")
        assert not InputValidator.validate_url("ftp://example.com")
        assert not InputValidator.validate_url("javascript:alert(1)")
    
    def test_validate_url_too_long(self):
        """Test URL exceeding max length"""
        long_url = "http://example.com/" + "a" * 2100
        assert not InputValidator.validate_url(long_url)
    
    def test_validate_email_valid(self):
        """Test valid emails"""
        assert InputValidator.validate_email("test@example.com")
        assert InputValidator.validate_email("user.name@example.org")
        assert InputValidator.validate_email("user+tag@example.co.uk")
    
    def test_validate_email_invalid(self):
        """Test invalid emails"""
        assert not InputValidator.validate_email("")
        assert not InputValidator.validate_email("not-an-email")
        assert not InputValidator.validate_email("@example.com")
        assert not InputValidator.validate_email("test@")
    
    def test_validate_target_url_valid(self):
        """Test valid target URLs"""
        is_valid, error = InputValidator.validate_target_url("http://example.com")
        assert is_valid
        assert error == ""
        
        is_valid, error = InputValidator.validate_target_url("https://api.example.com/v1")
        assert is_valid
    
    def test_validate_target_url_invalid_protocol(self):
        """Test target URL with invalid protocol"""
        is_valid, error = InputValidator.validate_target_url("ftp://example.com")
        assert not is_valid
        assert "HTTP" in error
    
    def test_validate_target_url_invalid_format(self):
        """Test target URL with invalid format"""
        is_valid, error = InputValidator.validate_target_url("not-a-url")
        assert not is_valid
        assert "Invalid URL" in error or "HTTP" in error
    
    def test_sanitize_input_basic(self):
        """Test basic input sanitization"""
        assert InputValidator.sanitize_input("  test  ") == "test"
        assert InputValidator.sanitize_input("hello") == "hello"
    
    def test_sanitize_input_null_bytes(self):
        """Test null byte removal"""
        result = InputValidator.sanitize_input("test\x00value\x00here")
        assert "\x00" not in result
        assert result == "testvaluehere"
    
    def test_sanitize_input_truncation(self):
        """Test input truncation"""
        long_input = "x" * 5000
        result = InputValidator.sanitize_input(long_input, max_length=100)
        assert len(result) == 100
    
    def test_sanitize_input_custom_max_length(self):
        """Test custom max length"""
        long_input = "x" * 5000
        result = InputValidator.sanitize_input(long_input, max_length=500)
        assert len(result) == 500
    
    def test_sanitize_input_empty(self):
        """Test empty input"""
        assert InputValidator.sanitize_input("") == ""
        assert InputValidator.sanitize_input(None) == ""


class TestAuthorizationHandler:
    """Test authorization handling"""
    
    def test_admin_has_all_permissions(self):
        """Test admin role has all permissions"""
        assert AuthorizationHandler.check_permission(["admin"], "scan:create")
        assert AuthorizationHandler.check_permission(["admin"], "target:delete")
        assert AuthorizationHandler.check_permission(["admin"], "user:create")
        assert AuthorizationHandler.check_permission(["admin"], "settings:update")
    
    def test_security_engineer_permissions(self):
        """Test security engineer role permissions"""
        assert AuthorizationHandler.check_permission(
            ["security_engineer"], "scan:create"
        )
        assert AuthorizationHandler.check_permission(
            ["security_engineer"], "report:export"
        )
        assert not AuthorizationHandler.check_permission(
            ["security_engineer"], "user:delete"
        )
    
    def test_developer_permissions(self):
        """Test developer role permissions"""
        assert AuthorizationHandler.check_permission(["developer"], "scan:create")
        assert AuthorizationHandler.check_permission(["developer"], "scan:read")
        assert not AuthorizationHandler.check_permission(["developer"], "target:delete")
        assert not AuthorizationHandler.check_permission(["developer"], "user:create")
    
    def test_viewer_permissions(self):
        """Test viewer role permissions"""
        assert AuthorizationHandler.check_permission(["viewer"], "scan:read")
        assert AuthorizationHandler.check_permission(["viewer"], "report:read")
        assert not AuthorizationHandler.check_permission(["viewer"], "scan:create")
        assert not AuthorizationHandler.check_permission(["viewer"], "target:update")
    
    def test_unknown_role(self):
        """Test unknown role has no permissions"""
        assert not AuthorizationHandler.check_permission(["unknown"], "scan:read")
    
    def test_multiple_roles(self):
        """Test user with multiple roles"""
        # User with developer and viewer roles
        assert AuthorizationHandler.check_permission(
            ["developer", "viewer"], "scan:create"
        )
        assert AuthorizationHandler.check_permission(
            ["developer", "viewer"], "scan:read"
        )
    
    def test_require_permission_decorator(self):
        """Test require_permission decorator"""
        @AuthorizationHandler.require_permission("scan:create")
        async def protected_function(current_user=None):
            return "success"
        
        # Would need proper async test with user context
        assert callable(protected_function)
    
    def test_require_role_decorator(self):
        """Test require_role decorator"""
        @AuthorizationHandler.require_role(["admin"])
        async def admin_function(current_user=None):
            return "success"
        
        assert callable(admin_function)


class TestUser:
    """Test User dataclass"""
    
    def test_user_creation(self):
        """Test user creation"""
        user = User(
            id="123",
            username="testuser",
            email="test@example.com",
            hashed_password="hashed",
            roles=["user"]
        )
        
        assert user.id == "123"
        assert user.username == "testuser"
        assert user.email == "test@example.com"
        assert user.roles == ["user"]
        assert user.is_active is True
    
    def test_user_with_multiple_roles(self):
        """Test user with multiple roles"""
        user = User(
            id="1",
            username="admin",
            email="admin@example.com",
            hashed_password="hashed",
            roles=["admin", "security_engineer"]
        )
        
        assert len(user.roles) == 2
        assert "admin" in user.roles


class TestToken:
    """Test Token dataclass"""
    
    def test_token_creation(self):
        """Test token creation"""
        token = Token(
            access_token="abc123",
            token_type="bearer",
            expires_in=1800
        )
        
        assert token.access_token == "abc123"
        assert token.token_type == "bearer"
        assert token.expires_in == 1800
        assert token.refresh_token is None
    
    def test_token_with_refresh(self):
        """Test token with refresh token"""
        token = Token(
            access_token="access123",
            token_type="bearer",
            expires_in=1800,
            refresh_token="refresh456"
        )
        
        assert token.refresh_token == "refresh456"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])