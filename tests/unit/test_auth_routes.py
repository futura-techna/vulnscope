"""
VulnScope - Authentication Routes Unit Tests
Tests for user registration, login, password reset, and email verification
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from uuid import uuid4
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api.auth_routes import (
    router, RegisterRequest, LoginRequest, PasswordResetRequest,
    PasswordResetConfirm, EmailVerificationRequest, ResendVerificationRequest,
    generate_token, create_password_reset_token, create_email_verification_token,
    verify_password_reset_token, get_user_by_username, get_user_by_email,
    create_user, MOCK_USERS
)
from src.api.security import pwd_context


# Create test app
app = FastAPI()
app.include_router(router)
client = TestClient(app)


class TestRegisterRequest:
    """Test RegisterRequest validation"""
    
    def test_valid_registration(self):
        request = RegisterRequest(
            username="testuser",
            email="test@example.com",
            password="ValidPass123",
            full_name="Test User"
        )
        assert request.username == "testuser"
        assert request.email == "test@example.com"
    
    def test_username_validation_alphanumeric(self):
        """Username must be alphanumeric"""
        with pytest.raises(ValueError):
            RegisterRequest(
                username="test-user!",
                email="test@example.com",
                password="ValidPass123"
            )
    
    def test_username_validation_lowercase(self):
        """Username should be converted to lowercase"""
        request = RegisterRequest(
            username="TestUser",
            email="test@example.com",
            password="ValidPass123"
        )
        assert request.username == "testuser"
    
    def test_password_validation_length(self):
        """Password must be at least 8 characters"""
        with pytest.raises(ValueError):
            RegisterRequest(
                username="testuser",
                email="test@example.com",
                password="Short1"
            )
    
    def test_password_validation_uppercase(self):
        """Password must contain uppercase letter"""
        with pytest.raises(ValueError):
            RegisterRequest(
                username="testuser",
                email="test@example.com",
                password="alllowercase123"
            )
    
    def test_password_validation_lowercase(self):
        """Password must contain lowercase letter"""
        with pytest.raises(ValueError):
            RegisterRequest(
                username="testuser",
                email="test@example.com",
                password="ALLUPPERCASE123"
            )
    
    def test_password_validation_digit(self):
        """Password must contain at least one digit"""
        with pytest.raises(ValueError):
            RegisterRequest(
                username="testuser",
                email="test@example.com",
                password="NoDigitHere"
            )


class TestPasswordResetConfirm:
    """Test PasswordResetConfirm validation"""
    
    def test_valid_password_reset(self):
        request = PasswordResetConfirm(
            token="valid-token-123",
            new_password="NewValidPass123"
        )
        assert request.token == "valid-token-123"
        assert request.new_password == "NewValidPass123"
    
    def test_password_validation_weak(self):
        """Password validation should match registration rules"""
        with pytest.raises(ValueError):
            PasswordResetConfirm(
                token="token",
                new_password="weak"
            )


class TestTokenGeneration:
    """Test token generation functions"""
    
    def test_generate_token_length(self):
        """Generated token should be secure length"""
        token = generate_token()
        assert len(token) >= 32
    
    def test_generate_token_uniqueness(self):
        """Generated tokens should be unique"""
        tokens = [generate_token() for _ in range(100)]
        assert len(set(tokens)) == 100
    
    @patch('src.api.auth_routes.get_token_storage')
    def test_create_password_reset_token(self, mock_storage):
        """Test password reset token creation"""
        mock_store = MagicMock()
        mock_storage.return_value = mock_store
        
        token = create_password_reset_token("test@example.com")
        
        assert token is not None
        mock_store.store_token.assert_called_once()
    
    @patch('src.api.auth_routes.get_token_storage')
    def test_create_email_verification_token(self, mock_storage):
        """Test email verification token creation"""
        mock_store = MagicMock()
        mock_storage.return_value = mock_store
        
        user_id = str(uuid4())
        token = create_email_verification_token(user_id, "test@example.com")
        
        assert token is not None
        mock_store.store_token.assert_called_once()
    
    @patch('src.api.auth_routes.get_token_storage')
    def test_verify_password_reset_token_valid(self, mock_storage):
        """Test verifying valid password reset token"""
        mock_store = MagicMock()
        mock_store.get_token.return_value = {"email": "test@example.com"}
        mock_storage.return_value = mock_store
        
        email = verify_password_reset_token("valid-token")
        
        assert email == "test@example.com"
    
    @patch('src.api.auth_routes.get_token_storage')
    def test_verify_password_reset_token_invalid(self, mock_storage):
        """Test verifying invalid password reset token"""
        mock_store = MagicMock()
        mock_store.get_token.return_value = None
        mock_storage.return_value = mock_store
        
        email = verify_password_reset_token("invalid-token")
        
        assert email is None


class TestUserManagement:
    """Test user management functions"""
    
    def setup_method(self):
        """Reset MOCK_USERS for each test"""
        self.original_users = MOCK_USERS.copy()
    
    def teardown_method(self):
        """Restore MOCK_USERS after each test"""
        MOCK_USERS.clear()
        MOCK_USERS.update(self.original_users)
    
    def test_get_user_by_username_exists(self):
        """Test getting existing user by username"""
        user = get_user_by_username("demo")
        assert user is not None
        assert user["username"] == "demo"
    
    def test_get_user_by_username_not_exists(self):
        """Test getting non-existent user"""
        user = get_user_by_username("nonexistent")
        assert user is None
    
    def test_get_user_by_email_exists(self):
        """Test getting existing user by email"""
        user = get_user_by_email("demo@vulnscope.local")
        assert user is not None
        assert user["email"] == "demo@vulnscope.local"
    
    def test_get_user_by_email_not_exists(self):
        """Test getting user by non-existent email"""
        user = get_user_by_email("nonexistent@example.com")
        assert user is None
    
    @patch('src.api.auth_routes.get_settings')
    def test_create_user(self, mock_settings):
        """Test user creation"""
        mock_settings.return_value = MagicMock(email=MagicMock(enabled=False))
        
        user = create_user(
            username="newuser",
            email="newuser@example.com",
            password="Password123",
            full_name="New User"
        )
        
        assert user["username"] == "newuser"
        assert user["email"] == "newuser@example.com"
        assert user["full_name"] == "New User"
        assert "hashed_password" in user
        assert user["roles"] == ["user"]
        assert user["is_active"] is True
        assert user["is_verified"] is True
    
    @patch('src.api.auth_routes.get_settings')
    def test_create_user_with_email_enabled(self, mock_settings):
        """Test user creation when email verification is enabled"""
        mock_settings.return_value = MagicMock(email=MagicMock(enabled=True))
        
        user = create_user(
            username="emailuser",
            email="emailuser@example.com",
            password="Password123"
        )
        
        assert user["is_verified"] is False


class TestRegisterEndpoint:
    """Test registration endpoint"""
    
    def setup_method(self):
        self.original_users = MOCK_USERS.copy()
    
    def teardown_method(self):
        MOCK_USERS.clear()
        MOCK_USERS.update(self.original_users)
    
    @patch('src.api.auth_routes.get_settings')
    @patch('src.api.auth_routes.get_email_service')
    def test_register_success(self, mock_email, mock_settings):
        """Test successful registration"""
        mock_settings.return_value = MagicMock(email=MagicMock(enabled=False))
        mock_email.return_value = MagicMock()
        
        response = client.post(
            "/auth/register",
            json={
                "username": "newuser",
                "email": "newuser@example.com",
                "password": "ValidPass123",
                "full_name": "New User"
            }
        )
        
        assert response.status_code == 201
        data = response.json()
        assert data["username"] == "newuser"
        assert data["email"] == "newuser@example.com"
    
    def test_register_duplicate_username(self):
        """Test registration with duplicate username"""
        response = client.post(
            "/auth/register",
            json={
                "username": "demo",
                "email": "different@example.com",
                "password": "ValidPass123"
            }
        )
        
        assert response.status_code == 400
        assert "Username already registered" in response.json()["detail"]
    
    def test_register_duplicate_email(self):
        """Test registration with duplicate email"""
        response = client.post(
            "/auth/register",
            json={
                "username": "differentuser",
                "email": "demo@vulnscope.local",
                "password": "ValidPass123"
            }
        )
        
        assert response.status_code == 400
        assert "Email already registered" in response.json()["detail"]
    
    def test_register_weak_password(self):
        """Test registration with weak password"""
        response = client.post(
            "/auth/register",
            json={
                "username": "weakpassuser",
                "email": "weak@example.com",
                "password": "weak"
            }
        )
        
        assert response.status_code == 422


class TestLoginEndpoint:
    """Test login endpoint"""
    
    def test_login_success(self):
        """Test successful login"""
        response = client.post(
            "/auth/login",
            json={
                "username": "demo",
                "password": "admin123"
            }
        )
        
        assert response.status_code == 200
        data = response.json()
        assert "access_token" in data
        assert data["token_type"] == "bearer"
        assert "refresh_token" in data
    
    def test_login_wrong_password(self):
        """Test login with wrong password"""
        response = client.post(
            "/auth/login",
            json={
                "username": "demo",
                "password": "wrongpassword"
            }
        )
        
        assert response.status_code == 401
        assert "Incorrect username or password" in response.json()["detail"]
    
    def test_login_nonexistent_user(self):
        """Test login with non-existent user"""
        response = client.post(
            "/auth/login",
            json={
                "username": "nonexistent",
                "password": "anypassword"
            }
        )
        
        assert response.status_code == 401
    
    def test_login_unverified_user(self):
        """Test login with unverified user"""
        MOCK_USERS["unverified"] = {
            "id": "2",
            "username": "unverified",
            "email": "unverified@example.com",
            "hashed_password": pwd_context.hash("Password123"),
            "roles": ["user"],
            "is_active": True,
            "is_verified": False
        }
        
        response = client.post(
            "/auth/login",
            json={
                "username": "unverified",
                "password": "Password123"
            }
        )
        
        assert response.status_code == 403
        assert "verify your email" in response.json()["detail"].lower()


class TestPasswordResetEndpoint:
    """Test password reset endpoints"""
    
    @patch('src.api.auth_routes.get_settings')
    @patch('src.api.auth_routes.get_email_service')
    @patch('src.api.auth_routes.create_password_reset_token')
    def test_request_password_reset_existing_user(self, mock_create_token, mock_email, mock_settings):
        """Test password reset request for existing user"""
        mock_settings.return_value = MagicMock(email=MagicMock(enabled=True))
        mock_email.return_value = MagicMock()
        mock_create_token.return_value = "reset-token"
        
        response = client.post(
            "/auth/password-reset",
            json={"email": "demo@vulnscope.local"}
        )
        
        assert response.status_code == 200
        assert "message" in response.json()
    
    def test_request_password_reset_nonexistent_user(self):
        """Test password reset request for non-existent user (should return success for security)"""
        response = client.post(
            "/auth/password-reset",
            json={"email": "nonexistent@example.com"}
        )
        
        # Should return success to prevent email enumeration
        assert response.status_code == 200
    
    @patch('src.api.auth_routes.get_token_storage')
    def test_confirm_password_reset_valid(self, mock_storage):
        """Test password reset confirmation with valid token"""
        mock_store = MagicMock()
        mock_store.get_token.return_value = {"email": "demo@vulnscope.local"}
        mock_storage.return_value = mock_store
        
        response = client.post(
            "/auth/password-reset/confirm",
            json={
                "token": "valid-token",
                "new_password": "NewValidPass123"
            }
        )
        
        assert response.status_code == 200
        assert "reset successfully" in response.json()["message"].lower()
    
    @patch('src.api.auth_routes.get_token_storage')
    def test_confirm_password_reset_invalid_token(self, mock_storage):
        """Test password reset confirmation with invalid token"""
        mock_store = MagicMock()
        mock_store.get_token.return_value = None
        mock_storage.return_value = mock_store
        
        response = client.post(
            "/auth/password-reset/confirm",
            json={
                "token": "invalid-token",
                "new_password": "NewValidPass123"
            }
        )
        
        assert response.status_code == 400


class TestEmailVerificationEndpoint:
    """Test email verification endpoint"""
    
    @patch('src.api.auth_routes.get_token_storage')
    def test_verify_email_valid_token(self, mock_storage):
        """Test email verification with valid token"""
        mock_store = MagicMock()
        mock_store.get_token.return_value = {
            "email": "demo@vulnscope.local",
            "user_id": "1"
        }
        mock_store.list_tokens.return_value = []
        mock_storage.return_value = mock_store
        
        response = client.post(
            "/auth/verify-email",
            json={"token": "valid-token"}
        )
        
        assert response.status_code == 200
        assert "verified successfully" in response.json()["message"].lower()
    
    @patch('src.api.auth_routes.get_token_storage')
    def test_verify_email_invalid_token(self, mock_storage):
        """Test email verification with invalid token"""
        mock_store = MagicMock()
        mock_store.get_token.return_value = None
        mock_store.list_tokens.return_value = []
        mock_storage.return_value = mock_store
        
        response = client.post(
            "/auth/verify-email",
            json={"token": "invalid-token"}
        )
        
        assert response.status_code == 400


class TestResendVerificationEndpoint:
    """Test resend verification endpoint"""
    
    @patch('src.api.auth_routes.get_settings')
    def test_resend_verification_email_disabled(self, mock_settings):
        """Test resend verification when email is disabled"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(enabled=False, frontend_url="http://localhost:3000")
        )
        
        response = client.post(
            "/auth/resend-verification",
            json={"email": "demo@vulnscope.local"}
        )
        
        assert response.status_code == 200
        # Should return verification URL when email is disabled
        data = response.json()
        assert "verification_url" in data or "message" in data
    
    @patch('src.api.auth_routes.get_settings')
    @patch('src.api.auth_routes.get_email_service')
    def test_resend_verification_email_enabled(self, mock_email, mock_settings):
        """Test resend verification when email is enabled"""
        mock_settings.return_value = MagicMock(
            email=MagicMock(enabled=True, frontend_url="http://localhost:3000")
        )
        mock_email.return_value = MagicMock()
        
        response = client.post(
            "/auth/resend-verification",
            json={"email": "demo@vulnscope.local"}
        )
        
        assert response.status_code == 200


class TestRefreshTokenEndpoint:
    """Test refresh token endpoint"""
    
    def test_refresh_token_invalid(self):
        """Test refresh with invalid token"""
        response = client.post(
            "/auth/refresh?refresh_token=invalid-token"
        )
        
        assert response.status_code == 401


class TestLogoutEndpoint:
    """Test logout endpoint"""
    
    def test_logout(self):
        """Test logout endpoint"""
        response = client.post("/auth/logout")
        
        assert response.status_code == 200
        assert "logged out" in response.json()["message"].lower()


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
</process>
</task_progress>
<task_progress>- [x] Phase 1: Créer test_auth_routes.py
- [ ] Phase 1: Créer test_email_service.py
- [ ] Phase 1: Créer test_token_storage.py
- [ ] Phase 1: Créer test_schemas.py
- [ ] Phase 2: Créer tests Frontend
- [ ] Phase 3: Améliorer tests existants</task_progress>
</write_to_file>