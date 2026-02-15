"""
VulnScope - Authentication Routes
User registration, login, password reset endpoints
"""

import secrets
import hashlib
from datetime import timedelta
from typing import Optional

from fastapi import APIRouter, HTTPException, Depends, status, BackgroundTasks
from fastapi.responses import JSONResponse
from pydantic import BaseModel, EmailStr, Field, validator
from jose import JWTError, jwt

from .security import (
    pwd_context, 
    JWTHandler, 
    User, 
    Token,
    InputValidator,
    get_settings
)


router = APIRouter(prefix="/auth", tags=["authentication"])


# Pydantic models
class RegisterRequest(BaseModel):
    """Request model for user registration"""
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=100)
    full_name: Optional[str] = Field(None, max_length=100)
    
    @validator('username')
    def validate_username(cls, v):
        # Alphanumeric and underscore only
        if not v.replace('_', '').isalnum():
            raise ValueError('Username must be alphanumeric')
        return v.lower()
    
    @validator('password')
    def validate_password(cls, v):
        # Check password strength
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class RegisterResponse(BaseModel):
    """Response model for registration"""
    user_id: str
    username: str
    email: str
    message: str


class LoginRequest(BaseModel):
    """Request model for login"""
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


class PasswordResetRequest(BaseModel):
    """Request model for password reset request"""
    email: EmailStr


class PasswordResetConfirm(BaseModel):
    """Request model for password reset confirmation"""
    token: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=100)
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class PasswordChangeRequest(BaseModel):
    """Request model for password change"""
    old_password: str = Field(..., min_length=1)
    new_password: str = Field(..., min_length=8, max_length=100)
    
    @validator('new_password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Password must be at least 8 characters')
        if not any(c.isupper() for c in v):
            raise ValueError('Password must contain at least one uppercase letter')
        if not any(c.islower() for c in v):
            raise ValueError('Password must contain at least one lowercase letter')
        if not any(c.isdigit() for c in v):
            raise ValueError('Password must contain at least one digit')
        return v


class EmailVerificationRequest(BaseModel):
    """Request model for email verification"""
    token: str = Field(..., min_length=1)


# In-memory user store (replace with database in production)
# This is a mock implementation
MOCK_USERS = {
    "demo": {
        "id": "1",
        "username": "demo",
        "email": "demo@vulnscope.local",
        "full_name": "Demo User",
        "hashed_password": pwd_context.hash("admin123"),
        "roles": ["admin"],
        "is_active": True,
        "is_verified": True,
    }
}

# Password reset tokens (in production, use Redis or database)
PASSWORD_RESET_TOKENS = {}

# Email verification tokens
EMAIL_VERIFICATION_TOKENS = {}


def generate_token() -> str:
    """Generate a secure random token"""
    return secrets.token_urlsafe(32)


def create_password_reset_token(email: str) -> str:
    """Create a password reset token"""
    token = generate_token()
    PASSWORD_RESET_TOKENS[token] = {
        "email": email,
        "expires": datetime.utcnow() + timedelta(hours=1)
    }
    return token


def create_email_verification_token(user_id: str, email: str) -> str:
    """Create an email verification token"""
    token = generate_token()
    EMAIL_VERIFICATION_TOKENS[token] = {
        "user_id": user_id,
        "email": email,
        "expires": datetime.utcnow() + timedelta(days=7)
    }
    return token


def verify_password_reset_token(token: str) -> Optional[str]:
    """Verify password reset token and return email"""
    if token not in PASSWORD_RESET_TOKENS:
        return None
    
    token_data = PASSWORD_RESET_TOKENS[token]
    if datetime.utcnow() > token_data["expires"]:
        del PASSWORD_RESET_TOKENS[token]
        return None
    
    return token_data["email"]


def get_user_by_username(username: str) -> Optional[dict]:
    """Get user by username"""
    return MOCK_USERS.get(username.lower())


def get_user_by_email(email: str) -> Optional[dict]:
    """Get user by email"""
    for user in MOCK_USERS.values():
        if user["email"].lower() == email.lower():
            return user
    return None


def create_user(username: str, email: str, password: str, full_name: Optional[str] = None) -> dict:
    """Create a new user"""
    user_id = secrets.token_hex(8)
    
    user = {
        "id": user_id,
        "username": username.lower(),
        "email": email.lower(),
        "full_name": full_name,
        "hashed_password": pwd_context.hash(password),
        "roles": ["user"],  # Default role
        "is_active": True,
        "is_verified": False,  # Require email verification
    }
    
    MOCK_USERS[username.lower()] = user
    return user


# Import datetime
from datetime import datetime


@router.post("/register", response_model=RegisterResponse, status_code=status.HTTP_201_CREATED)
async def register(request: RegisterRequest, background_tasks: BackgroundTasks):
    """Register a new user account"""
    
    # Check if username already exists
    if get_user_by_username(request.username):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Username already registered"
        )
    
    # Check if email already exists
    if get_user_by_email(request.email):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email already registered"
        )
    
    # Create user
    user = create_user(
        username=request.username,
        email=request.email,
        password=request.password,
        full_name=request.full_name
    )
    
    # In production, send verification email in background
    # verification_token = create_email_verification_token(user["id"], user["email"])
    # background_tasks.add_task(send_verification_email, user["email"], verification_token)
    
    return RegisterResponse(
        user_id=user["id"],
        username=user["username"],
        email=user["email"],
        message="Registration successful. Please check your email to verify your account."
    )


@router.post("/login", response_model=Token)
async def login(request: LoginRequest):
    """Login to get access token"""
    
    # Get user
    user = get_user_by_username(request.username)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Verify password
    if not pwd_context.verify(request.password, user["hashed_password"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    # Check if user is active
    if not user.get("is_active", True):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is disabled"
        )
    
    # Check if email is verified
    if not user.get("is_verified", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Please verify your email address"
        )
    
    # Create tokens
    jwt_handler = JWTHandler()
    
    access_token = jwt_handler.create_access_token(
        data={"sub": user["username"], "user_id": user["id"], "roles": user["roles"]}
    )
    refresh_token = jwt_handler.create_refresh_token(
        data={"sub": user["username"], "user_id": user["id"]}
    )
    
    return Token(
        access_token=access_token,
        token_type="bearer",
        expires_in=1800,  # 30 minutes
        refresh_token=refresh_token
    )


@router.post("/refresh", response_model=Token)
async def refresh_token(refresh_token: str):
    """Refresh access token"""
    
    jwt_handler = JWTHandler()
    
    try:
        payload = jwt_handler.verify_token(refresh_token)
        
        if payload.get("type") != "refresh":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid token type"
            )
        
        username = payload.get("sub")
        user_id = payload.get("user_id")
        
        user = get_user_by_username(username)
        if not user or not user.get("is_active"):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="User not found or disabled"
            )
        
        # Create new tokens
        access_token = jwt_handler.create_access_token(
            data={"sub": user["username"], "user_id": user["id"], "roles": user["roles"]}
        )
        new_refresh_token = jwt_handler.create_refresh_token(
            data={"sub": user["username"], "user_id": user["id"]}
        )
        
        return Token(
            access_token=access_token,
            token_type="bearer",
            expires_in=1800,
            refresh_token=new_refresh_token
        )
        
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or expired refresh token",
            headers={"WWW-Authenticate": "Bearer"},
        )


@router.post("/password-reset")
async def request_password_reset(request: PasswordResetRequest, background_tasks: BackgroundTasks):
    """Request password reset"""
    
    user = get_user_by_email(request.email)
    
    # Always return success to prevent email enumeration
    # But only send email if user exists
    
    if user:
        reset_token = create_password_reset_token(request.email)
        
        # In production, send reset email in background
        # background_tasks.add_task(send_password_reset_email, request.email, reset_token)
        pass
    
    return {
        "message": "If an account exists with this email, a password reset link has been sent."
    }


@router.post("/password-reset/confirm")
async def confirm_password_reset(request: PasswordResetConfirm):
    """Confirm password reset with new password"""
    
    email = verify_password_reset_token(request.token)
    
    if not email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid or expired reset token"
        )
    
    # Get user by email
    user = get_user_by_email(email)
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Update password
    user["hashed_password"] = pwd_context.hash(request.new_password)
    
    # Delete used token
    del PASSWORD_RESET_TOKENS[request.token]
    
    # In production, send confirmation email
    # background_tasks.add_task(send_password_changed_email, user["email"])
    
    return {"message": "Password has been reset successfully"}


@router.post("/password-change")
async def change_password(
    request: PasswordChangeRequest,
    current_user: User = Depends(lambda: None)  # Will be replaced with actual dependency
):
    """Change password for logged in user"""
    
    # This would require authentication
    # For now, return a placeholder
    
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail="Password change requires authentication. Use the /auth/token endpoint."
    )


@router.post("/verify-email")
async def verify_email(request: EmailVerificationRequest):
    """Verify email address with token"""
    
    if request.token not in EMAIL_VERIFICATION_TOKENS:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid verification token"
        )
    
    token_data = EMAIL_VERIFICATION_TOKENS[request.token]
    
    if datetime.utcnow() > token_data["expires"]:
        del EMAIL_VERIFICATION_TOKENS[request.token]
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Verification token expired"
        )
    
    # Get user and mark as verified
    user = get_user_by_email(token_data["email"])
    
    if user:
        user["is_verified"] = True
    
    # Delete used token
    del EMAIL_VERIFICATION_TOKENS[request.token]
    
    return {"message": "Email verified successfully"}


@router.get("/me")
async def get_current_user_info(current_user: User = Depends(lambda: None)):
    """Get current user information"""
    
    # This would require authentication
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Not authenticated"
    )


@router.post("/logout")
async def logout():
    """Logout (client should discard tokens)"""
    
    # In production, you might want to blacklist the token
    return {"message": "Successfully logged out"}
