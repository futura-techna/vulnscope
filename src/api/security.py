"""
VulnScope - API Security Features
JWT authentication, rate limiting, input validation, authorization
"""

import time
import re
from typing import Optional, Dict, Any, List
from dataclasses import dataclass
from datetime import datetime, timedelta
from functools import wraps
from fastapi import HTTPException, Security, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials, APIKeyHeader
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import JWTError, jwt
from passlib.context import CryptContext
from pydantic import BaseModel, Field, validator
import redis
import requests

from ..config.settings import get_settings


# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/api/v1/auth/token")
api_key_header = APIKeyHeader(name="X-API-Key")


# JWT Configuration
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30
REFRESH_TOKEN_EXPIRE_DAYS = 7


@dataclass
class User:
    """User model"""
    id: str
    username: str
    email: str
    hashed_password: str
    roles: List[str]
    is_active: bool = True
    created_at: datetime = None


@dataclass
class Token:
    """Token response"""
    access_token: str
    token_type: str
    expires_in: int
    refresh_token: Optional[str] = None


class JWTHandler:
    """Handle JWT token operations"""
    
    def __init__(self, secret_key: str = None, algorithm: str = JWT_ALGORITHM):
        settings = get_settings()
        self.secret_key = secret_key or settings.secret_key or "dev-secret-key-change-in-production"
        self.algorithm = algorithm
    
    def create_access_token(self, data: Dict, expires_delta: timedelta = None) -> str:
        """Create JWT access token"""
        to_encode = data.copy()
        
        if expires_delta:
            expire = datetime.utcnow() + expires_delta
        else:
            expire = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
        
        to_encode.update({"exp": expire, "type": "access"})
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def create_refresh_token(self, data: Dict) -> str:
        """Create JWT refresh token"""
        to_encode = data.copy()
        expire = datetime.utcnow() + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS)
        to_encode.update({"exp": expire, "type": "refresh"})
        
        encoded_jwt = jwt.encode(to_encode, self.secret_key, algorithm=self.algorithm)
        return encoded_jwt
    
    def verify_token(self, token: str) -> Dict:
        """Verify and decode JWT token"""
        try:
            payload = jwt.decode(token, self.secret_key, algorithms=[self.algorithm])
            return payload
        except JWTError as e:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials",
                headers={"WWW-Authenticate": "Bearer"},
            )
    
    def get_current_user(self, token: str) -> User:
        """Get current user from token"""
        payload = self.verify_token(token)
        
        username = payload.get("sub")
        if username is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Could not validate credentials"
            )
        
        # In production, fetch user from database
        # For now, create a mock user
        return User(
            id=payload.get("user_id", "1"),
            username=username,
            email=f"{username}@example.com",
            hashed_password="",
            roles=payload.get("roles", ["user"])
        )


class RateLimiter:
    """
    Redis-based rate limiter
    
    Features:
    - Sliding window rate limiting
    - Per-user and per-IP limits
    - Configurable limits
    - Graceful fallback when Redis is unavailable
    """
    
    def __init__(self, redis_client: redis.Redis = None):
        self.redis = redis_client
        self.default_limit = 100  # requests per window
        self.default_window = 60  # seconds
        self._redis_available = True
    
    def _get_redis(self):
        """Get or create Redis connection"""
        if self.redis is None:
            settings = get_settings()
            try:
                # Use the new get_connection_params method
                params = settings.redis.get_connection_params()
                self.redis = redis.Redis(
                    host=params['host'],
                    port=params['port'],
                    db=params['db'],
                    password=params['password'],
                    decode_responses=True,
                    socket_connect_timeout=5,  # 5 second timeout
                    socket_timeout=5
                )
                # Test connection
                self.redis.ping()
            except Exception as e:
                # Log warning but don't crash - rate limiting will be disabled
                import logging
                logger = logging.getLogger(__name__)
                logger.warning(f"Redis connection failed: {e}. Rate limiting will be bypassed.")
                self._redis_available = False
                return None
        return self.redis
    
    async def check_rate_limit(self, key: str, limit: int = None, 
                              window: int = None) -> tuple[bool, int]:
        """
        Check if request is within rate limit
        
        Args:
            key: Rate limit key (user_id or IP)
            limit: Max requests per window
            window: Time window in seconds
            
        Returns:
            (is_allowed, remaining_requests)
        """
        limit = limit or self.default_limit
        window = window or self.default_window
        
        # If Redis is not available, allow all requests (graceful degradation)
        if not self._redis_available:
            return True, limit
        
        try:
            r = self._get_redis()
            
            # If Redis connection failed, allow request
            if r is None:
                return True, limit
            
            current = r.get(f"ratelimit:{key}")
            
            current_count = int(current) if current else 0
            
            if current_count >= limit:
                # Rate limited
                ttl = r.ttl(f"ratelimit:{key}")
                return False, 0
            
            # Increment counter
            pipe = r.pipeline()
            pipe.incr(f"ratelimit:{key}")
            pipe.expire(f"ratelimit:{key}", window)
            pipe.execute()
            
            return True, limit - current_count - 1
            
        except Exception:
            # If Redis fails, allow request
            return True, limit
    
    async def rate_limit(self, key: str = None):
        """Decorator for rate limiting"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Get rate limit key
                rate_key = key or func.__name__
                
                # Check rate limit
                allowed, remaining = await self.check_rate_limit(rate_key)
                
                if not allowed:
                    raise HTTPException(
                        status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                        detail="Rate limit exceeded",
                        headers={"X-RateLimit-Remaining": "0"}
                    )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator


class InputValidator:
    """
    Input validation for API requests
    
    Features:
    - URL validation
    - Email validation
    - Custom validation rules
    """
    
    # URL regex pattern
    URL_PATTERN = re.compile(
        r'^https?://'  # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+[A-Z]{2,6}\.?|'  # domain
        r'localhost|'  # localhost
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # IP
        r'(?::\d+)?'  # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE
    )
    
    # Email regex pattern
    EMAIL_PATTERN = re.compile(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$')
    
    @classmethod
    def validate_url(cls, url: str) -> bool:
        """Validate URL format"""
        if not url or len(url) > 2048:
            return False
        return bool(cls.URL_PATTERN.match(url))
    
    @classmethod
    def validate_email(cls, email: str) -> bool:
        """Validate email format"""
        if not email:
            return False
        return bool(cls.EMAIL_PATTERN.match(email))
    
    @classmethod
    def validate_target_url(cls, url: str) -> tuple[bool, str]:
        """
        Validate target URL for scanning
        
        Returns:
            (is_valid, error_message)
        """
        # Check allowed protocols first
        if url:
            url_lower = url.lower()
            if not url_lower.startswith('http://') and not url_lower.startswith('https://'):
                return False, "Only HTTP and HTTPS protocols are allowed"
        
        # Check URL format
        if not cls.validate_url(url):
            return False, "Invalid URL format"
        
        # Check for localhost/private IPs (optional - can be enabled for security)
        # This is commented out to allow scanning internal APIs during development
        # if 'localhost' in url or '127.0.0.1' in url:
        #     return False, "Cannot scan localhost"
        
        return True, ""
    
    @classmethod
    def sanitize_input(cls, input_str: str, max_length: int = 1000) -> str:
        """Sanitize user input"""
        if not input_str:
            return ""
        
        # Remove null bytes
        sanitized = input_str.replace('\x00', '')
        
        # Truncate to max length
        if len(sanitized) > max_length:
            sanitized = sanitized[:max_length]
        
        return sanitized.strip()


class AuthorizationHandler:
    """
    Handle authorization and access control
    
    Features:
    - Role-based access control (RBAC)
    - Permission checking
    - Resource-level authorization
    """
    
    # Role permissions
    PERMISSIONS = {
        "admin": [
            "scan:create", "scan:read", "scan:update", "scan:delete",
            "target:create", "target:read", "target:update", "target:delete",
            "report:create", "report:read", "report:export",
            "user:create", "user:read", "user:update", "user:delete",
            "settings:read", "settings:update"
        ],
        "security_engineer": [
            "scan:create", "scan:read", "scan:update", "scan:delete",
            "target:create", "target:read", "target:update",
            "report:create", "report:read", "report:export",
            "settings:read"
        ],
        "developer": [
            "scan:create", "scan:read",
            "target:read",
            "report:read"
        ],
        "viewer": [
            "scan:read",
            "target:read",
            "report:read"
        ]
    }
    
    @classmethod
    def check_permission(cls, user_roles: List[str], permission: str) -> bool:
        """Check if user has permission"""
        for role in user_roles:
            role_permissions = cls.PERMISSIONS.get(role, [])
            if permission in role_permissions:
                return True
        return False
    
    @classmethod
    def require_permission(cls, permission: str):
        """Decorator to require specific permission"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                # Get current user from token
                # This would be extracted from the request context
                # For now, assume it's passed as a kwarg
                user = kwargs.get("current_user")
                
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required"
                    )
                
                if not cls.check_permission(user.roles, permission):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail=f"Permission denied: {permission}"
                    )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator
    
    @classmethod
    def require_role(cls, required_roles: List[str]):
        """Decorator to require specific role"""
        def decorator(func):
            @wraps(func)
            async def wrapper(*args, **kwargs):
                user = kwargs.get("current_user")
                
                if not user:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Authentication required"
                    )
                
                user_roles = set(user.roles)
                required = set(required_roles)
                
                if not user_roles.intersection(required):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="Insufficient permissions"
                    )
                
                return await func(*args, **kwargs)
            return wrapper
        return decorator


# Pydantic models for request validation
class ScanCreateRequest(BaseModel):
    """Request model for creating a scan"""
    name: str = Field(..., min_length=1, max_length=100)
    target_url: str = Field(..., min_length=1)
    scan_type: str = Field(default="full")
    description: Optional[str] = Field(None, max_length=500)
    
    @validator('target_url')
    def validate_target_url(cls, v):
        is_valid, error = InputValidator.validate_target_url(v)
        if not is_valid:
            raise ValueError(error)
        return v


class TargetCreateRequest(BaseModel):
    """Request model for creating a target"""
    name: str = Field(..., min_length=1, max_length=100)
    url: str = Field(..., min_length=1)
    description: Optional[str] = Field(None, max_length=500)
    tags: List[str] = Field(default_factory=list)
    
    @validator('url')
    def validate_url(cls, v):
        is_valid, error = InputValidator.validate_target_url(v)
        if not is_valid:
            raise ValueError(error)
        return v


class LoginRequest(BaseModel):
    """Request model for login"""
    username: str = Field(..., min_length=1)
    password: str = Field(..., min_length=1)


# Security middleware
class SecurityMiddleware:
    """Security middleware for FastAPI"""
    
    @staticmethod
    def add_security_headers(response):
        """Add security headers to response"""
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        return response
