"""
VulnScope - Token Storage Service
Persistent storage for verification and reset tokens using Redis
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional, Dict, Any

logger = logging.getLogger(__name__)

# Try to import redis
try:
    import redis
    REDIS_AVAILABLE = True
except ImportError:
    REDIS_AVAILABLE = False
    logger.warning("Redis not installed - falling back to in-memory token storage")


class TokenStorage:
    """
    Token storage service with Redis backend and in-memory fallback.
    Persists verification tokens across server restarts.
    """
    
    def __init__(self, redis_url: Optional[str] = None):
        self._redis_client = None
        self._memory_store: Dict[str, Dict[str, Any]] = {}
        
        if REDIS_AVAILABLE and redis_url:
            try:
                self._redis_client = redis.from_url(
                    redis_url,
                    socket_connect_timeout=5,
                    socket_timeout=5,
                    decode_responses=True
                )
                # Test connection
                self._redis_client.ping()
                logger.info(f"[TokenStorage] Connected to Redis successfully")
            except Exception as e:
                logger.warning(f"[TokenStorage] Redis connection failed, using in-memory fallback: {e}")
                self._redis_client = None
        else:
            logger.info("[TokenStorage] Using in-memory token storage")
    
    @property
    def is_redis(self) -> bool:
        """Check if Redis is being used"""
        return self._redis_client is not None
    
    def _get_key(self, token_type: str, token: str) -> str:
        """Generate Redis key for token"""
        return f"vulnscope:{token_type}:{token}"
    
    def store_token(
        self,
        token_type: str,  # 'email_verification' or 'password_reset'
        token: str,
        data: Dict[str, Any],
        expires_in_hours: int = 24
    ) -> bool:
        """
        Store a token with associated data.
        
        Args:
            token_type: Type of token (email_verification, password_reset)
            token: The token string
            data: Associated data (email, user_id, etc.)
            expires_in_hours: Token expiration time in hours
            
        Returns:
            True if stored successfully
        """
        key = self._get_key(token_type, token)
        expires_at = (datetime.utcnow() + timedelta(hours=expires_in_hours)).isoformat()
        
        token_data = {
            **data,
            "expires": expires_at,
            "created_at": datetime.utcnow().isoformat()
        }
        
        try:
            if self._redis_client:
                # Store in Redis with expiration
                self._redis_client.setex(
                    key,
                    timedelta(hours=expires_in_hours),
                    json.dumps(token_data)
                )
                logger.debug(f"[TokenStorage] Stored {token_type} token in Redis: {token[:20]}...")
            else:
                # Store in memory
                self._memory_store[key] = token_data
                logger.debug(f"[TokenStorage] Stored {token_type} token in memory: {token[:20]}...")
            
            return True
        except Exception as e:
            logger.error(f"[TokenStorage] Failed to store token: {e}")
            return False
    
    def get_token(
        self,
        token_type: str,
        token: str
    ) -> Optional[Dict[str, Any]]:
        """
        Retrieve token data.
        
        Args:
            token_type: Type of token
            token: The token string
            
        Returns:
            Token data if found and not expired, None otherwise
        """
        key = self._get_key(token_type, token)
        
        try:
            if self._redis_client:
                data = self._redis_client.get(key)
                if data:
                    token_data = json.loads(data)
                else:
                    return None
            else:
                token_data = self._memory_store.get(key)
            
            if not token_data:
                return None
            
            # Check expiration
            expires = datetime.fromisoformat(token_data["expires"])
            if datetime.utcnow() > expires:
                # Token expired, delete it
                self.delete_token(token_type, token)
                logger.debug(f"[TokenStorage] Token expired: {token[:20]}...")
                return None
            
            return token_data
            
        except (KeyError, ValueError) as e:
            # Malformed token data - delete it and return None
            logger.error(f"[TokenStorage] Failed to get token: {e}")
            self.delete_token(token_type, token)
            return None
        except Exception as e:
            logger.error(f"[TokenStorage] Failed to get token: {e}")
            return None
    
    def delete_token(self, token_type: str, token: str) -> bool:
        """
        Delete a token.
        
        Args:
            token_type: Type of token
            token: The token string
            
        Returns:
            True if deleted successfully
        """
        key = self._get_key(token_type, token)
        
        try:
            if self._redis_client:
                self._redis_client.delete(key)
            else:
                self._memory_store.pop(key, None)
            
            return True
        except Exception as e:
            logger.error(f"[TokenStorage] Failed to delete token: {e}")
            return False
    
    def token_exists(self, token_type: str, token: str) -> bool:
        """Check if a token exists"""
        return self.get_token(token_type, token) is not None
    
    def cleanup_expired(self) -> int:
        """
        Remove expired tokens from memory store.
        Redis handles this automatically.
        
        Returns:
            Number of tokens cleaned up
        """
        if self._redis_client:
            return 0  # Redis handles expiration automatically
        
        count = 0
        now = datetime.utcnow()
        expired_keys = []
        
        for key, data in self._memory_store.items():
            try:
                expires = datetime.fromisoformat(data["expires"])
                if now > expires:
                    expired_keys.append(key)
                    count += 1
            except (KeyError, ValueError):
                expired_keys.append(key)
                count += 1
        
        for key in expired_keys:
            del self._memory_store[key]
        
        if count > 0:
            logger.info(f"[TokenStorage] Cleaned up {count} expired tokens")
        
        return count
    
    def list_tokens(self, token_type: str) -> list:
        """
        List all tokens of a given type (for debugging).
        
        Args:
            token_type: Type of token
            
        Returns:
            List of token keys (without full token values for security)
        """
        prefix = f"vulnscope:{token_type}:"
        
        if self._redis_client:
            keys = self._redis_client.keys(f"{prefix}*")
            return [k.replace(prefix, '')[:20] + '...' for k in keys]
        else:
            return [k.replace(prefix, '')[:20] + '...' for k in self._memory_store.keys() if k.startswith(prefix)]


# Global instance
_token_storage: Optional[TokenStorage] = None


def get_token_storage() -> TokenStorage:
    """Get or create token storage singleton"""
    global _token_storage
    
    if _token_storage is None:
        from src.config.settings import get_settings
        settings = get_settings()
        
        redis_url = settings.redis.url or (
            f"redis://:{settings.redis.password}@{settings.redis.host}:{settings.redis.port}/{settings.redis.db}"
            if settings.redis.password else
            f"redis://{settings.redis.host}:{settings.redis.port}/{settings.redis.db}"
        )
        
        _token_storage = TokenStorage(redis_url)
    
    return _token_storage