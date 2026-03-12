"""
VulnScope - Token Storage Unit Tests
Tests for token storage service (Redis and in-memory fallback)
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
import json

from src.utils.token_storage import TokenStorage, get_token_storage


class TestTokenStorageInit:
    """Test TokenStorage initialization"""
    
    def test_initialization_without_redis(self):
        """Test initialization without Redis URL"""
        storage = TokenStorage(redis_url=None)
        
        assert storage._redis_client is None
        assert storage.is_redis is False
        assert isinstance(storage._memory_store, dict)
    
    @patch('src.utils.token_storage.REDIS_AVAILABLE', False)
    def test_initialization_redis_not_available(self):
        """Test initialization when Redis is not installed"""
        storage = TokenStorage(redis_url="redis://localhost:6379")
        
        assert storage._redis_client is None
        assert storage.is_redis is False


class TestTokenStorageInMemory:
    """Test in-memory token storage"""
    
    def test_store_token(self):
        """Test storing a token"""
        storage = TokenStorage(redis_url=None)
        
        result = storage.store_token(
            token_type="email_verification",
            token="test-token-123",
            data={"user_id": "1", "email": "test@example.com"},
            expires_in_hours=24
        )
        
        assert result is True
        assert len(storage._memory_store) == 1
    
    def test_get_token_valid(self):
        """Test getting a valid token"""
        storage = TokenStorage(redis_url=None)
        
        storage.store_token(
            token_type="password_reset",
            token="valid-token",
            data={"email": "user@example.com"},
            expires_in_hours=1
        )
        
        token_data = storage.get_token("password_reset", "valid-token")
        
        assert token_data is not None
        assert token_data["email"] == "user@example.com"
    
    def test_get_token_not_found(self):
        """Test getting a non-existent token"""
        storage = TokenStorage(redis_url=None)
        
        token_data = storage.get_token("password_reset", "nonexistent-token")
        
        assert token_data is None
    
    def test_get_token_expired(self):
        """Test getting an expired token"""
        storage = TokenStorage(redis_url=None)
        
        # Store token with past expiration
        key = "vulnscope:password_reset:expired-token"
        storage._memory_store[key] = {
            "email": "user@example.com",
            "expires": (datetime.utcnow() - timedelta(hours=1)).isoformat(),
            "created_at": datetime.utcnow().isoformat()
        }
        
        token_data = storage.get_token("password_reset", "expired-token")
        
        # Should return None and delete the token
        assert token_data is None
        assert key not in storage._memory_store
    
    def test_delete_token(self):
        """Test deleting a token"""
        storage = TokenStorage(redis_url=None)
        
        storage.store_token(
            token_type="email_verification",
            token="token-to-delete",
            data={"email": "test@example.com"},
            expires_in_hours=24
        )
        
        result = storage.delete_token("email_verification", "token-to-delete")
        
        assert result is True
        assert storage.get_token("email_verification", "token-to-delete") is None
    
    def test_delete_token_nonexistent(self):
        """Test deleting a non-existent token"""
        storage = TokenStorage(redis_url=None)
        
        result = storage.delete_token("password_reset", "nonexistent-token")
        
        assert result is True  # Should still return True
    
    def test_token_exists(self):
        """Test checking if token exists"""
        storage = TokenStorage(redis_url=None)
        
        storage.store_token(
            token_type="email_verification",
            token="existing-token",
            data={"email": "test@example.com"},
            expires_in_hours=24
        )
        
        assert storage.token_exists("email_verification", "existing-token") is True
        assert storage.token_exists("email_verification", "nonexistent-token") is False
    
    def test_list_tokens(self):
        """Test listing tokens"""
        storage = TokenStorage(redis_url=None)
        
        storage.store_token(
            token_type="email_verification",
            token="token-1",
            data={"email": "test1@example.com"},
            expires_in_hours=24
        )
        storage.store_token(
            token_type="email_verification",
            token="token-2",
            data={"email": "test2@example.com"},
            expires_in_hours=24
        )
        
        tokens = storage.list_tokens("email_verification")
        
        assert len(tokens) == 2
    
    def test_cleanup_expired(self):
        """Test cleaning up expired tokens"""
        storage = TokenStorage(redis_url=None)
        
        # Add valid token
        storage.store_token(
            token_type="password_reset",
            token="valid-token",
            data={"email": "valid@example.com"},
            expires_in_hours=1
        )
        
        # Add expired token directly
        storage._memory_store["vulnscope:password_reset:expired-token"] = {
            "email": "expired@example.com",
            "expires": (datetime.utcnow() - timedelta(hours=1)).isoformat()
        }
        
        count = storage.cleanup_expired()
        
        assert count == 1
        assert storage.token_exists("password_reset", "valid-token") is True
        assert storage.token_exists("password_reset", "expired-token") is False


class TestTokenStorageRedis:
    """Test Redis token storage"""
    
    @patch('src.utils.token_storage.REDIS_AVAILABLE', True)
    @patch('src.utils.token_storage.redis')
    def test_redis_initialization_success(self, mock_redis_module):
        """Test successful Redis connection"""
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_redis_module.from_url.return_value = mock_client
        
        storage = TokenStorage(redis_url="redis://localhost:6379")
        
        assert storage.is_redis is True
        mock_redis_module.from_url.assert_called_once()
    
    @patch('src.utils.token_storage.REDIS_AVAILABLE', True)
    @patch('src.utils.token_storage.redis')
    def test_redis_connection_failure_fallback(self, mock_redis_module):
        """Test fallback to memory when Redis connection fails"""
        mock_redis_module.from_url.side_effect = Exception("Connection refused")
        
        storage = TokenStorage(redis_url="redis://localhost:6379")
        
        assert storage.is_redis is False
        assert storage._redis_client is None
    
    @patch('src.utils.token_storage.REDIS_AVAILABLE', True)
    @patch('src.utils.token_storage.redis')
    def test_redis_store_token(self, mock_redis_module):
        """Test storing token in Redis"""
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_redis_module.from_url.return_value = mock_client
        
        storage = TokenStorage(redis_url="redis://localhost:6379")
        
        result = storage.store_token(
            token_type="email_verification",
            token="redis-token",
            data={"user_id": "1"},
            expires_in_hours=24
        )
        
        assert result is True
        mock_client.setex.assert_called_once()
    
    @patch('src.utils.token_storage.REDIS_AVAILABLE', True)
    @patch('src.utils.token_storage.redis')
    def test_redis_get_token(self, mock_redis_module):
        """Test getting token from Redis"""
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_redis_module.from_url.return_value = mock_client
        
        token_data = {
            "user_id": "1",
            "email": "test@example.com",
            "expires": (datetime.utcnow() + timedelta(hours=1)).isoformat()
        }
        mock_client.get.return_value = json.dumps(token_data)
        
        storage = TokenStorage(redis_url="redis://localhost:6379")
        result = storage.get_token("email_verification", "redis-token")
        
        assert result is not None
        assert result["user_id"] == "1"
    
    @patch('src.utils.token_storage.REDIS_AVAILABLE', True)
    @patch('src.utils.token_storage.redis')
    def test_redis_get_token_not_found(self, mock_redis_module):
        """Test getting non-existent token from Redis"""
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_redis_module.from_url.return_value = mock_client
        mock_client.get.return_value = None
        
        storage = TokenStorage(redis_url="redis://localhost:6379")
        result = storage.get_token("email_verification", "nonexistent")
        
        assert result is None
    
    @patch('src.utils.token_storage.REDIS_AVAILABLE', True)
    @patch('src.utils.token_storage.redis')
    def test_redis_delete_token(self, mock_redis_module):
        """Test deleting token from Redis"""
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_redis_module.from_url.return_value = mock_client
        
        storage = TokenStorage(redis_url="redis://localhost:6379")
        result = storage.delete_token("email_verification", "redis-token")
        
        assert result is True
        mock_client.delete.assert_called_once()
    
    @patch('src.utils.token_storage.REDIS_AVAILABLE', True)
    @patch('src.utils.token_storage.redis')
    def test_redis_cleanup_returns_zero(self, mock_redis_module):
        """Test that cleanup returns 0 for Redis (handled automatically)"""
        mock_client = MagicMock()
        mock_client.ping.return_value = True
        mock_redis_module.from_url.return_value = mock_client
        
        storage = TokenStorage(redis_url="redis://localhost:6379")
        count = storage.cleanup_expired()
        
        assert count == 0  # Redis handles expiration automatically


class TestGetTokenStorage:
    """Test get_token_storage singleton function"""
    
    @patch('src.config.settings.get_settings')
    def test_get_token_storage_singleton(self, mock_settings):
        """Test that get_token_storage returns singleton"""
        mock_settings.return_value = MagicMock(
            redis=MagicMock(
                url=None,
                host='localhost',
                port=6379,
                password=None,
                db=0
            )
        )
        
        # Reset singleton
        import src.utils.token_storage as token_module
        token_module._token_storage = None
        
        storage1 = get_token_storage()
        storage2 = get_token_storage()
        
        assert storage1 is storage2


class TestTokenKeyGeneration:
    """Test token key generation"""
    
    def test_get_key_format(self):
        """Test that keys are generated in correct format"""
        storage = TokenStorage(redis_url=None)
        
        key = storage._get_key("email_verification", "abc123")
        
        assert key == "vulnscope:email_verification:abc123"
    
    def test_different_token_types(self):
        """Test that different token types have different keys"""
        storage = TokenStorage(redis_url=None)
        
        key1 = storage._get_key("email_verification", "token123")
        key2 = storage._get_key("password_reset", "token123")
        
        assert key1 != key2
        assert "email_verification" in key1
        assert "password_reset" in key2


class TestEdgeCases:
    """Test edge cases and error handling"""
    
    def test_store_token_with_special_characters(self):
        """Test storing token with special characters in data"""
        storage = TokenStorage(redis_url=None)
        
        result = storage.store_token(
            token_type="password_reset",
            token="token-with-special-chars",
            data={
                "email": "test+special@example.com",
                "name": "O'Brien"
            },
            expires_in_hours=1
        )
        
        assert result is True
        
        token_data = storage.get_token("password_reset", "token-with-special-chars")
        assert token_data["email"] == "test+special@example.com"
    
    def test_get_token_with_malformed_expiry(self):
        """Test getting token with malformed expiry date"""
        storage = TokenStorage(redis_url=None)
        
        # Add token with malformed expiry
        key = "vulnscope:password_reset:malformed-token"
        storage._memory_store[key] = {
            "email": "user@example.com",
            "expires": "not-a-date",
            "created_at": datetime.utcnow().isoformat()
        }
        
        # Should handle gracefully and remove the token
        token_data = storage.get_token("password_reset", "malformed-token")
        
        assert token_data is None
        assert key not in storage._memory_store
    
    def test_concurrent_access_simulation(self):
        """Test simulated concurrent access"""
        storage = TokenStorage(redis_url=None)
        
        # Store multiple tokens rapidly
        for i in range(100):
            storage.store_token(
                token_type="test",
                token=f"token-{i}",
                data={"index": i},
                expires_in_hours=1
            )
        
        # Verify all tokens stored
        assert len(storage.list_tokens("test")) == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])