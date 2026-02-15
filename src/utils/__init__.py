"""
VulnScope - Utility Functions
Common utilities for VulnScope platform
"""

import hashlib
import secrets
import string
from typing import Any, Dict, Optional
from datetime import datetime, timezone


def generate_id(length: int = 8) -> str:
    """Generate a random ID"""
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(length))


def hash_content(content: str) -> str:
    """Generate SHA-256 hash of content"""
    return hashlib.sha256(content.encode()).hexdigest()


def utc_now() -> datetime:
    """Get current UTC datetime"""
    return datetime.now(timezone.utc)


def format_timestamp(dt: datetime) -> str:
    """Format datetime as ISO string"""
    return dt.isoformat()


def parse_timestamp(ts: str) -> datetime:
    """Parse ISO timestamp string"""
    return datetime.fromisoformat(ts)


def sanitize_filename(filename: str) -> str:
    """Sanitize filename for safe storage"""
    # Remove invalid characters
    invalid_chars = '<>:"/\\|?*'
    for char in invalid_chars:
        filename = filename.replace(char, '_')
    return filename


def truncate(text: str, length: int = 100, suffix: str = "...") -> str:
    """Truncate text to specified length"""
    if len(text) <= length:
        return text
    return text[:length - len(suffix)] + suffix


def dict_merge(dict1: Dict, dict2: Dict) -> Dict:
    """Merge two dictionaries"""
    result = dict1.copy()
    result.update(dict2)
    return result


def safe_get(dictionary: Dict, *keys: str, default: Any = None) -> Any:
    """Safely get nested dictionary value"""
    current = dictionary
    for key in keys:
        if isinstance(current, dict):
            current = current.get(key)
            if current is None:
                return default
        else:
            return default
    return current


class RateTracker:
    """Track request rates"""
    
    def __init__(self, max_requests: int, window_seconds: int = 60):
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self.requests: list = []
    
    def allow_request(self) -> bool:
        """Check if request is allowed"""
        now = datetime.now().timestamp()
        
        # Remove old requests
        self.requests = [t for t in self.requests if now - t < self.window_seconds]
        
        if len(self.requests) < self.max_requests:
            self.requests.append(now)
            return True
        
        return False
    
    def get_remaining(self) -> int:
        """Get remaining requests in window"""
        now = datetime.now().timestamp()
        self.requests = [t for t in self.requests if now - t < self.window_seconds]
        return max(0, self.max_requests - len(self.requests))
