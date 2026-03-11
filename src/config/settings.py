"""
VulnScope - Settings Configuration
Centralized configuration management for VulnScope platform
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings
from enum import Enum


class LogLevel(str, Enum):
    DEBUG = "DEBUG"
    INFO = "INFO"
    WARNING = "WARNING"
    ERROR = "ERROR"


class ScannerMode(str, Enum):
    PASSIVE = "passive"
    ACTIVE = "active"
    FUZZING = "fuzzing"


class OutputFormat(str, Enum):
    JSON = "json"
    XML = "xml"
    HTML = "html"
    SARIF = "sarif"
    CSV = "csv"


class DatabaseConfig(BaseModel):
    """Database connection configuration"""
    url: str = Field(default="sqlite:///vulnscope.db")
    pool_size: int = Field(default=10)
    max_overflow: int = Field(default=20)
    echo: bool = Field(default=False)


class RedisConfig(BaseModel):
    """Redis cache configuration"""
    url: Optional[str] = Field(default=None)  # Full connection URL (Render provides this)
    host: str = Field(default="localhost")
    port: int = Field(default=6379)
    db: int = Field(default=0)
    password: Optional[str] = Field(default=None)
    
    def get_connection_params(self) -> dict:
        """
        Parse Redis URL and return connection parameters.
        Handles Render's redis:// URL format.
        """
        if self.url:
            # Parse URL like redis://user:password@host:port/db
            # or redis://host:port/db
            from urllib.parse import urlparse
            parsed = urlparse(self.url)
            
            host = parsed.hostname or self.host
            port = parsed.port or self.port
            password = parsed.password or self.password
            
            # Extract DB number from path (e.g., /0 -> 0)
            db = 0
            if parsed.path and parsed.path != '/':
                try:
                    db = int(parsed.path.lstrip('/'))
                except ValueError:
                    pass
            
            return {
                'host': host,
                'port': port,
                'db': db,
                'password': password
            }
        
        return {
            'host': self.host,
            'port': self.port,
            'db': self.db,
            'password': self.password
        }


class ScannerConfig(BaseModel):
    """Scanner engine configuration"""
    mode: ScannerMode = Field(default=ScannerMode.ACTIVE)
    max_concurrent_requests: int = Field(default=50)
    request_timeout: int = Field(default=30)
    max_retries: int = Field(default=3)
    rate_limit_per_second: int = Field(default=100)
    user_agent: str = Field(
        default="VulnScope-Scanner/1.0 (Security Assessment Tool)"
    )
    follow_redirects: bool = Field(default=True)
    verify_ssl: bool = Field(default=True)
    allowed_domains: Optional[List[str]] = Field(default=None)
    blocked_domains: Optional[List[str]] = Field(default=None)


class CrawlerConfig(BaseModel):
    """Web crawler configuration"""
    max_depth: int = Field(default=5)
    max_pages: int = Field(default=1000)
    concurrency: int = Field(default=10)
    delay_between_requests: float = Field(default=0.5)
    respect_robots_txt: bool = Field(default=True)
    extract_forms: bool = Field(default=True)
    extract_api_endpoints: bool = Field(default=True)


class FuzzerConfig(BaseModel):
    """API Fuzzer configuration"""
    wordlists_path: str = Field(default="/opt/vulnscope/wordlists")
    payloads_per_endpoint: int = Field(default=1000)
    enable_auth_bypass: bool = Field(default=True)
    test_rate_limiting: bool = Field(default=True)
    test_idor: bool = Field(default=True)
    test_sql_injection: bool = Field(default=True)
    test_xss: bool = Field(default=True)
    test_ssrf: bool = Field(default=True)


class EvidenceConfig(BaseModel):
    """Evidence vault configuration"""
    storage_path: str = Field(default="/var/vulnscope/evidence")
    encryption_enabled: bool = Field(default=True)
    retention_days: int = Field(default=365)
    compression: bool = Field(default=True)


class Settings(BaseSettings):
    """Main application settings"""
    
    # Application
    app_name: str = "VulnScope"
    app_version: str = "1.0.0"
    debug: bool = Field(default=False)
    environment: str = Field(default="production")
    
    # Logging
    log_level: LogLevel = Field(default=LogLevel.INFO)
    log_file: Optional[str] = Field(default=None)  # None = stdout only (container-friendly)
    
    # Security
    api_key: Optional[str] = Field(default=None)
    secret_key: Optional[str] = Field(default=None)
    
    # Database
    database: DatabaseConfig = Field(default_factory=DatabaseConfig)
    
    # Redis
    redis: RedisConfig = Field(default_factory=RedisConfig)
    
    # Scanner
    scanner: ScannerConfig = Field(default_factory=ScannerConfig)
    
    # Crawler
    crawler: CrawlerConfig = Field(default_factory=CrawlerConfig)
    
    # Fuzzer
    fuzzer: FuzzerConfig = Field(default_factory=FuzzerConfig)
    
    # Evidence
    evidence: EvidenceConfig = Field(default_factory=EvidenceConfig)
    
    # Output
    output_format: OutputFormat = Field(default=OutputFormat.JSON)
    output_directory: str = Field(default="/var/vulnscope/reports")
    
    class Config:
        env_prefix = "VULNSCOPE_"
        env_nested_delimiter = "__"


# Global settings instance
_settings: Optional[Settings] = None


def get_settings() -> Settings:
    """Get or create settings singleton"""
    global _settings
    if _settings is None:
        _settings = Settings()
    return _settings
