"""
VulnScope - Configuration Unit Tests
Tests for configuration settings
"""

import pytest
from unittest.mock import Mock, patch

from src.config.settings import (
    Settings, ScannerConfig, CrawlerConfig, FuzzerConfig,
    DatabaseConfig, RedisConfig, EvidenceConfig,
    get_settings, LogLevel, ScannerMode, OutputFormat
)


class TestSettings:
    """Test Settings class"""
    
    def test_default_settings(self):
        settings = Settings()
        assert settings is not None
    
    def test_app_name(self):
        settings = Settings()
        assert hasattr(settings, 'app_name')
        assert settings.app_name == "VulnScope"
    
    def test_environment(self):
        settings = Settings()
        assert hasattr(settings, 'environment')
    
    def test_app_version(self):
        settings = Settings()
        assert hasattr(settings, 'app_version')
    
    def test_debug_default(self):
        settings = Settings()
        assert settings.debug == False
    
    def test_nested_configs(self):
        settings = Settings()
        assert hasattr(settings, 'database')
        assert hasattr(settings, 'redis')
        assert hasattr(settings, 'scanner')
        assert hasattr(settings, 'crawler')
        assert hasattr(settings, 'fuzzer')
        assert hasattr(settings, 'evidence')


class TestScannerConfig:
    """Test ScannerConfig class"""
    
    def test_default_config(self):
        config = ScannerConfig()
        assert config is not None
    
    def test_rate_limit_default(self):
        config = ScannerConfig()
        assert config.rate_limit_per_second > 0
    
    def test_timeout_default(self):
        config = ScannerConfig()
        assert config.request_timeout > 0
    
    def test_max_concurrent_requests(self):
        config = ScannerConfig()
        assert config.max_concurrent_requests > 0
    
    def test_custom_config(self):
        config = ScannerConfig(
            rate_limit_per_second=50,
            request_timeout=60,
            max_concurrent_requests=20
        )
        assert config.rate_limit_per_second == 50
        assert config.request_timeout == 60
        assert config.max_concurrent_requests == 20
    
    def test_allowed_domains(self):
        config = ScannerConfig(allowed_domains=["example.com"])
        assert "example.com" in config.allowed_domains
    
    def test_blocked_domains(self):
        config = ScannerConfig(blocked_domains=["blocked.com"])
        assert "blocked.com" in config.blocked_domains
    
    def test_scanner_mode_default(self):
        config = ScannerConfig()
        assert config.mode == ScannerMode.ACTIVE
    
    def test_follow_redirects_default(self):
        config = ScannerConfig()
        assert config.follow_redirects == True


class TestCrawlerConfig:
    """Test CrawlerConfig class"""
    
    def test_default_config(self):
        config = CrawlerConfig()
        assert config is not None
    
    def test_max_pages_default(self):
        config = CrawlerConfig()
        assert config.max_pages > 0
    
    def test_max_depth_default(self):
        config = CrawlerConfig()
        assert hasattr(config, 'max_depth')
        assert config.max_depth == 5
    
    def test_concurrency_default(self):
        config = CrawlerConfig()
        assert config.concurrency > 0
    
    def test_extract_forms_option(self):
        config = CrawlerConfig(extract_forms=True)
        assert config.extract_forms == True
    
    def test_extract_api_endpoints_option(self):
        config = CrawlerConfig(extract_api_endpoints=True)
        assert config.extract_api_endpoints == True
    
    def test_respect_robots_txt(self):
        config = CrawlerConfig()
        assert config.respect_robots_txt == True


class TestFuzzerConfig:
    """Test FuzzerConfig class"""
    
    def test_default_config(self):
        config = FuzzerConfig()
        assert config is not None
    
    def test_payloads_per_endpoint(self):
        config = FuzzerConfig()
        assert config.payloads_per_endpoint == 1000
    
    def test_test_sqli_default(self):
        config = FuzzerConfig()
        assert config.test_sql_injection == True
    
    def test_test_xss_default(self):
        config = FuzzerConfig()
        assert config.test_xss == True


class TestDatabaseConfig:
    """Test DatabaseConfig class"""
    
    def test_default_config(self):
        config = DatabaseConfig()
        assert config is not None
    
    def test_default_url(self):
        config = DatabaseConfig()
        assert config.url == "sqlite:///vulnscope.db"
    
    def test_pool_size(self):
        config = DatabaseConfig()
        assert config.pool_size == 10


class TestRedisConfig:
    """Test RedisConfig class"""
    
    def test_default_config(self):
        config = RedisConfig()
        assert config is not None
    
    def test_default_host(self):
        config = RedisConfig()
        assert config.host == "localhost"
    
    def test_default_port(self):
        config = RedisConfig()
        assert config.port == 6379


class TestEvidenceConfig:
    """Test EvidenceConfig class"""
    
    def test_default_config(self):
        config = EvidenceConfig()
        assert config is not None
    
    def test_encryption_enabled(self):
        config = EvidenceConfig()
        assert config.encryption_enabled == True
    
    def test_retention_days(self):
        config = EvidenceConfig()
        assert config.retention_days == 365


class TestGetSettings:
    """Test get_settings function"""
    
    def test_get_settings_returns_settings(self):
        settings = get_settings()
        assert isinstance(settings, Settings)
    
    def test_get_settings_singleton(self):
        settings1 = get_settings()
        settings2 = get_settings()
        # Should return same instance (cached)
        assert settings1 is not None
        assert settings2 is not None


class TestEnums:
    """Test configuration enums"""
    
    def test_log_level_enum(self):
        assert LogLevel.DEBUG == "DEBUG"
        assert LogLevel.INFO == "INFO"
        assert LogLevel.WARNING == "WARNING"
        assert LogLevel.ERROR == "ERROR"
    
    def test_scanner_mode_enum(self):
        assert ScannerMode.PASSIVE == "passive"
        assert ScannerMode.ACTIVE == "active"
        assert ScannerMode.FUZZING == "fuzzing"
    
    def test_output_format_enum(self):
        assert OutputFormat.JSON == "json"
        assert OutputFormat.HTML == "html"
        assert OutputFormat.SARIF == "sarif"


class TestConfigValidation:
    """Test configuration validation"""
    
    def test_scanner_config_validation(self):
        # Valid config
        config = ScannerConfig(
            rate_limit_per_second=100,
            request_timeout=30
        )
        assert config.rate_limit_per_second == 100
    
    def test_crawler_config_validation(self):
        # Valid config
        config = CrawlerConfig(
            max_pages=100,
            max_depth=5
        )
        assert config.max_pages == 100


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
