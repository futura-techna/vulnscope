"""
VulnScope - Crawler Unit Tests
Tests for the web crawler component
"""

import pytest
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime
from uuid import uuid4
from urllib.parse import urlparse

from src.discovery.crawler import (
    Crawler, CrawlerResult, get_default_crawler_config
)
from src.core.models import Target, Endpoint
from src.config.settings import CrawlerConfig


class TestCrawlerResult:
    """Test CrawlerResult dataclass"""
    
    def test_default_values(self):
        result = CrawlerResult()
        assert len(result.endpoints) == 0
        assert result.pages_crawled == 0
        assert len(result.errors) == 0
        assert result.duration_seconds == 0.0
    
    def test_with_endpoints(self):
        target_id = uuid4()
        endpoints = [
            Endpoint(
                target_id=target_id,
                url="http://example.com/page1",
                method="GET",
                path="/page1"
            ),
            Endpoint(
                target_id=target_id,
                url="http://example.com/page2",
                method="GET",
                path="/page2"
            ),
        ]
        
        result = CrawlerResult(endpoints=endpoints, pages_crawled=5)
        assert len(result.endpoints) == 2
        assert result.pages_crawled == 5


class TestCrawler:
    """Test Crawler class"""
    
    def test_initialization(self):
        crawler = Crawler()
        assert crawler.config is not None
        assert crawler.session is not None
        assert len(crawler.visited_urls) == 0
    
    def test_initialization_with_config(self):
        config = CrawlerConfig(max_pages=50)
        crawler = Crawler(config)
        assert crawler.config.max_pages == 50
    
    def test_is_valid_url(self):
        crawler = Crawler()
        
        # Valid URLs
        assert crawler._is_valid_url("http://example.com")
        assert crawler._is_valid_url("https://example.com/path")
        
        # Invalid URLs
        assert not crawler._is_valid_url("")
        assert not crawler._is_valid_url(None)
        assert not crawler._is_valid_url("javascript:void(0)")
        assert not crawler._is_valid_url("#fragment")
    
    def test_is_valid_url_with_allowed_domains(self):
        config = CrawlerConfig(allowed_domains=["example.com"])
        crawler = Crawler(config)
        
        assert crawler._is_valid_url("http://example.com/page")
        assert not crawler._is_valid_url("http://other.com/page")
    
    def test_is_valid_url_with_blocked_domains(self):
        config = CrawlerConfig(blocked_domains=["blocked.com"])
        crawler = Crawler(config)
        
        assert not crawler._is_valid_url("http://blocked.com/page")
        assert crawler._is_valid_url("http://example.com/page")
    
    def test_normalize_url(self):
        crawler = Crawler()
        
        # Remove fragment
        assert crawler._normalize_url("http://example.com/page#fragment") == "http://example.com/page"
        
        # Lowercase host
        assert crawler._normalize_url("http://EXAMPLE.COM/Page") == "http://example.com/Page"
        
        # Remove trailing slash
        assert crawler._normalize_url("http://example.com/page/") == "http://example.com/page"
    
    def test_extract_links(self):
        crawler = Crawler()
        
        html = '''
        <html>
        <body>
            <a href="/page1">Link 1</a>
            <a href="http://example.com/page2">Link 2</a>
            <a href="http://other.com/page3">Link 3</a>
            <a href="#fragment">Fragment</a>
            <a href="javascript:void(0)">JS</a>
        </body>
        </html>
        '''
        
        links = crawler._extract_links(html, "http://example.com")
        
        # Should extract valid links
        assert len(links) > 0
    
    def test_extract_forms(self):
        crawler = Crawler()
        
        html = '''
        <html>
        <body>
            <form action="/login" method="POST">
                <input type="text" name="username" required>
                <input type="password" name="password">
                <button type="submit">Login</button>
            </form>
        </body>
        </html>
        '''
        
        forms = crawler._extract_forms(html, "http://example.com")
        
        assert len(forms) == 1
        assert forms[0]['method'] == 'POST'
        assert len(forms[0]['inputs']) == 2
    
    def test_extract_api_endpoints(self):
        crawler = Crawler()
        
        html = '''
        <html>
        <body>
            <a href="/api/v1/users">API Users</a>
            <a href="/api/products">API Products</a>
            <a href="/graphql">GraphQL</a>
        </body>
        </html>
        '''
        
        endpoints = crawler._extract_api_endpoints(html, "http://example.com")
        
        assert len(endpoints) > 0
    
    def test_create_endpoint(self):
        crawler = Crawler()
        
        endpoint = crawler._create_endpoint(
            "http://example.com/api/users",
            method="GET",
            source="crawler"
        )
        
        assert endpoint.url == "http://example.com/api/users"
        assert endpoint.method == "GET"
        assert endpoint.path == "/api/users"
        assert endpoint.source == "crawler"
    
    def test_fetch_page_success(self):
        crawler = Crawler()
        
        with patch.object(crawler.session, 'get') as mock_get:
            mock_response = Mock()
            mock_response.text = "<html><body>Content</body></html>"
            mock_response.raise_for_status = Mock()
            mock_get.return_value = mock_response
            
            result = crawler._fetch_page("http://example.com")
            
            assert result is not None
            assert "Content" in result
    
    def test_fetch_page_failure(self):
        crawler = Crawler()
        
        with patch.object(crawler.session, 'get') as mock_get:
            mock_get.side_effect = Exception("Connection error")
            
            result = crawler._fetch_page("http://example.com")
            
            assert result is None
            assert len(crawler.errors) > 0


class TestCrawlerIntegration:
    """Integration tests for Crawler"""
    
    @pytest.mark.asyncio
    async def test_crawl_basic(self):
        crawler = Crawler()
        
        target = Target(
            name="Test Target",
            url="http://example.com"
        )
        
        with patch.object(crawler, '_fetch_page') as mock_fetch:
            mock_fetch.return_value = '''
            <html>
            <body>
                <a href="/page1">Page 1</a>
                <a href="/page2">Page 2</a>
            </body>
            </html>
            '''
            
            result = await crawler.crawl(target)
            
            assert result is not None
            assert isinstance(result, CrawlerResult)
    
    def test_crawl_sync(self):
        crawler = Crawler()
        
        target = Target(
            name="Test Target",
            url="http://example.com"
        )
        
        with patch.object(crawler, '_fetch_page') as mock_fetch:
            mock_fetch.return_value = "<html><body>Content</body></html>"
            
            # Test that method exists
            assert hasattr(crawler, 'crawl_sync')


class TestDefaultConfig:
    """Test default configuration"""
    
    def test_get_default_crawler_config(self):
        config = get_default_crawler_config()
        assert config is not None
        assert isinstance(config, CrawlerConfig)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])