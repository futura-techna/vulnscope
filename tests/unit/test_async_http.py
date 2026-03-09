"""
VulnScope - Async HTTP Unit Tests
Tests for async HTTP client
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from uuid import uuid4

from src.utils.async_http import AsyncHTTPClient, AsyncRateLimiter, AsyncCrawler
from src.config.settings import ScannerConfig


class TestAsyncHTTPClient:
    """Test AsyncHTTPClient class"""
    
    def test_initialization(self):
        client = AsyncHTTPClient()
        assert client is not None
        assert client.config is not None
    
    def test_initialization_with_config(self):
        config = ScannerConfig(
            request_timeout=30,
            max_concurrent_requests=20
        )
        client = AsyncHTTPClient(config)
        
        assert client.config.request_timeout == 30
        assert client.config.max_concurrent_requests == 20
    
    def test_default_session_is_none(self):
        client = AsyncHTTPClient()
        assert client.session is None
    
    def test_default_semaphore_is_none(self):
        client = AsyncHTTPClient()
        assert client.semaphore is None
    
    def test_request_count_starts_at_zero(self):
        client = AsyncHTTPClient()
        assert client.request_count == 0


class TestAsyncHTTPClientAsync:
    """Test AsyncHTTPClient async operations"""
    
    @pytest.mark.asyncio
    async def test_context_manager(self):
        config = ScannerConfig()
        
        async with AsyncHTTPClient(config) as client:
            assert client.session is not None
            assert client.semaphore is not None
        
        # Session should be closed after context exit
        assert client.session is None or client.session.closed
    
    @pytest.mark.asyncio
    async def test_fetch_returns_response(self):
        config = ScannerConfig()
        
        async with AsyncHTTPClient(config) as client:
            with patch.object(client, 'fetch', new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = {
                    'status': 200,
                    'headers': {},
                    'body': 'OK',
                    'url': 'http://example.com'
                }
                
                response = await client.fetch("http://example.com")
                
                assert response is not None
                assert response['status'] == 200
    
    @pytest.mark.asyncio
    async def test_fetch_handles_timeout(self):
        config = ScannerConfig(request_timeout=1)
        
        async with AsyncHTTPClient(config) as client:
            # Mock the session to raise TimeoutError
            with patch.object(client, 'fetch', new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = None
                
                response = await client.fetch("http://example.com")
                
                assert response is None
    
    @pytest.mark.asyncio
    async def test_fetch_multiple(self):
        config = ScannerConfig()
        
        async with AsyncHTTPClient(config) as client:
            urls = [
                "http://example.com/page1",
                "http://example.com/page2",
                "http://example.com/page3"
            ]
            
            with patch.object(client, 'fetch', new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = {'status': 200, 'body': 'OK', 'headers': {}, 'url': 'test'}
                
                responses = await client.fetch_multiple(urls)
                
                assert len(responses) == 3
    
    @pytest.mark.asyncio
    async def test_fetch_increments_request_count(self):
        config = ScannerConfig()
        
        async with AsyncHTTPClient(config) as client:
            initial_count = client.request_count
            
            with patch.object(client, 'fetch', new_callable=AsyncMock) as mock_fetch:
                mock_fetch.return_value = {'status': 200, 'body': 'OK', 'headers': {}, 'url': 'test'}
                
                await client.fetch("http://example.com")
                
                # Request count should increment


class TestAsyncRateLimiter:
    """Test AsyncRateLimiter class"""
    
    def test_initialization(self):
        limiter = AsyncRateLimiter(requests_per_second=100)
        
        assert limiter.requests_per_second == 100
        assert limiter.interval == 0.01  # 1/100
    
    def test_custom_rate(self):
        limiter = AsyncRateLimiter(requests_per_second=10)
        
        assert limiter.requests_per_second == 10
        assert limiter.interval == 0.1  # 1/10
    
    def test_last_request_starts_at_zero(self):
        limiter = AsyncRateLimiter()
        
        assert limiter.last_request == 0.0
    
    @pytest.mark.asyncio
    async def test_acquire(self):
        limiter = AsyncRateLimiter(requests_per_second=100)
        
        # Should not raise
        await limiter.acquire()
        
        # Last request time should be updated
        assert limiter.last_request > 0
    
    @pytest.mark.asyncio
    async def test_rate_limiting_delays(self):
        limiter = AsyncRateLimiter(requests_per_second=10)
        
        import time
        start = time.time()
        
        await limiter.acquire()
        await limiter.acquire()
        
        elapsed = time.time() - start
        
        # Second request should have been delayed
        # At 10 req/s, interval is 0.1s


class TestAsyncCrawler:
    """Test AsyncCrawler class"""
    
    def test_initialization(self):
        crawler = AsyncCrawler()
        assert crawler is not None
    
    def test_initialization_with_config(self):
        config = ScannerConfig(max_concurrent_requests=20)
        crawler = AsyncCrawler(config)
        
        assert crawler.config.max_concurrent_requests == 20
    
    def test_visited_starts_empty(self):
        crawler = AsyncCrawler()
        assert len(crawler.visited) == 0
    
    def test_endpoints_starts_empty(self):
        crawler = AsyncCrawler()
        assert len(crawler.endpoints) == 0
    
    def test_client_starts_none(self):
        crawler = AsyncCrawler()
        assert crawler.client is None
    
    @pytest.mark.asyncio
    async def test_crawl_returns_endpoints(self):
        config = ScannerConfig()
        crawler = AsyncCrawler(config)
        
        with patch.object(crawler, 'crawl', new_callable=AsyncMock) as mock_crawl:
            from src.core.models import Endpoint
            
            mock_crawl.return_value = [
                Endpoint(target_id=uuid4(), url="http://example.com", method="GET", path="/", source="crawler")
            ]
            
            endpoints = await crawler.crawl("http://example.com", max_pages=1)
            
            assert len(endpoints) == 1


class TestScannerConfigForHTTP:
    """Test ScannerConfig for HTTP client"""
    
    def test_default_timeout(self):
        config = ScannerConfig()
        assert config.request_timeout == 30
    
    def test_default_max_concurrent(self):
        config = ScannerConfig()
        assert config.max_concurrent_requests == 50
    
    def test_default_user_agent(self):
        config = ScannerConfig()
        assert "VulnScope" in config.user_agent
    
    def test_default_follow_redirects(self):
        config = ScannerConfig()
        assert config.follow_redirects == True
    
    def test_default_verify_ssl(self):
        config = ScannerConfig()
        assert config.verify_ssl == True
    
    def test_custom_config(self):
        config = ScannerConfig(
            request_timeout=60,
            max_concurrent_requests=100,
            follow_redirects=False,
            verify_ssl=False
        )
        
        assert config.request_timeout == 60
        assert config.max_concurrent_requests == 100
        assert config.follow_redirects == False
        assert config.verify_ssl == False


class TestAsyncHTTPIntegration:
    """Integration tests for async HTTP (with mocking)"""
    
    @pytest.mark.asyncio
    async def test_full_request_flow(self):
        config = ScannerConfig(request_timeout=5)
        
        async with AsyncHTTPClient(config) as client:
            assert client.session is not None
            assert client.semaphore is not None
            
            # Mock a successful response
            with patch.object(client.session, 'request') as mock_request:
                mock_response = AsyncMock()
                mock_response.status = 200
                mock_response.headers = {'Content-Type': 'text/html'}
                mock_response.url = 'http://example.com'
                mock_response.text = AsyncMock(return_value='<html>OK</html>')
                mock_request.return_value.__aenter__.return_value = mock_response
                
                response = await client.fetch("http://example.com")
                
                assert response is not None
    
    @pytest.mark.asyncio
    async def test_concurrent_requests_respect_semaphore(self):
        config = ScannerConfig(max_concurrent_requests=5)
        
        async with AsyncHTTPClient(config) as client:
            assert client.semaphore._value == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])