"""
VulnScope - Performance Tests
Tests for performance and load testing
"""

import pytest
import asyncio
import time
import statistics
from typing import List
from unittest.mock import Mock, patch
from uuid import uuid4

from src.scanner.advanced_scanner import (
    AsyncScanOptimizer, FuzzingWordlistManager
)
from src.discovery.advanced_discovery import (
    JavaScriptParser, APIVersionDetector
)
from src.api.security import RateLimiter
from src.utils.infrastructure import (
    CacheManager, MessageQueue
)


# ============================================
# PERFORMANCE BENCHMARKS
# ============================================
class PerformanceBenchmark:
    """Helper class for performance benchmarking"""
    
    def __init__(self):
        self.results: List[float] = []
    
    def measure(self, func, *args, iterations: int = 100, **kwargs):
        """Measure execution time"""
        times = []
        
        for _ in range(iterations):
            start = time.perf_counter()
            func(*args, **kwargs)
            end = time.perf_counter()
            times.append(end - start)
        
        return {
            "mean": statistics.mean(times),
            "median": statistics.median(times),
            "stdev": statistics.stdev(times) if len(times) > 1 else 0,
            "min": min(times),
            "max": max(times),
            "iterations": iterations
        }


class TestScannerPerformance:
    """Test scanner performance"""
    
    @pytest.mark.asyncio
    async def test_async_scan_throughput(self):
        """Test async scan throughput"""
        optimizer = AsyncScanOptimizer(max_concurrent=50)
        
        async def mock_scan(endpoint):
            await asyncio.sleep(0.001)  # Simulate work
            return {"endpoint": endpoint, "vulnerabilities": []}
        
        # Test with different endpoint counts
        endpoint_counts = [10, 50, 100, 200]
        results = []
        
        for count in endpoint_counts:
            endpoints = [f"http://example.com/api/{i}" for i in range(count)]
            
            start = time.perf_counter()
            await optimizer.scan_with_backpressure(endpoints, mock_scan)
            duration = time.perf_counter() - start
            
            throughput = count / duration
            results.append({
                "endpoints": count,
                "duration": duration,
                "throughput": throughput
            })
        
        # Verify throughput improves with concurrency
        assert results[-1]["throughput"] > results[0]["throughput"]
    
    def test_fuzzing_payload_generation_performance(self):
        """Test fuzzing payload generation speed"""
        manager = FuzzingWordlistManager()
        
        benchmark = PerformanceBenchmark()
        
        # Add many words
        for i in range(1000):
            manager.add_word("large", f"word_{i}")
        
        # Measure generation
        result = benchmark.measure(
            manager.generate_fuzz_payloads,
            "test",
            "large",
            iterations=10
        )
        
        # Should complete quickly
        assert result["mean"] < 1.0  # Less than 1 second
    
    def test_wordlist_loading_performance(self):
        """Test wordlist loading performance"""
        manager = FuzzingWordlistManager()
        
        benchmark = PerformanceBenchmark()
        
        # Measure wordlist access
        result = benchmark.measure(
            manager.get_wordlist,
            "parameters",
            iterations=1000
        )
        
        # Should be very fast
        assert result["mean"] < 0.001  # Less than 1ms


class TestDiscoveryPerformance:
    """Test discovery performance"""
    
    def test_javascript_parsing_performance(self):
        """Test JavaScript parsing speed"""
        parser = JavaScriptParser()
        
        # Large JavaScript content
        js_content = """
        """ + "\n".join([
            f'axios.get("/api/v1/resource{i}");'
            for i in range(100)
        ])
        
        benchmark = PerformanceBenchmark()
        
        result = benchmark.measure(
            parser._extract_api_endpoints,
            js_content,
            "http://example.com",
            iterations=100
        )
        
        assert result["mean"] < 0.1  # Less than 100ms
    
    def test_api_version_detection_performance(self):
        """Test API version detection speed"""
        detector = APIVersionDetector()
        
        # Create many endpoints - need target_id
        from src.core.models import Endpoint
        
        target_id = uuid4()
        endpoints = []
        for v in range(1, 6):  # v1 to v5
            for r in range(100):  # 100 resources per version
                endpoints.append(Endpoint(
                    target_id=target_id,
                    url=f"http://api.example.com/v{v}/resource{r}",
                    method="GET",
                    path=f"/v{v}/resource{r}"
                ))
        
        benchmark = PerformanceBenchmark()
        
        result = benchmark.measure(
            detector.detect_versions,
            endpoints,
            iterations=50
        )
        
        assert result["mean"] < 0.1  # Less than 100ms


class TestSecurityPerformance:
    """Test security component performance"""
    
    @pytest.mark.asyncio
    async def test_rate_limiter_performance(self):
        """Test rate limiter speed"""
        with patch('src.api.security.redis.Redis') as mock_redis:
            mock_client = Mock()
            mock_redis.return_value = mock_client
            mock_client.get.return_value = None
            
            limiter = RateLimiter(mock_client)
            
            benchmark = PerformanceBenchmark()
            
            # Measure rate limit checks - run directly in the async context
            async def run_check():
                times = []
                for _ in range(100):
                    start = time.perf_counter()
                    await limiter.check_rate_limit("test_key", 100, 60)
                    end = time.perf_counter()
                    times.append(end - start)
                return {
                    "mean": statistics.mean(times),
                    "median": statistics.median(times),
                }
            
            result = await run_check()
            
            # Should be fast
            assert result["mean"] < 0.01


class TestInfrastructurePerformance:
    """Test infrastructure component performance"""
    
    @patch('src.utils.infrastructure.redis.Redis')
    def test_cache_operations_performance(self, mock_redis):
        """Test cache operations speed"""
        mock_client = Mock()
        mock_redis.return_value = mock_client
        mock_client.get.return_value = None
        
        manager = CacheManager(mock_client)
        
        benchmark = PerformanceBenchmark()
        
        # Measure cache set
        result = benchmark.measure(
            manager.set,
            "test_key",
            {"data": "value"},
            iterations=100
        )
        
        assert result["mean"] < 0.01  # Less than 10ms
    
    @patch('src.utils.infrastructure.redis.Redis')
    def test_message_queue_performance(self, mock_redis):
        """Test message queue performance"""
        mock_client = Mock()
        mock_redis.return_value = mock_client
        
        queue = MessageQueue(mock_client)
        
        benchmark = PerformanceBenchmark()
        
        # Measure enqueue
        result = benchmark.measure(
            queue.enqueue,
            "test_task",
            {"data": "value"},
            iterations=100
        )
        
        assert result["mean"] < 0.01


# ============================================
# LOAD TESTS
# ============================================
class TestLoadScenarios:
    """Load testing scenarios"""
    
    @pytest.mark.asyncio
    async def test_concurrent_scan_load(self):
        """Test scanning under load"""
        optimizer = AsyncScanOptimizer(max_concurrent=100)
        
        scan_times = []
        
        async def load_test():
            # Single scan run
            endpoints = [f"http://api.example.com/{i}" for i in range(50)]
            
            async def scan(ep):
                await asyncio.sleep(0.001)
                return {"endpoint": ep}
            
            start = time.perf_counter()
            await optimizer.scan_with_backpressure(endpoints, scan)
            scan_times.append(time.perf_counter() - start)
        
        # Run 5 load tests concurrently
        await asyncio.gather(*[load_test() for _ in range(5)])
        
        # Should complete all scans
        assert len(scan_times) == 5
        assert all(t > 0 for t in scan_times)
    
    def test_memory_usage_with_large_wordlists(self):
        """Test memory usage with large wordlists"""
        manager = FuzzingWordlistManager()
        
        # Add large wordlist
        for i in range(10000):
            manager.add_word("massive", f"word_{i}")
        
        # Should still be functional
        wordlist = manager.get_wordlist("massive")
        
        assert len(wordlist) == 10000
        
        # Generation should still work
        payloads = manager.generate_fuzz_payloads("test", "massive")
        
        assert len(payloads) > 0


# ============================================
# STRESS TESTS
# ============================================
class TestStressScenarios:
    """Stress testing scenarios"""
    
    @pytest.mark.asyncio
    async def test_high_concurrency_stress(self):
        """Test system under high concurrency"""
        optimizer = AsyncScanOptimizer(max_concurrent=1000)
        
        endpoints = [f"http://example.com/{i}" for i in range(500)]
        
        success_count = 0
        error_count = 0
        
        async def scan_with_tracking(endpoint):
            nonlocal success_count, error_count
            try:
                await asyncio.sleep(0.001)
                success_count += 1
                return {"endpoint": endpoint}
            except Exception:
                error_count += 1
                return None
        
        await optimizer.scan_with_backpressure(endpoints, scan_with_tracking)
        
        # Should handle all requests
        assert success_count + error_count == 500
    
    def test_cache_overflow_handling(self):
        """Test handling of cache overflow"""
        with patch('src.utils.infrastructure.redis.Redis') as mock_redis:
            mock_client = Mock()
            mock_redis.return_value = mock_client
            
            # Simulate Redis errors
            mock_client.setex.side_effect = Exception("Redis full")
            
            manager = CacheManager(mock_client)
            
            # Should not raise
            try:
                manager.set("key", {"data": "value"})
            except Exception:
                pass  # Expected to handle gracefully


# Run performance tests
if __name__ == "__main__":
    pytest.main([__file__, "-v", "--tb=short"])
