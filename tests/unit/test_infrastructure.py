"""
VulnScope - Infrastructure Unit Tests
Tests for Cache Manager, Message Queue, Backup Manager, Task Scheduler
"""

import pytest
import os
import json
import tempfile
from unittest.mock import Mock, patch, MagicMock
from datetime import datetime, timedelta
from pathlib import Path

from src.utils.infrastructure import (
    CacheManager, MessageQueue, BackupManager, BackupConfig,
    TaskScheduler, get_cache_manager, get_message_queue, get_backup_manager
)


class TestCacheManager:
    """Test Redis cache manager"""
    
    def test_initialization(self):
        """Test cache manager initialization"""
        cache = CacheManager()
        assert cache.default_ttl == 3600
    
    def test_initialization_with_redis(self):
        """Test initialization with Redis client"""
        mock_redis = Mock()
        cache = CacheManager(redis_client=mock_redis)
        assert cache.redis == mock_redis
    
    def test_get_hit(self):
        """Test cache get with hit"""
        import pickle
        mock_redis = Mock()
        mock_redis.get.return_value = pickle.dumps({"key": "value"})
        
        cache = CacheManager(redis_client=mock_redis)
        result = cache.get("test_key")
        
        assert result == {"key": "value"}
        mock_redis.get.assert_called_once_with("test_key")
    
    def test_get_miss(self):
        """Test cache get with miss"""
        mock_redis = Mock()
        mock_redis.get.return_value = None
        
        cache = CacheManager(redis_client=mock_redis)
        result = cache.get("missing_key")
        
        assert result is None
    
    def test_get_error(self):
        """Test cache get handles errors"""
        mock_redis = Mock()
        mock_redis.get.side_effect = Exception("Redis error")
        
        cache = CacheManager(redis_client=mock_redis)
        result = cache.get("test_key")
        
        assert result is None
    
    def test_set(self):
        """Test cache set"""
        mock_redis = Mock()
        
        cache = CacheManager(redis_client=mock_redis)
        cache.set("test_key", {"data": "value"}, ttl=1800)
        
        assert mock_redis.setex.called
        call_args = mock_redis.setex.call_args
        assert call_args[0][0] == "test_key"
        assert call_args[0][1] == 1800
    
    def test_set_default_ttl(self):
        """Test cache set with default TTL"""
        mock_redis = Mock()
        
        cache = CacheManager(redis_client=mock_redis)
        cache.set("test_key", {"data": "value"})
        
        call_args = mock_redis.setex.call_args
        assert call_args[0][1] == 3600  # default TTL
    
    def test_set_error(self):
        """Test cache set handles errors"""
        mock_redis = Mock()
        mock_redis.setex.side_effect = Exception("Redis error")
        
        cache = CacheManager(redis_client=mock_redis)
        # Should not raise
        cache.set("test_key", {"data": "value"})
    
    def test_delete(self):
        """Test cache delete"""
        mock_redis = Mock()
        
        cache = CacheManager(redis_client=mock_redis)
        cache.delete("test_key")
        
        mock_redis.delete.assert_called_once_with("test_key")
    
    def test_delete_error(self):
        """Test cache delete handles errors"""
        mock_redis = Mock()
        mock_redis.delete.side_effect = Exception("Redis error")
        
        cache = CacheManager(redis_client=mock_redis)
        # Should not raise
        cache.delete("test_key")
    
    def test_delete_pattern(self):
        """Test deleting keys by pattern"""
        mock_redis = Mock()
        mock_redis.keys.return_value = [b"key1", b"key2", b"key3"]
        
        cache = CacheManager(redis_client=mock_redis)
        cache.delete_pattern("test_*")
        
        mock_redis.keys.assert_called_once_with("test_*")
        mock_redis.delete.assert_called_once()
    
    def test_delete_pattern_no_keys(self):
        """Test deleting pattern with no keys"""
        mock_redis = Mock()
        mock_redis.keys.return_value = []
        
        cache = CacheManager(redis_client=mock_redis)
        cache.delete_pattern("test_*")
        
        # Should not call delete
        mock_redis.delete.assert_not_called()
    
    def test_get_or_compute_cached(self):
        """Test get or compute with cached value"""
        import pickle
        mock_redis = Mock()
        mock_redis.get.return_value = pickle.dumps("cached_value")
        
        cache = CacheManager(redis_client=mock_redis)
        compute_fn = Mock(return_value="computed_value")
        
        result = cache.get_or_compute("test_key", compute_fn)
        
        assert result == "cached_value"
        compute_fn.assert_not_called()
    
    def test_get_or_compute_not_cached(self):
        """Test get or compute without cached value"""
        mock_redis = Mock()
        mock_redis.get.return_value = None
        
        cache = CacheManager(redis_client=mock_redis)
        compute_fn = Mock(return_value="computed_value")
        
        result = cache.get_or_compute("test_key", compute_fn)
        
        assert result == "computed_value"
        compute_fn.assert_called_once()
    
    def test_cache_scan_results(self):
        """Test caching scan results"""
        mock_redis = Mock()
        
        cache = CacheManager(redis_client=mock_redis)
        cache.cache_scan_results("http://example.com", [{"finding": "xss"}])
        
        assert mock_redis.setex.called
    
    def test_get_cached_scan_results(self):
        """Test getting cached scan results"""
        import pickle
        mock_redis = Mock()
        cached_findings = [{"finding": "xss"}]
        mock_redis.get.return_value = pickle.dumps(cached_findings)
        
        cache = CacheManager(redis_client=mock_redis)
        result = cache.get_cached_scan_results("http://example.com")
        
        assert result == cached_findings


class TestMessageQueue:
    """Test Redis message queue"""
    
    def test_initialization(self):
        """Test message queue initialization"""
        queue = MessageQueue()
        assert queue.default_queue == "vulnscope:tasks"
    
    def test_initialization_with_redis(self):
        """Test initialization with Redis client"""
        mock_redis = Mock()
        queue = MessageQueue(redis_client=mock_redis)
        assert queue.redis == mock_redis
    
    def test_enqueue(self):
        """Test enqueueing a task"""
        mock_redis = Mock()
        
        queue = MessageQueue(redis_client=mock_redis)
        task_id = queue.enqueue("scan", {"target": "http://example.com"})
        
        assert task_id is not None
        assert "scan:" in task_id
        mock_redis.zadd.assert_called_once()
    
    def test_enqueue_with_priority(self):
        """Test enqueueing with priority"""
        mock_redis = Mock()
        
        queue = MessageQueue(redis_client=mock_redis)
        queue.enqueue("scan", {"target": "http://example.com"}, priority=10)
        
        call_args = mock_redis.zadd.call_args
        task_data = json.loads(list(call_args[0][0].keys())[0])
        assert task_data["priority"] == 10
    
    def test_enqueue_scan(self):
        """Test enqueueing scan task"""
        mock_redis = Mock()
        
        queue = MessageQueue(redis_client=mock_redis)
        task_id = queue.enqueue_scan("http://example.com", {"depth": 3})
        
        assert task_id is not None
        mock_redis.zadd.assert_called_once()
    
    def test_enqueue_export(self):
        """Test enqueueing export task"""
        mock_redis = Mock()
        
        queue = MessageQueue(redis_client=mock_redis)
        task_id = queue.enqueue_export("scan-123", "json")
        
        assert task_id is not None
    
    def test_dequeue(self):
        """Test dequeueing tasks"""
        mock_redis = Mock()
        task1 = json.dumps({
            "id": "scan:1",
            "type": "scan",
            "payload": {"target": "http://example.com"},
            "priority": 1
        })
        task2 = json.dumps({
            "id": "scan:2",
            "type": "scan",
            "payload": {"target": "http://other.com"},
            "priority": 0
        })
        mock_redis.zrevrange.return_value = [task1, task2]
        
        queue = MessageQueue(redis_client=mock_redis)
        tasks = queue.dequeue(count=2)
        
        assert len(tasks) == 2
        assert tasks[0]["id"] == "scan:1"
    
    def test_dequeue_empty(self):
        """Test dequeueing from empty queue"""
        mock_redis = Mock()
        mock_redis.zrevrange.return_value = []
        
        queue = MessageQueue(redis_client=mock_redis)
        tasks = queue.dequeue()
        
        assert len(tasks) == 0
    
    def test_get_queue_size(self):
        """Test getting queue size"""
        mock_redis = Mock()
        mock_redis.zcard.return_value = 5
        
        queue = MessageQueue(redis_client=mock_redis)
        size = queue.get_queue_size()
        
        assert size == 5


class TestBackupManager:
    """Test backup manager"""
    
    def test_initialization(self):
        """Test backup manager initialization"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = BackupConfig(backup_dir=tmpdir)
            manager = BackupManager(config)
            
            assert manager.config == config
            assert manager.backup_dir.exists()
    
    def test_default_config(self):
        """Test default backup config"""
        config = BackupConfig()
        
        assert config.backup_dir == "/var/vulnscope/backups"
        assert config.retention_days == 30
        assert config.max_backups == 10
        assert config.compress is True
    
    def test_create_backup(self):
        """Test creating a backup"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a file to backup
            source_file = os.path.join(tmpdir, "source.txt")
            with open(source_file, 'w') as f:
                f.write("test data")
            
            config = BackupConfig(backup_dir=os.path.join(tmpdir, "backups"))
            manager = BackupManager(config)
            
            backup_path = manager.create_backup(source_file)
            
            assert backup_path is not None
            assert os.path.exists(backup_path)
    
    def test_create_backup_with_name(self):
        """Test creating backup with custom name"""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = os.path.join(tmpdir, "source.txt")
            with open(source_file, 'w') as f:
                f.write("test data")
            
            config = BackupConfig(backup_dir=os.path.join(tmpdir, "backups"))
            manager = BackupManager(config)
            
            backup_path = manager.create_backup(source_file, "custom_backup")
            
            assert "custom_backup" in backup_path
    
    def test_backup_database(self):
        """Test database backup"""
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create a mock database file
            db_file = os.path.join(tmpdir, "vulnscope.db")
            with open(db_file, 'w') as f:
                f.write("database content")
            
            config = BackupConfig(backup_dir=os.path.join(tmpdir, "backups"))
            manager = BackupManager(config)
            
            backup_path = manager.backup_database(db_file)
            
            assert backup_path is not None
            assert "db_" in backup_path
    
    def test_list_backups(self):
        """Test listing backups"""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = os.path.join(tmpdir, "source.txt")
            with open(source_file, 'w') as f:
                f.write("test data")
            
            config = BackupConfig(backup_dir=os.path.join(tmpdir, "backups"))
            manager = BackupManager(config)
            
            # Create multiple backups
            manager.create_backup(source_file, "backup1")
            manager.create_backup(source_file, "backup2")
            
            backups = manager.list_backups()
            
            assert len(backups) == 2
    
    def test_list_backups_empty(self):
        """Test listing backups when empty"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = BackupConfig(backup_dir=tmpdir)
            manager = BackupManager(config)
            
            backups = manager.list_backups()
            
            assert len(backups) == 0
    
    def test_verify_backup_valid(self):
        """Test verifying valid backup"""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = os.path.join(tmpdir, "source.txt")
            with open(source_file, 'w') as f:
                f.write("test data")
            
            config = BackupConfig(backup_dir=os.path.join(tmpdir, "backups"))
            manager = BackupManager(config)
            
            backup_path = manager.create_backup(source_file)
            is_valid = manager.verify_backup(backup_path)
            
            assert is_valid is True
    
    def test_verify_backup_invalid(self):
        """Test verifying invalid backup"""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = BackupConfig(backup_dir=tmpdir)
            manager = BackupManager(config)
            
            # Non-existent file
            is_valid = manager.verify_backup("/nonexistent/backup.tar.gz")
            
            assert is_valid is False
    
    def test_restore_backup(self):
        """Test restoring from backup"""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = os.path.join(tmpdir, "source.txt")
            with open(source_file, 'w') as f:
                f.write("original data")
            
            config = BackupConfig(backup_dir=os.path.join(tmpdir, "backups"))
            manager = BackupManager(config)
            
            backup_path = manager.create_backup(source_file)
            
            # Modify original file
            with open(source_file, 'w') as f:
                f.write("modified data")
            
            # Restore
            restore_dir = os.path.join(tmpdir, "restored")
            os.makedirs(restore_dir)
            manager.restore_backup(backup_path, restore_dir)
            
            # Check restored content
            restored_file = os.path.join(restore_dir, "source.txt")
            with open(restored_file, 'r') as f:
                content = f.read()
            
            assert content == "original data"
    
    def test_cleanup_old_backups(self):
        """Test cleanup of old backups"""
        with tempfile.TemporaryDirectory() as tmpdir:
            source_file = os.path.join(tmpdir, "source.txt")
            with open(source_file, 'w') as f:
                f.write("test data")
            
            config = BackupConfig(
                backup_dir=os.path.join(tmpdir, "backups"),
                max_backups=2,
                retention_days=30
            )
            manager = BackupManager(config)
            
            # Create 5 backups
            for i in range(5):
                manager.create_backup(source_file, f"backup_{i}")
            
            # Cleanup
            manager.cleanup_old_backups()
            
            # Should only have 2 backups left
            backups = manager.list_backups()
            assert len(backups) == 2


class TestTaskScheduler:
    """Test task scheduler"""
    
    def test_initialization(self):
        """Test scheduler initialization"""
        scheduler = TaskScheduler()
        assert len(scheduler.tasks) == 0
    
    def test_schedule_interval(self):
        """Test scheduling interval task"""
        scheduler = TaskScheduler()
        
        task_fn = Mock()
        scheduler.schedule_interval("test_task", task_fn, interval_seconds=60)
        
        assert "test_task" in scheduler.tasks
        assert scheduler.tasks["test_task"]["interval"] == 60
    
    def test_schedule_daily(self):
        """Test scheduling daily task"""
        scheduler = TaskScheduler()
        
        task_fn = Mock()
        scheduler.schedule_daily("daily_task", task_fn, hour=2, minute=30)
        
        assert "daily_task" in scheduler.tasks
        assert scheduler.tasks["daily_task"]["hour"] == 2
        assert scheduler.tasks["daily_task"]["minute"] == 30
    
    def test_run_pending(self):
        """Test running pending tasks"""
        scheduler = TaskScheduler()
        
        task_fn = Mock()
        scheduler.schedule_interval("test_task", task_fn, interval_seconds=60)
        
        # Set next_run to past so task will run
        scheduler.tasks["test_task"]["next_run"] = datetime.utcnow() - timedelta(seconds=1)
        
        scheduler.run_pending()
        
        task_fn.assert_called_once()
    
    def test_run_pending_not_due(self):
        """Test running pending when not due"""
        scheduler = TaskScheduler()
        
        task_fn = Mock()
        scheduler.schedule_interval("test_task", task_fn, interval_seconds=60)
        
        # Set next_run to future
        scheduler.tasks["test_task"]["next_run"] = datetime.utcnow() + timedelta(hours=1)
        
        scheduler.run_pending()
        
        task_fn.assert_not_called()
    
    def test_run_pending_error_handling(self):
        """Test error handling in run_pending"""
        scheduler = TaskScheduler()
        
        task_fn = Mock(side_effect=Exception("Task error"))
        scheduler.schedule_interval("test_task", task_fn, interval_seconds=60)
        
        # Set next_run to past
        scheduler.tasks["test_task"]["next_run"] = datetime.utcnow() - timedelta(seconds=1)
        
        # Should not raise
        scheduler.run_pending()
        
        task_fn.assert_called_once()
    
    def test_get_next_run(self):
        """Test getting next run time"""
        scheduler = TaskScheduler()
        
        task_fn = Mock()
        scheduler.schedule_interval("test_task", task_fn, interval_seconds=60)
        
        next_run = scheduler.get_next_run("test_task")
        
        assert next_run is not None
        assert isinstance(next_run, datetime)
    
    def test_get_next_run_nonexistent(self):
        """Test getting next run for nonexistent task"""
        scheduler = TaskScheduler()
        
        next_run = scheduler.get_next_run("nonexistent")
        
        assert next_run is None


class TestSingletonFunctions:
    """Test singleton getter functions"""
    
    @patch('src.utils.infrastructure.CacheManager')
    def test_get_cache_manager(self, mock_class):
        """Test getting cache manager singleton"""
        import src.utils.infrastructure as infra
        infra._cache_manager = None  # Reset singleton
        
        manager = get_cache_manager()
        
        assert manager is not None
    
    @patch('src.utils.infrastructure.MessageQueue')
    def test_get_message_queue(self, mock_class):
        """Test getting message queue singleton"""
        import src.utils.infrastructure as infra
        infra._message_queue = None  # Reset singleton
        
        queue = get_message_queue()
        
        assert queue is not None
    
    @patch('src.utils.infrastructure.BackupManager')
    def test_get_backup_manager(self, mock_class):
        """Test getting backup manager singleton"""
        import src.utils.infrastructure as infra
        infra._backup_manager = None  # Reset singleton
        
        manager = get_backup_manager()
        
        assert manager is not None


if __name__ == "__main__":
    pytest.main([__file__, "-v"])