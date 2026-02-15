"""
VulnScope - Infrastructure Components
Caching, message queue, and backup utilities
"""

import os
import json
import shutil
import hashlib
import redis
import pickle
from typing import Any, Optional, Dict, List
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
import logging

from ..config.settings import get_settings


logger = logging.getLogger(__name__)


# Cache Implementation
class CacheManager:
    """
    Redis-based caching manager
    
    Features:
    - Key-value caching with TTL
    - Cache invalidation
    - Cache patterns
    - Serialization support
    """
    
    def __init__(self, redis_client: redis.Redis = None):
        self.redis = redis_client
        self.default_ttl = 3600  # 1 hour
    
    def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection"""
        if self.redis is None:
            settings = get_settings()
            self.redis = redis.Redis(
                host=settings.redis.host,
                port=settings.redis.port,
                db=settings.redis.db,
                password=settings.redis.password,
                decode_responses=False  # Need binary for pickle
            )
        return self.redis
    
    def get(self, key: str) -> Optional[Any]:
        """Get value from cache"""
        try:
            r = self._get_redis()
            value = r.get(key)
            if value:
                return pickle.loads(value)
            return None
        except Exception as e:
            logger.error(f"Cache get error: {e}")
            return None
    
    def set(self, key: str, value: Any, ttl: int = None):
        """Set value in cache"""
        try:
            r = self._get_redis()
            ttl = ttl or self.default_ttl
            serialized = pickle.dumps(value)
            r.setex(key, ttl, serialized)
        except Exception as e:
            logger.error(f"Cache set error: {e}")
    
    def delete(self, key: str):
        """Delete key from cache"""
        try:
            r = self._get_redis()
            r.delete(key)
        except Exception as e:
            logger.error(f"Cache delete error: {e}")
    
    def delete_pattern(self, pattern: str):
        """Delete all keys matching pattern"""
        try:
            r = self._get_redis()
            keys = r.keys(pattern)
            if keys:
                r.delete(*keys)
        except Exception as e:
            logger.error(f"Cache delete pattern error: {e}")
    
    def get_or_compute(self, key: str, compute_fn, ttl: int = None) -> Any:
        """Get from cache or compute and cache"""
        value = self.get(key)
        if value is not None:
            return value
        
        value = compute_fn()
        self.set(key, value, ttl)
        return value
    
    def cache_scan_results(self, target_url: str, findings: List):
        """Cache scan results"""
        key = f"scan_results:{hashlib.md5(target_url.encode()).hexdigest()}"
        self.set(key, findings, ttl=1800)  # 30 minutes
    
    def get_cached_scan_results(self, target_url: str) -> Optional[List]:
        """Get cached scan results"""
        key = f"scan_results:{hashlib.md5(target_url.encode()).hexdigest()}"
        return self.get(key)


# Message Queue Implementation
class MessageQueue:
    """
    Redis-based message queue for background tasks
    
    Features:
    - Task queuing
    - Task scheduling
    - Priority support
    - Retry logic
    """
    
    def __init__(self, redis_client: redis.Redis = None):
        self.redis = redis_client
        self.default_queue = "vulnscope:tasks"
    
    def _get_redis(self) -> redis.Redis:
        """Get or create Redis connection"""
        if self.redis is None:
            settings = get_settings()
            self.redis = redis.Redis(
                host=settings.redis.host,
                port=settings.redis.port,
                db=settings.redis.db,
                password=settings.redis.password,
                decode_responses=True
            )
        return self.redis
    
    def enqueue(self, task_type: str, payload: Dict, priority: int = 0, 
                queue: str = None) -> str:
        """
        Add task to queue
        
        Args:
            task_type: Type of task (e.g., 'scan', 'export')
            payload: Task data
            priority: Higher = more important
            queue: Queue name
            
        Returns:
            Task ID
        """
        queue = queue or self.default_queue
        task_id = f"{task_type}:{datetime.utcnow().timestamp()}"
        
        task = {
            "id": task_id,
            "type": task_type,
            "payload": payload,
            "priority": priority,
            "created_at": datetime.utcnow().isoformat(),
            "retries": 0
        }
        
        r = self._get_redis()
        
        # Use sorted set for priority queue
        r.zadd(queue, {json.dumps(task): priority})
        
        return task_id
    
    def dequeue(self, queue: str = None, count: int = 1) -> List[Dict]:
        """Get tasks from queue"""
        queue = queue or self.default_queue
        r = self._get_redis()
        
        # Get highest priority tasks
        tasks = r.zrevrange(queue, 0, count - 1)
        
        result = []
        for task_json in tasks:
            task = json.loads(task_json)
            # Remove from queue
            r.zrem(queue, task_json)
            result.append(task)
        
        return result
    
    def enqueue_scan(self, target_url: str, scan_config: Dict) -> str:
        """Enqueue a scan task"""
        return self.enqueue("scan", {
            "target_url": target_url,
            "config": scan_config
        }, priority=1)
    
    def enqueue_export(self, scan_id: str, format: str) -> str:
        """Enqueue an export task"""
        return self.enqueue("export", {
            "scan_id": scan_id,
            "format": format
        }, priority=0)
    
    def get_queue_size(self, queue: str = None) -> int:
        """Get number of tasks in queue"""
        queue = queue or self.default_queue
        r = self._get_redis()
        return r.zcard(queue)


# Backup Manager
@dataclass
class BackupConfig:
    """Backup configuration"""
    backup_dir: str = "/var/vulnscope/backups"
    retention_days: int = 30
    max_backups: int = 10
    compress: bool = True


class BackupManager:
    """
    Automated backup manager
    
    Features:
    - Scheduled backups
    - Retention policies
    - Compression support
    - Backup verification
    """
    
    def __init__(self, config: BackupConfig = None):
        self.config = config or BackupConfig()
        self.backup_dir = Path(self.config.backup_dir)
        self.backup_dir.mkdir(parents=True, exist_ok=True)
    
    def create_backup(self, source_path: str, backup_name: str = None) -> str:
        """
        Create a backup
        
        Args:
            source_path: Path to backup
            backup_name: Name for backup (optional)
            
        Returns:
            Backup file path
        """
        if backup_name is None:
            timestamp = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
            backup_name = f"backup_{timestamp}"
        
        backup_path = self.backup_dir / f"{backup_name}.tar.gz"
        
        # Create tar archive
        import tarfile
        with tarfile.open(backup_path, "w:gz" if self.config.compress else "w") as tar:
            tar.add(source_path, arcname=os.path.basename(source_path))
        
        logger.info(f"Backup created: {backup_path}")
        return str(backup_path)
    
    def backup_database(self, db_path: str = "vulnscope.db") -> str:
        """Backup database"""
        return self.create_backup(db_path, f"db_{datetime.utcnow().strftime('%Y%m%d')}")
    
    def backup_config(self, config_dir: str = "config") -> str:
        """Backup configuration"""
        return self.create_backup(config_dir, f"config_{datetime.utcnow().strftime('%Y%m%d')}")
    
    def restore_backup(self, backup_path: str, restore_path: str):
        """
        Restore from backup
        
        Args:
            backup_path: Path to backup file
            restore_path: Path to restore to
        """
        import tarfile
        
        with tarfile.open(backup_path, "r:*") as tar:
            tar.extractall(path=restore_path)
        
        logger.info(f"Backup restored from: {backup_path}")
    
    def list_backups(self) -> List[Dict]:
        """List available backups"""
        backups = []
        
        for backup_file in self.backup_dir.glob("*.tar.gz"):
            stat = backup_file.stat()
            backups.append({
                "name": backup_file.name,
                "path": str(backup_file),
                "size": stat.st_size,
                "created": datetime.fromtimestamp(stat.st_mtime).isoformat()
            })
        
        return sorted(backups, key=lambda x: x["created"], reverse=True)
    
    def cleanup_old_backups(self):
        """Remove old backups based on retention policy"""
        backups = self.list_backups()
        
        # Remove by age
        cutoff = datetime.utcnow() - timedelta(days=self.config.retention_days)
        
        for backup in backups:
            created = datetime.fromisoformat(backup["created"])
            if created < cutoff:
                os.remove(backup["path"])
                logger.info(f"Removed old backup: {backup['name']}")
        
        # Remove excess backups by count
        backups = self.list_backups()
        if len(backups) > self.config.max_backups:
            for backup in backups[self.config.max_backups:]:
                os.remove(backup["path"])
                logger.info(f"Removed excess backup: {backup['name']}")
    
    def verify_backup(self, backup_path: str) -> bool:
        """Verify backup integrity"""
        try:
            import tarfile
            with tarfile.open(backup_path, "r:*") as tar:
                # Try to list contents
                members = tar.getmembers()
                return len(members) > 0
        except Exception as e:
            logger.error(f"Backup verification failed: {e}")
            return False


# Task Scheduler (simple implementation)
class TaskScheduler:
    """
    Simple task scheduler for periodic jobs
    
    Features:
    - Scheduled tasks
    - Interval-based scheduling
    - One-time and recurring tasks
    """
    
    def __init__(self):
        self.tasks: Dict[str, Dict] = {}
    
    def schedule_interval(self, task_id: str, task_fn, interval_seconds: int):
        """Schedule a task to run at intervals"""
        self.tasks[task_id] = {
            "fn": task_fn,
            "interval": interval_seconds,
            "last_run": None,
            "next_run": datetime.utcnow()
        }
    
    def schedule_daily(self, task_id: str, task_fn, hour: int = 0, minute: int = 0):
        """Schedule a task to run daily"""
        self.tasks[task_id] = {
            "fn": task_fn,
            "interval": 86400,  # 24 hours
            "hour": hour,
            "minute": minute,
            "last_run": None,
            "next_run": datetime.utcnow().replace(hour=hour, minute=minute)
        }
    
    def run_pending(self):
        """Run tasks that are due"""
        now = datetime.utcnow()
        
        for task_id, task in list(self.tasks.items()):
            if now >= task["next_run"]:
                try:
                    task["fn"]()
                    task["last_run"] = now
                    task["next_run"] = now + timedelta(seconds=task["interval"])
                    logger.info(f"Task {task_id} completed")
                except Exception as e:
                    logger.error(f"Task {task_id} failed: {e}")
    
    def get_next_run(self, task_id: str) -> Optional[datetime]:
        """Get next run time for task"""
        task = self.tasks.get(task_id)
        return task["next_run"] if task else None


# Singleton instances
_cache_manager: Optional[CacheManager] = None
_message_queue: Optional[MessageQueue] = None
_backup_manager: Optional[BackupManager] = None


def get_cache_manager() -> CacheManager:
    """Get cache manager singleton"""
    global _cache_manager
    if _cache_manager is None:
        _cache_manager = CacheManager()
    return _cache_manager


def get_message_queue() -> MessageQueue:
    """Get message queue singleton"""
    global _message_queue
    if _message_queue is None:
        _message_queue = MessageQueue()
    return _message_queue


def get_backup_manager() -> BackupManager:
    """Get backup manager singleton"""
    global _backup_manager
    if _backup_manager is None:
        _backup_manager = BackupManager()
    return _backup_manager
