"""
VulnScope - WebSocket API Tests
Tests for WebSocket endpoints and real-time communication
"""

import pytest
import asyncio
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
import json

from src.api.websocket import (
    ConnectionManager, ScanProgressHandler,
    WebSocketMessage, MessageType
)


class TestConnectionManager:
    """Test WebSocket connection manager"""
    
    def test_init(self):
        manager = ConnectionManager()
        
        assert manager.active_connections == []
        assert manager.scan_subscriptions == {}
    
    @pytest.mark.asyncio
    async def test_connect(self):
        manager = ConnectionManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        
        assert mock_websocket in manager.active_connections
        mock_websocket.accept.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect(self):
        manager = ConnectionManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        manager.disconnect(mock_websocket)
        
        assert mock_websocket not in manager.active_connections
    
    @pytest.mark.asyncio
    async def test_send_personal_message(self):
        manager = ConnectionManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        await manager.send_personal_message({"type": "test"}, mock_websocket)
        
        mock_websocket.send_json.assert_called_once_with({"type": "test"})
    
    @pytest.mark.asyncio
    async def test_broadcast(self):
        manager = ConnectionManager()
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        
        await manager.connect(mock_ws1)
        await manager.connect(mock_ws2)
        
        await manager.broadcast({"type": "broadcast"})
        
        mock_ws1.send_json.assert_called_once_with({"type": "broadcast"})
        mock_ws2.send_json.assert_called_once_with({"type": "broadcast"})
    
    @pytest.mark.asyncio
    async def test_subscribe_to_scan(self):
        manager = ConnectionManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        manager.subscribe_to_scan(mock_websocket, "scan-123")
        
        assert "scan-123" in manager.scan_subscriptions
        assert mock_websocket in manager.scan_subscriptions["scan-123"]
    
    @pytest.mark.asyncio
    async def test_unsubscribe_from_scan(self):
        manager = ConnectionManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        manager.subscribe_to_scan(mock_websocket, "scan-123")
        manager.unsubscribe_from_scan(mock_websocket, "scan-123")
        
        assert mock_websocket not in manager.scan_subscriptions.get("scan-123", [])
    
    @pytest.mark.asyncio
    async def test_broadcast_to_scan_subscribers(self):
        manager = ConnectionManager()
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        
        await manager.connect(mock_ws1)
        await manager.connect(mock_ws2)
        
        manager.subscribe_to_scan(mock_ws1, "scan-123")
        manager.subscribe_to_scan(mock_ws2, "scan-456")
        
        await manager.broadcast_to_scan("scan-123", {"type": "progress"})
        
        mock_ws1.send_json.assert_called_once_with({"type": "progress"})
        mock_ws2.send_json.assert_not_called()


class TestScanProgressHandler:
    """Test scan progress handler"""
    
    def test_init(self):
        handler = ScanProgressHandler()
        
        assert handler.scans == {}
    
    def test_start_scan(self):
        handler = ScanProgressHandler()
        
        handler.start_scan("scan-123", "target-1")
        
        assert "scan-123" in handler.scans
        assert handler.scans["scan-123"]["target_id"] == "target-1"
        assert handler.scans["scan-123"]["status"] == "running"
        assert handler.scans["scan-123"]["progress"] == 0
    
    def test_update_progress(self):
        handler = ScanProgressHandler()
        handler.start_scan("scan-123", "target-1")
        
        handler.update_progress("scan-123", 50, "Scanning endpoints")
        
        assert handler.scans["scan-123"]["progress"] == 50
        assert handler.scans["scan-123"]["message"] == "Scanning endpoints"
    
    def test_complete_scan(self):
        handler = ScanProgressHandler()
        handler.start_scan("scan-123", "target-1")
        
        handler.complete_scan("scan-123", findings_count=10)
        
        assert handler.scans["scan-123"]["status"] == "completed"
        assert handler.scans["scan-123"]["progress"] == 100
        assert handler.scans["scan-123"]["findings_count"] == 10
    
    def test_fail_scan(self):
        handler = ScanProgressHandler()
        handler.start_scan("scan-123", "target-1")
        
        handler.fail_scan("scan-123", "Connection timeout")
        
        assert handler.scans["scan-123"]["status"] == "failed"
        assert handler.scans["scan-123"]["error"] == "Connection timeout"
    
    def test_get_scan_status(self):
        handler = ScanProgressHandler()
        handler.start_scan("scan-123", "target-1")
        
        status = handler.get_scan_status("scan-123")
        
        assert status["scan_id"] == "scan-123"
        assert status["status"] == "running"
    
    def test_get_nonexistent_scan_status(self):
        handler = ScanProgressHandler()
        
        status = handler.get_scan_status("nonexistent")
        
        assert status is None


class TestWebSocketMessage:
    """Test WebSocket message models"""
    
    def test_create_progress_message(self):
        msg = WebSocketMessage(
            type=MessageType.PROGRESS,
            data={"progress": 50, "message": "Scanning"}
        )
        
        assert msg.type == MessageType.PROGRESS
        assert msg.data["progress"] == 50
    
    def test_create_finding_message(self):
        msg = WebSocketMessage(
            type=MessageType.FINDING,
            data={"id": "finding-1", "severity": "High"}
        )
        
        assert msg.type == MessageType.FINDING
        assert msg.data["id"] == "finding-1"
    
    def test_create_complete_message(self):
        msg = WebSocketMessage(
            type=MessageType.COMPLETE,
            data={"findings_count": 5}
        )
        
        assert msg.type == MessageType.COMPLETE
        assert msg.data["findings_count"] == 5
    
    def test_create_error_message(self):
        msg = WebSocketMessage(
            type=MessageType.ERROR,
            data={"error": "Something went wrong"}
        )
        
        assert msg.type == MessageType.ERROR
        assert msg.data["error"] == "Something went wrong"
    
    def test_to_json(self):
        msg = WebSocketMessage(
            type=MessageType.PROGRESS,
            data={"progress": 50}
        )
        
        json_str = msg.to_json()
        
        assert '"type": "progress"' in json_str
        assert '"progress": 50' in json_str


class TestMessageType:
    """Test message type enum"""
    
    def test_message_types(self):
        assert MessageType.PROGRESS == "progress"
        assert MessageType.FINDING == "finding"
        assert MessageType.COMPLETE == "complete"
        assert MessageType.ERROR == "error"
        assert MessageType.CANCELLED == "cancelled"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])