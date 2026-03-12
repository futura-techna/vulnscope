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
    WebSocketManager, WSMessage, MessageType,
    ws_manager
)


class TestWebSocketManager:
    """Test WebSocket connection manager"""
    
    def test_init(self):
        manager = WebSocketManager()
        
        assert manager.active_connections == set()
    
    @pytest.mark.asyncio
    async def test_connect(self):
        manager = WebSocketManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        
        assert mock_websocket in manager.active_connections
        mock_websocket.accept.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_disconnect(self):
        manager = WebSocketManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        manager.disconnect(mock_websocket)
        
        assert mock_websocket not in manager.active_connections
    
    @pytest.mark.asyncio
    async def test_broadcast(self):
        manager = WebSocketManager()
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        
        await manager.connect(mock_ws1)
        await manager.connect(mock_ws2)
        
        message = WSMessage(
            type=MessageType.SCAN_PROGRESS.value,
            data={"progress": 50},
            timestamp=datetime.utcnow()
        )
        
        await manager.broadcast(message)
        
        mock_ws1.send_text.assert_called_once()
        mock_ws2.send_text.assert_called_once()
    
    @pytest.mark.asyncio
    async def test_broadcast_removes_disconnected(self):
        manager = WebSocketManager()
        mock_ws1 = AsyncMock()
        mock_ws2 = AsyncMock()
        
        # Make ws2 throw an exception when sending
        mock_ws2.send_text.side_effect = Exception("Connection lost")
        
        await manager.connect(mock_ws1)
        await manager.connect(mock_ws2)
        
        message = WSMessage(
            type=MessageType.SCAN_PROGRESS.value,
            data={"progress": 50},
            timestamp=datetime.utcnow()
        )
        
        await manager.broadcast(message)
        
        # ws2 should be removed due to error
        assert mock_ws2 not in manager.active_connections
        assert mock_ws1 in manager.active_connections


class TestWSMessage:
    """Test WSMessage dataclass"""
    
    def test_create_message(self):
        msg = WSMessage(
            type=MessageType.SCAN_STARTED.value,
            data={"scan_id": "123"},
            timestamp=datetime.utcnow()
        )
        
        assert msg.type == MessageType.SCAN_STARTED.value
        assert msg.data["scan_id"] == "123"
        assert isinstance(msg.timestamp, datetime)


class TestMessageType:
    """Test message type enum"""
    
    def test_message_types(self):
        assert MessageType.SCAN_STARTED == "scan_started"
        assert MessageType.SCAN_PROGRESS == "scan_progress"
        assert MessageType.SCAN_COMPLETED == "scan_completed"
        assert MessageType.SCAN_ERROR == "scan_error"
        assert MessageType.FINDING_DISCOVERED == "finding_discovered"
        assert MessageType.ENDPOINT_DISCOVERED == "endpoint_discovered"


class TestWebSocketManagerMethods:
    """Test WebSocket manager message methods"""
    
    @pytest.mark.asyncio
    async def test_send_scan_started(self):
        manager = WebSocketManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        await manager.send_scan_started("scan-123", "Test Target")
        
        mock_websocket.send_text.assert_called_once()
        call_args = mock_websocket.send_text.call_args[0][0]
        data = json.loads(call_args)
        
        assert data["type"] == "scan_started"
        assert data["data"]["scan_id"] == "scan-123"
        assert data["data"]["target"] == "Test Target"
    
    @pytest.mark.asyncio
    async def test_send_scan_progress(self):
        manager = WebSocketManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        await manager.send_scan_progress("scan-123", 50, 10, 2)
        
        mock_websocket.send_text.assert_called_once()
        call_args = mock_websocket.send_text.call_args[0][0]
        data = json.loads(call_args)
        
        assert data["type"] == "scan_progress"
        assert data["data"]["progress"] == 50
        assert data["data"]["endpoints_discovered"] == 10
        assert data["data"]["findings_count"] == 2
    
    @pytest.mark.asyncio
    async def test_send_scan_completed(self):
        manager = WebSocketManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        await manager.send_scan_completed("scan-123", 5, 30.5)
        
        mock_websocket.send_text.assert_called_once()
        call_args = mock_websocket.send_text.call_args[0][0]
        data = json.loads(call_args)
        
        assert data["type"] == "scan_completed"
        assert data["data"]["total_findings"] == 5
        assert data["data"]["duration_seconds"] == 30.5
    
    @pytest.mark.asyncio
    async def test_send_finding(self):
        manager = WebSocketManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        finding = {"id": "finding-1", "severity": "High", "title": "XSS"}
        await manager.send_finding("scan-123", finding)
        
        mock_websocket.send_text.assert_called_once()
        call_args = mock_websocket.send_text.call_args[0][0]
        data = json.loads(call_args)
        
        assert data["type"] == "finding_discovered"
        assert data["data"]["scan_id"] == "scan-123"
        assert data["data"]["finding"]["id"] == "finding-1"
    
    @pytest.mark.asyncio
    async def test_send_endpoint(self):
        manager = WebSocketManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        endpoint = {"url": "http://example.com/api", "method": "GET"}
        await manager.send_endpoint("scan-123", endpoint)
        
        mock_websocket.send_text.assert_called_once()
        call_args = mock_websocket.send_text.call_args[0][0]
        data = json.loads(call_args)
        
        assert data["type"] == "endpoint_discovered"
        assert data["data"]["scan_id"] == "scan-123"
        assert data["data"]["endpoint"]["url"] == "http://example.com/api"
    
    @pytest.mark.asyncio
    async def test_send_error(self):
        manager = WebSocketManager()
        mock_websocket = AsyncMock()
        
        await manager.connect(mock_websocket)
        await manager.send_error("scan-123", "Connection timeout")
        
        mock_websocket.send_text.assert_called_once()
        call_args = mock_websocket.send_text.call_args[0][0]
        data = json.loads(call_args)
        
        assert data["type"] == "scan_error"
        assert data["data"]["scan_id"] == "scan-123"
        assert data["data"]["error"] == "Connection timeout"


class TestGlobalWSManager:
    """Test global WebSocket manager instance"""
    
    def test_global_manager_exists(self):
        assert ws_manager is not None
        assert isinstance(ws_manager, WebSocketManager)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])