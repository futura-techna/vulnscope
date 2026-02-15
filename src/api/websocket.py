"""
VulnScope - WebSocket Support
Real-time scan updates via WebSocket
"""

import asyncio
import json
from typing import Dict, Any, Set
from dataclasses import dataclass
from datetime import datetime
from enum import Enum


class MessageType(str, Enum):
    SCAN_STARTED = "scan_started"
    SCAN_PROGRESS = "scan_progress"
    SCAN_COMPLETED = "scan_completed"
    SCAN_ERROR = "scan_error"
    FINDING_DISCOVERED = "finding_discovered"
    ENDPOINT_DISCOVERED = "endpoint_discovered"


@dataclass
class WSMessage:
    """WebSocket message"""
    type: str
    data: Dict[str, Any]
    timestamp: datetime


class WebSocketManager:
    """
    WebSocket manager for real-time updates
    
    Features:
    - Broadcast scan progress
    - Real-time finding notifications
    - Connection management
    """
    
    def __init__(self):
        self.active_connections: Set[Any] = set()
    
    async def connect(self, websocket):
        """Accept new WebSocket connection"""
        await websocket.accept()
        self.active_connections.add(websocket)
    
    def disconnect(self, websocket):
        """Remove WebSocket connection"""
        self.active_connections.discard(websocket)
    
    async def broadcast(self, message: WSMessage):
        """Broadcast message to all connections"""
        message_json = json.dumps({
            'type': message.type,
            'data': message.data,
            'timestamp': message.timestamp.isoformat(),
        })
        
        # Send to all connections
        disconnected = set()
        
        for connection in self.active_connections:
            try:
                await connection.send_text(message_json)
            except Exception:
                disconnected.add(connection)
        
        # Remove disconnected
        for conn in disconnected:
            self.active_connections.discard(conn)
    
    async def send_scan_started(self, scan_id: str, target_name: str):
        """Send scan started message"""
        await self.broadcast(WSMessage(
            type=MessageType.SCAN_STARTED.value,
            data={'scan_id': scan_id, 'target': target_name},
            timestamp=datetime.utcnow()
        ))
    
    async def send_scan_progress(self, scan_id: str, progress: int, 
                               endpoints: int, findings: int):
        """Send scan progress message"""
        await self.broadcast(WSMessage(
            type=MessageType.SCAN_PROGRESS.value,
            data={
                'scan_id': scan_id,
                'progress': progress,
                'endpoints_discovered': endpoints,
                'findings_count': findings,
            },
            timestamp=datetime.utcnow()
        ))
    
    async def send_scan_completed(self, scan_id: str, total_findings: int,
                                duration: float):
        """Send scan completed message"""
        await self.broadcast(WSMessage(
            type=MessageType.SCAN_COMPLETED.value,
            data={
                'scan_id': scan_id,
                'total_findings': total_findings,
                'duration_seconds': duration,
            },
            timestamp=datetime.utcnow()
        ))
    
    async def send_finding(self, scan_id: str, finding: Dict[str, Any]):
        """Send new finding discovered message"""
        await self.broadcast(WSMessage(
            type=MessageType.FINDING_DISCOVERED.value,
            data={'scan_id': scan_id, 'finding': finding},
            timestamp=datetime.utcnow()
        ))
    
    async def send_endpoint(self, scan_id: str, endpoint: Dict[str, Any]):
        """Send new endpoint discovered message"""
        await self.broadcast(WSMessage(
            type=MessageType.ENDPOINT_DISCOVERED.value,
            data={'scan_id': scan_id, 'endpoint': endpoint},
            timestamp=datetime.utcnow()
        ))
    
    async def send_error(self, scan_id: str, error: str):
        """Send error message"""
        await self.broadcast(WSMessage(
            type=MessageType.SCAN_ERROR.value,
            data={'scan_id': scan_id, 'error': error},
            timestamp=datetime.utcnow()
        ))


# Global WebSocket manager
ws_manager = WebSocketManager()


# Example FastAPI WebSocket endpoint
"""
from fastapi import WebSocket, WebSocketDisconnect

@router.websocket("/ws/{client_id}")
async def websocket_endpoint(websocket: WebSocket, client_id: str):
    await ws_manager.connect(websocket)
    try:
        while True:
            # Keep connection alive
            data = await websocket.receive_text()
            # Handle client messages if needed
    except WebSocketDisconnect:
        ws_manager.disconnect(websocket)
"""
