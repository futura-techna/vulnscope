"""
VulnScope - REST API Module
FastAPI REST API for VulnScope platform
"""

from .main import app
from .routes import router
from .schemas import *

__all__ = [
    "app",
    "router",
]
