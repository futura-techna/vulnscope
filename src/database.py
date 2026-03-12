"""
VulnScope - Database Module
SQLAlchemy database configuration and session management
"""

import os
from datetime import datetime
from typing import AsyncGenerator, Optional
from sqlalchemy import create_engine, Column, String, DateTime, Integer, Text, Boolean, ForeignKey, Enum as SQLEnum
from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase, sessionmaker, relationship
from sqlalchemy.types import TypeDecorator, JSON
from uuid import uuid4
import enum

from .config.settings import get_settings


class Base(DeclarativeBase):
    """Base class for all database models"""
    pass


class GUID(TypeDecorator):
    """Platform-independent GUID type."""
    impl = String
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(String(36))

    def process_bind_param(self, value, dialect):
        if value is None:
            return value
        return str(value)


class JsonType(TypeDecorator):
    """JSON type for SQLite compatibility"""
    impl = Text
    cache_ok = True

    def load_dialect_impl(self, dialect):
        return dialect.type_descriptor(Text())

    def process_bind_param(self, value, dialect):
        if value is None:
            return None
        import json
        return json.dumps(value)

    def process_result_value(self, value, dialect):
        if value is None:
            return None
        import json
        return json.loads(value)


# ============ Database Models ============

class TargetModel(Base):
    """Target database model"""
    __tablename__ = "targets"

    id = Column(GUID, primary_key=True, default=lambda: str(uuid4()))
    name = Column(String(255), nullable=False)
    url = Column(String(2048), nullable=False)
    description = Column(Text, nullable=True)
    tags = Column(JsonType, default=list)
    auth_type = Column(String(50), nullable=True)
    auth_config = Column(JsonType, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    scans = relationship("ScanModel", back_populates="target", cascade="all, delete-orphan")


class ScanModel(Base):
    """Scan database model"""
    __tablename__ = "scans"

    id = Column(GUID, primary_key=True, default=lambda: str(uuid4()))
    target_id = Column(GUID, ForeignKey("targets.id"), nullable=False)
    name = Column(String(255), nullable=False)
    description = Column(Text, nullable=True)
    scan_type = Column(String(50), default="full")
    status = Column(String(50), default="pending")
    progress = Column(Integer, default=0)
    error_message = Column(Text, nullable=True)
    
    # Scan options
    enable_crawler = Column(Boolean, default=True)
    enable_openapi_import = Column(Boolean, default=True)
    enable_graphql_import = Column(Boolean, default=True)
    enable_dast = Column(Boolean, default=True)
    enable_fuzzer = Column(Boolean, default=True)
    
    # Results
    endpoints_discovered = Column(Integer, default=0)
    findings_count = Column(Integer, default=0)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    started_at = Column(DateTime, nullable=True)
    completed_at = Column(DateTime, nullable=True)

    # Relationships
    target = relationship("TargetModel", back_populates="scans")
    findings = relationship("FindingModel", back_populates="scan", cascade="all, delete-orphan")


class FindingModel(Base):
    """Finding database model"""
    __tablename__ = "findings"

    id = Column(GUID, primary_key=True, default=lambda: str(uuid4()))
    scan_id = Column(GUID, ForeignKey("scans.id"), nullable=False)
    target_id = Column(GUID, ForeignKey("targets.id"), nullable=False)
    
    # Vulnerability details
    title = Column(String(500), nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String(20), default="Medium")
    vuln_type = Column(String(100), default="Unknown")
    
    # Technical details
    url = Column(String(2048), nullable=True)
    method = Column(String(10), nullable=True)
    parameter = Column(String(255), nullable=True)
    payload = Column(Text, nullable=True)
    evidence = Column(Text, nullable=True)
    
    # Classification
    cwe_id = Column(String(20), nullable=True)
    owasp_category = Column(String(50), nullable=True)
    cvss_score = Column(Integer, nullable=True)
    
    # Status
    status = Column(String(50), default="Open")
    false_positive = Column(Boolean, default=False)
    verified = Column(Boolean, default=False)
    
    # Timestamps
    created_at = Column(DateTime, default=datetime.utcnow)
    verified_at = Column(DateTime, nullable=True)
    remediated_at = Column(DateTime, nullable=True)

    # Relationships
    scan = relationship("ScanModel", back_populates="findings")


class ReportModel(Base):
    """Report database model"""
    __tablename__ = "reports"

    id = Column(GUID, primary_key=True, default=lambda: str(uuid4()))
    scan_id = Column(GUID, ForeignKey("scans.id"), nullable=False)
    name = Column(String(255), nullable=False)
    format = Column(String(20), default="json")
    size = Column(String(50), nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)


class SettingsModel(Base):
    """Application settings database model"""
    __tablename__ = "settings"

    key = Column(String(100), primary_key=True)
    value = Column(JsonType, nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


class ComplianceDataModel(Base):
    """Persistent compliance data cache"""
    __tablename__ = "compliance_data"

    id = Column(Integer, primary_key=True, autoincrement=True)
    data_type = Column(String(50), nullable=False)  # 'standards' or 'categories'
    data = Column(JsonType, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)


# ============ Database Engine & Session ============

_engine = None
_async_session_maker = None


def get_database_url() -> str:
    """Get the database URL, converting to async format if needed"""
    settings = get_settings()
    url = os.environ.get("DATABASE_URL", settings.database.url)
    
    # Render provides DATABASE_URL as postgres://, need to convert
    if url.startswith("postgres://"):
        url = url.replace("postgres://", "postgresql://", 1)
    
    # For async engines, need async driver
    if url.startswith("postgresql://"):
        url = url.replace("postgresql://", "postgresql+asyncpg://", 1)
    elif url.startswith("sqlite://"):
        url = url.replace("sqlite://", "sqlite+aiosqlite://", 1)
    
    return url


def get_engine():
    """Get or create the database engine"""
    global _engine
    if _engine is None:
        url = get_database_url()
        _engine = create_async_engine(
            url,
            echo=get_settings().database.echo,
            pool_pre_ping=True,
        )
    return _engine


async def get_session() -> AsyncGenerator[AsyncSession, None]:
    """Get database session"""
    global _async_session_maker
    
    if _async_session_maker is None:
        engine = get_engine()
        _async_session_maker = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    
    async with _async_session_maker() as session:
        try:
            yield session
        finally:
            await session.close()


async def init_db():
    """Initialize database tables"""
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)


async def get_or_create_session():
    """Get a session directly (not as generator)"""
    global _async_session_maker
    
    if _async_session_maker is None:
        engine = get_engine()
        _async_session_maker = async_sessionmaker(
            engine,
            class_=AsyncSession,
            expire_on_commit=False,
        )
    
    return _async_session_maker()