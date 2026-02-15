"""
VulnScope - Dynamic Application Security Testing Platform
Copyright (c) 2026 VulnScope Security

A comprehensive security testing platform for discovering and testing
API and web application vulnerabilities.
"""

__version__ = "1.0.0"
__author__ = "VulnScope Security"

from .core import models, exceptions
from .config import settings
from .discovery import crawler, openapi_importer, graphql_importer, auth_flows
from .scanner import scanner, detectors, payloads
from .fuzzer import fuzzer, rate_limiter
from .evidence import vault, policy, exporters, compliance
from .integrations import cicd, itsm, siem

__all__ = [
    # Core
    "models",
    "exceptions",
    # Config
    "settings",
    # Discovery
    "crawler",
    "openapi_importer",
    "graphql_importer",
    "auth_flows",
    # Scanner
    "scanner",
    "detectors",
    "payloads",
    # Fuzzer
    "fuzzer",
    "rate_limiter",
    # Evidence
    "vault",
    "policy",
    "exporters",
    "compliance",
    # Integrations
    "cicd",
    "itsm",
    "siem",
]
