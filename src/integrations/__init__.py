"""
VulnScope - Integrations Module
CI/CD, ITSM, and SIEM integrations
"""

from .cicd import (
    GitHubIntegration,
    GitLabIntegration,
    JenkinsIntegration,
    CIAdapter,
)
from .itsm import (
    ServiceNowIntegration,
    JiraIntegration,
    ITSMAdapter,
)
from .siem import (
    SplunkIntegration,
    ELKIntegration,
    SIEMAdapter,
)

__all__ = [
    "GitHubIntegration",
    "GitLabIntegration", 
    "JenkinsIntegration",
    "CIAdapter",
    "ServiceNowIntegration",
    "JiraIntegration",
    "ITSMAdapter",
    "SplunkIntegration",
    "ELKIntegration",
    "SIEMAdapter",
]
