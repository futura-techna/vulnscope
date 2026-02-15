"""
VulnScope - Configuration Loaders
Loaders for policies, credentials, and external configurations
"""

import os
import yaml
import json
from typing import Dict, Any, Optional
from pathlib import Path


def load_policy(policy_path: str) -> Dict[str, Any]:
    """
    Load security policy from YAML file (Policy-as-Code)
    
    Args:
        policy_path: Path to the policy YAML file
        
    Returns:
        Dictionary containing policy rules
        
    Raises:
        FileNotFoundError: If policy file doesn't exist
        yaml.YAMLError: If policy file is invalid YAML
    """
    path = Path(policy_path)
    
    if not path.exists():
        raise FileNotFoundError(f"Policy file not found: {policy_path}")
    
    with open(path, 'r') as f:
        if path.suffix in ['.yaml', '.yml']:
            policy = yaml.safe_load(f)
        elif path.suffix == '.json':
            policy = json.load(f)
        else:
            raise ValueError(f"Unsupported policy format: {path.suffix}")
    
    return policy


def load_credentials(cred_path: str) -> Dict[str, Any]:
    """
    Load credentials from encrypted JSON file
    
    Args:
        cred_path: Path to the credentials file
        
    Returns:
        Dictionary containing credentials
        
    Note:
        In production, use proper encryption (e.g., HashiCorp Vault, AWS Secrets Manager)
    """
    path = Path(cred_path)
    
    if not path.exists():
        return {}
    
    with open(path, 'r') as f:
        creds = json.load(f)
    
    return creds


def load_openapi_spec(spec_path: str) -> Dict[str, Any]:
    """
    Load OpenAPI specification for API discovery
    
    Args:
        spec_path: Path to OpenAPI JSON/YAML file
        
    Returns:
        Dictionary containing OpenAPI specification
    """
    path = Path(spec_path)
    
    if not path.exists():
        raise FileNotFoundError(f"OpenAPI spec not found: {spec_path}")
    
    with open(path, 'r') as f:
        if path.suffix in ['.yaml', '.yml']:
            spec = yaml.safe_load(f)
        elif path.suffix == '.json':
            spec = json.load(f)
        else:
            raise ValueError(f"Unsupported spec format: {path.suffix}")
    
    return spec


def load_graphql_schema(schema_path: str) -> Dict[str, Any]:
    """
    Load GraphQL schema for API discovery
    
    Args:
        schema_path: Path to GraphQL schema file
        
    Returns:
        Dictionary containing GraphQL schema
    """
    path = Path(schema_path)
    
    if not path.exists():
        raise FileNotFoundError(f"GraphQL schema not found: {schema_path}")
    
    with open(path, 'r') as f:
        if path.suffix == '.json':
            schema = json.load(f)
        elif path.suffix == '.graphql':
            schema = {'type': 'graphql', 'content': f.read()}
        else:
            raise ValueError(f"Unsupported schema format: {path.suffix}")
    
    return schema
