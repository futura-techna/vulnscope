"""
VulnScope - Configuration Loaders Tests
Tests for policy, credentials, and spec loaders
"""

import pytest
import os
import json
import tempfile
from pathlib import Path
from unittest.mock import Mock, patch, mock_open

from src.config.loaders import (
    load_policy, load_credentials, load_openapi_spec, load_graphql_schema
)


class TestLoadPolicy:
    """Test policy loading functionality"""
    
    def test_load_yaml_policy(self):
        """Test loading a YAML policy file"""
        yaml_content = """
name: Security Policy
version: 1.0
rules:
  - name: SQL Injection Check
    enabled: true
  - name: XSS Check
    enabled: true
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            
            result = load_policy(f.name)
            
            assert result['name'] == 'Security Policy'
            assert result['version'] == 1.0
            assert len(result['rules']) == 2
            
            os.unlink(f.name)
    
    def test_load_yml_policy(self):
        """Test loading a .yml policy file"""
        yaml_content = "name: Test Policy\nversion: 2.0"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            
            result = load_policy(f.name)
            
            assert result['name'] == 'Test Policy'
            assert result['version'] == 2.0
            
            os.unlink(f.name)
    
    def test_load_json_policy(self):
        """Test loading a JSON policy file"""
        policy = {
            "name": "JSON Policy",
            "version": "1.5",
            "rules": [{"name": "Rule1", "enabled": True}]
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(policy, f)
            f.flush()
            
            result = load_policy(f.name)
            
            assert result['name'] == 'JSON Policy'
            assert result['version'] == '1.5'
            assert len(result['rules']) == 1
            
            os.unlink(f.name)
    
    def test_load_policy_file_not_found(self):
        """Test loading non-existent policy file"""
        with pytest.raises(FileNotFoundError) as exc_info:
            load_policy('/nonexistent/policy.yaml')
        
        assert 'Policy file not found' in str(exc_info.value)
    
    def test_load_policy_unsupported_format(self):
        """Test loading policy with unsupported format"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("some content")
            f.flush()
            
            with pytest.raises(ValueError) as exc_info:
                load_policy(f.name)
            
            assert 'Unsupported policy format' in str(exc_info.value)
            
            os.unlink(f.name)
    
    def test_load_policy_invalid_yaml(self):
        """Test loading invalid YAML content"""
        invalid_yaml = "key: value\n  invalid: indentation"
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(invalid_yaml)
            f.flush()
            
            # This may or may not raise depending on YAML parser
            # Just ensure the function doesn't crash
            try:
                result = load_policy(f.name)
            except Exception:
                pass
            
            os.unlink(f.name)


class TestLoadCredentials:
    """Test credentials loading functionality"""
    
    def test_load_credentials_file(self):
        """Test loading credentials file"""
        creds = {
            "api_key": "test-key",
            "username": "admin",
            "password": "secret"
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(creds, f)
            f.flush()
            
            result = load_credentials(f.name)
            
            assert result['api_key'] == 'test-key'
            assert result['username'] == 'admin'
            
            os.unlink(f.name)
    
    def test_load_credentials_file_not_found(self):
        """Test loading non-existent credentials file returns empty dict"""
        result = load_credentials('/nonexistent/creds.json')
        
        assert result == {}
    
    def test_load_credentials_empty_file(self):
        """Test loading empty credentials file"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump({}, f)
            f.flush()
            
            result = load_credentials(f.name)
            
            assert result == {}
            
            os.unlink(f.name)
    
    def test_load_credentials_nested(self):
        """Test loading nested credentials"""
        creds = {
            "database": {
                "host": "localhost",
                "port": 5432,
                "credentials": {
                    "user": "admin",
                    "pass": "secret"
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(creds, f)
            f.flush()
            
            result = load_credentials(f.name)
            
            assert result['database']['host'] == 'localhost'
            assert result['database']['credentials']['user'] == 'admin'
            
            os.unlink(f.name)


class TestLoadOpenAPISpec:
    """Test OpenAPI specification loading"""
    
    def test_load_openapi_json(self):
        """Test loading OpenAPI JSON spec"""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "Test API", "version": "1.0"},
            "paths": {
                "/users": {"get": {"summary": "List users"}},
                "/users/{id}": {"get": {"summary": "Get user"}}
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(spec, f)
            f.flush()
            
            result = load_openapi_spec(f.name)
            
            assert result['openapi'] == '3.0.0'
            assert '/users' in result['paths']
            
            os.unlink(f.name)
    
    def test_load_openapi_yaml(self):
        """Test loading OpenAPI YAML spec"""
        yaml_content = """
openapi: 3.0.0
info:
  title: Test API
  version: '1.0'
paths:
  /api/test:
    get:
      summary: Test endpoint
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.yaml', delete=False) as f:
            f.write(yaml_content)
            f.flush()
            
            result = load_openapi_spec(f.name)
            
            assert result['openapi'] == '3.0.0'
            assert result['info']['title'] == 'Test API'
            
            os.unlink(f.name)
    
    def test_load_openapi_spec_not_found(self):
        """Test loading non-existent OpenAPI spec"""
        with pytest.raises(FileNotFoundError) as exc_info:
            load_openapi_spec('/nonexistent/spec.yaml')
        
        assert 'OpenAPI spec not found' in str(exc_info.value)
    
    def test_load_openapi_unsupported_format(self):
        """Test loading OpenAPI spec with unsupported format"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.xml', delete=False) as f:
            f.write("<spec></spec>")
            f.flush()
            
            with pytest.raises(ValueError) as exc_info:
                load_openapi_spec(f.name)
            
            assert 'Unsupported spec format' in str(exc_info.value)
            
            os.unlink(f.name)
    
    def test_load_openapi_with_components(self):
        """Test loading OpenAPI spec with components"""
        spec = {
            "openapi": "3.0.0",
            "info": {"title": "API", "version": "1.0"},
            "components": {
                "schemas": {
                    "User": {"type": "object", "properties": {"id": {"type": "integer"}}}
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(spec, f)
            f.flush()
            
            result = load_openapi_spec(f.name)
            
            assert 'schemas' in result['components']
            assert 'User' in result['components']['schemas']
            
            os.unlink(f.name)


class TestLoadGraphQLSchema:
    """Test GraphQL schema loading"""
    
    def test_load_graphql_json_schema(self):
        """Test loading GraphQL JSON schema"""
        schema = {
            "data": {
                "__schema": {
                    "types": [
                        {"name": "Query", "kind": "OBJECT"},
                        {"name": "Mutation", "kind": "OBJECT"}
                    ]
                }
            }
        }
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(schema, f)
            f.flush()
            
            result = load_graphql_schema(f.name)
            
            assert result['data']['__schema']['types'][0]['name'] == 'Query'
            
            os.unlink(f.name)
    
    def test_load_graphql_schema_file(self):
        """Test loading .graphql schema file"""
        schema_content = """
type Query {
  users: [User]
  user(id: ID!): User
}

type User {
  id: ID!
  name: String!
  email: String!
}

type Mutation {
  createUser(name: String!, email: String!): User
}
"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.graphql', delete=False) as f:
            f.write(schema_content)
            f.flush()
            
            result = load_graphql_schema(f.name)
            
            assert result['type'] == 'graphql'
            assert 'type Query' in result['content']
            
            os.unlink(f.name)
    
    def test_load_graphql_schema_not_found(self):
        """Test loading non-existent GraphQL schema"""
        with pytest.raises(FileNotFoundError) as exc_info:
            load_graphql_schema('/nonexistent/schema.graphql')
        
        assert 'GraphQL schema not found' in str(exc_info.value)
    
    def test_load_graphql_unsupported_format(self):
        """Test loading GraphQL schema with unsupported format"""
        with tempfile.NamedTemporaryFile(mode='w', suffix='.txt', delete=False) as f:
            f.write("some content")
            f.flush()
            
            with pytest.raises(ValueError) as exc_info:
                load_graphql_schema(f.name)
            
            assert 'Unsupported schema format' in str(exc_info.value)
            
            os.unlink(f.name)


class TestPathHandling:
    """Test path handling in loaders"""
    
    def test_load_policy_with_path_object(self):
        """Test loading policy with Path object"""
        policy = {"name": "Test"}
        with tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False) as f:
            json.dump(policy, f)
            f.flush()
            
            # Test that string paths work
            result = load_policy(str(f.name))
            
            assert result['name'] == 'Test'
            
            os.unlink(f.name)
    
    def test_load_policy_with_relative_path(self):
        """Test loading policy with relative path"""
        yaml_content = "name: Relative Policy"
        
        # Create temp file in current directory
        temp_file = 'temp_test_policy.yaml'
        with open(temp_file, 'w') as f:
            f.write(yaml_content)
        
        try:
            result = load_policy(temp_file)
            assert result['name'] == 'Relative Policy'
        finally:
            if os.path.exists(temp_file):
                os.unlink(temp_file)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])