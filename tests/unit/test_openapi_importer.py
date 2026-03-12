"""
VulnScope - OpenAPI Importer Unit Tests
Tests for OpenAPI specification parsing
"""

import pytest
from unittest.mock import Mock, patch
from uuid import uuid4

from src.discovery.openapi_importer import OpenAPIImporter, OpenAPIImportResult
from src.core.models import Target


class TestOpenAPIImporter:
    """Test OpenAPIImporter class"""
    
    def test_initialization(self):
        importer = OpenAPIImporter()
        assert importer is not None
        assert importer.spec is None
        assert importer.base_url == ""
    
    def test_import_from_dict_v3(self):
        """Test importing OpenAPI v3 spec from dict"""
        importer = OpenAPIImporter()
        
        spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List users",
                        "responses": {"200": {"description": "OK"}}
                    },
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        },
                        "responses": {"201": {"description": "Created"}}
                    }
                },
                "/users/{id}": {
                    "get": {
                        "summary": "Get user",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True}
                        ],
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }
        
        target = Target(id=uuid4(), name="Test", url="http://example.com")
        result = importer.import_from_dict(spec, target)
        
        assert isinstance(result, OpenAPIImportResult)
        assert len(result.endpoints) == 3
    
    def test_import_from_dict_v2(self):
        """Test importing Swagger v2 spec from dict"""
        importer = OpenAPIImporter()
        
        spec = {
            "swagger": "2.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "host": "api.example.com",
            "basePath": "/v1",
            "paths": {
                "/products": {
                    "get": {
                        "summary": "List products",
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }
        
        target = Target(id=uuid4(), name="Test", url="http://example.com")
        result = importer.import_from_dict(spec, target)
        
        assert isinstance(result, OpenAPIImportResult)
        assert len(result.endpoints) == 1
    
    def test_extract_security_schemes_v3(self):
        """Test extracting security schemes from OpenAPI v3"""
        importer = OpenAPIImporter()
        
        importer.spec = {
            "openapi": "3.0.0",
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer"
                    },
                    "apiKey": {
                        "type": "apiKey",
                        "name": "X-API-Key",
                        "in": "header"
                    }
                }
            }
        }
        
        security = importer._extract_security_schemes()
        
        assert len(security) == 2
        assert "bearerAuth" in security
        assert "apiKey" in security
    
    def test_extract_security_schemes_v2(self):
        """Test extracting security schemes from Swagger v2"""
        importer = OpenAPIImporter()
        
        importer.spec = {
            "swagger": "2.0",
            "securityDefinitions": {
                "basic": {
                    "type": "basic"
                }
            }
        }
        
        security = importer._extract_security_schemes()
        
        assert len(security) == 1
        assert "basic" in security
    
    def test_extract_schemas_v3(self):
        """Test extracting schemas from OpenAPI v3"""
        importer = OpenAPIImporter()
        
        importer.spec = {
            "openapi": "3.0.0",
            "components": {
                "schemas": {
                    "User": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "name": {"type": "string"}
                        }
                    }
                }
            }
        }
        
        schemas = importer._extract_schemas()
        
        assert "User" in schemas
    
    def test_extract_schemas_v2(self):
        """Test extracting schemas from Swagger v2"""
        importer = OpenAPIImporter()
        
        importer.spec = {
            "swagger": "2.0",
            "definitions": {
                "Product": {
                    "type": "object"
                }
            }
        }
        
        schemas = importer._extract_schemas()
        
        assert "Product" in schemas
    
    def test_get_base_url_from_servers(self):
        """Test getting base URL from servers (OpenAPI v3)"""
        importer = OpenAPIImporter()
        
        importer.spec = {
            "openapi": "3.0.0",
            "servers": [
                {"url": "https://api.example.com/v1"}
            ]
        }
        
        target = Target(id=uuid4(), name="Test", url="http://example.com")
        base_url = importer._get_base_url(target)
        
        assert base_url == "https://api.example.com/v1"
    
    def test_get_base_url_from_host(self):
        """Test getting base URL from host (Swagger v2)"""
        importer = OpenAPIImporter()
        
        importer.spec = {
            "swagger": "2.0",
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"]
        }
        
        target = Target(id=uuid4(), name="Test", url="http://example.com")
        base_url = importer._get_base_url(target)
        
        assert base_url == "https://api.example.com/v1"
    
    def test_get_base_url_fallback(self):
        """Test base URL fallback to target URL"""
        importer = OpenAPIImporter()
        
        importer.spec = {"openapi": "3.0.0"}  # No servers defined
        
        target = Target(id=uuid4(), name="Test", url="http://fallback.example.com")
        base_url = importer._get_base_url(target)
        
        # Falls back to target URL since no servers defined
        # Note: Target URL normalizes to include trailing slash
        assert base_url == "http://fallback.example.com/"
    
    def test_parse_path(self):
        """Test parsing a single path"""
        importer = OpenAPIImporter()
        
        path = "/users"
        methods = {
            "get": {
                "summary": "List users",
                "parameters": [
                    {"name": "limit", "in": "query", "schema": {"type": "integer"}}
                ],
                "responses": {"200": {"description": "OK"}}
            },
            "post": {
                "summary": "Create user",
                "requestBody": {
                    "content": {
                        "application/json": {
                            "schema": {"type": "object"}
                        }
                    }
                },
                "responses": {"201": {"description": "Created"}}
            }
        }
        
        target_id = uuid4()
        endpoints = importer._parse_path(path, methods, str(target_id), "http://example.com")
        
        assert len(endpoints) == 2
        assert all(e.path == "/users" for e in endpoints)
        methods_found = [e.method for e in endpoints]
        assert "GET" in methods_found
        assert "POST" in methods_found
    
    @patch('requests.get')
    def test_import_from_url(self, mock_get):
        """Test importing from URL"""
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "openapi": "3.0.0",
            "paths": {
                "/api/test": {
                    "get": {"responses": {"200": {"description": "OK"}}}
                }
            }
        }
        mock_get.return_value = mock_response
        
        importer = OpenAPIImporter()
        target = Target(id=uuid4(), name="Test", url="http://example.com")
        
        result = importer.import_from_url("http://example.com/openapi.json", target)
        
        assert isinstance(result, OpenAPIImportResult)
        assert len(result.endpoints) == 1


class TestOpenAPIImportResult:
    """Test OpenAPIImportResult dataclass"""
    
    def test_default_values(self):
        """Test default values for import result"""
        result = OpenAPIImportResult()
        
        assert result.endpoints == []
        assert result.schemas == {}
        assert result.security_schemes == {}
        assert result.base_url == ""
    
    def test_with_values(self):
        """Test import result with values"""
        result = OpenAPIImportResult(
            endpoints=[Mock()],
            schemas={'User': {'type': 'object'}},
            security_schemes={'bearer': {'type': 'http'}},
            base_url="http://example.com"
        )
        
        assert len(result.endpoints) == 1
        assert 'User' in result.schemas
        assert 'bearer' in result.security_schemes
        assert result.base_url == "http://example.com"


class TestOpenAPIImportIntegration:
    """Integration tests for OpenAPI importer"""
    
    def test_full_spec_import(self):
        """Test full spec import with multiple endpoints"""
        importer = OpenAPIImporter()
        
        full_spec = {
            "openapi": "3.0.0",
            "info": {
                "title": "Sample API",
                "version": "1.0.0"
            },
            "servers": [
                {"url": "https://api.example.com/v1"}
            ],
            "paths": {
                "/users": {
                    "get": {
                        "summary": "List all users",
                        "parameters": [
                            {"name": "limit", "in": "query", "schema": {"type": "integer"}},
                            {"name": "offset", "in": "query", "schema": {"type": "integer"}}
                        ],
                        "responses": {"200": {"description": "OK"}}
                    },
                    "post": {
                        "summary": "Create user",
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "name": {"type": "string"},
                                            "email": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        },
                        "responses": {"201": {"description": "Created"}}
                    }
                },
                "/users/{id}": {
                    "get": {
                        "summary": "Get user",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "responses": {"200": {"description": "OK"}}
                    },
                    "put": {
                        "summary": "Update user",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "requestBody": {
                            "content": {
                                "application/json": {
                                    "schema": {"type": "object"}
                                }
                            }
                        },
                        "responses": {"200": {"description": "OK"}}
                    },
                    "delete": {
                        "summary": "Delete user",
                        "parameters": [
                            {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}}
                        ],
                        "responses": {"204": {"description": "No Content"}}
                    }
                }
            },
            "components": {
                "securitySchemes": {
                    "bearerAuth": {
                        "type": "http",
                        "scheme": "bearer"
                    }
                }
            }
        }
        
        target = Target(id=uuid4(), name="Test", url="http://example.com")
        result = importer.import_from_dict(full_spec, target)
        
        # Should have 5 endpoints: GET /users, POST /users, GET /users/{id}, PUT /users/{id}, DELETE /users/{id}
        assert len(result.endpoints) == 5
        assert result.base_url == "https://api.example.com/v1"
        assert "bearerAuth" in result.security_schemes


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
