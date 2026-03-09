"""
VulnScope - OpenAPI Importer Unit Tests
Tests for OpenAPI specification parsing
"""

import pytest
from unittest.mock import Mock, patch
from uuid import uuid4

from src.discovery.openapi_importer import OpenAPIImporter
from src.core.models import Endpoint


class TestOpenAPIImporter:
    """Test OpenAPIImporter class"""
    
    def test_initialization(self):
        importer = OpenAPIImporter()
        assert importer is not None
    
    def test_parse_openapi_v3(self):
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
        
        endpoints = importer.parse_spec(spec)
        
        assert len(endpoints) == 3
    
    def test_parse_openapi_v2(self):
        importer = OpenAPIImporter()
        
        spec = {
            "swagger": "2.0",
            "info": {
                "title": "Test API",
                "version": "1.0.0"
            },
            "paths": {
                "/products": {
                    "get": {
                        "summary": "List products",
                        "responses": {"200": {"description": "OK"}}
                    }
                }
            }
        }
        
        endpoints = importer.parse_spec(spec)
        
        assert len(endpoints) == 1
    
    def test_extract_parameters(self):
        importer = OpenAPIImporter()
        
        operation = {
            "parameters": [
                {"name": "limit", "in": "query", "type": "integer"},
                {"name": "offset", "in": "query", "type": "integer"},
                {"name": "id", "in": "path", "type": "string"}
            ]
        }
        
        params = importer.extract_parameters(operation)
        
        assert len(params) == 3
    
    def test_extract_request_body(self):
        importer = OpenAPIImporter()
        
        operation = {
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
            }
        }
        
        body = importer.extract_request_body(operation)
        
        assert body is not None
    
    def test_import_from_url(self):
        importer = OpenAPIImporter()
        
        with patch.object(importer, 'fetch_spec') as mock_fetch:
            mock_fetch.return_value = {
                "openapi": "3.0.0",
                "paths": {
                    "/api/test": {
                        "get": {"responses": {"200": {"description": "OK"}}}
                    }
                }
            }
            
            endpoints = importer.import_from_url("http://example.com/openapi.json")
            
            assert isinstance(endpoints, list)
    
    def test_import_from_file(self):
        importer = OpenAPIImporter()
        
        with patch.object(importer, 'load_file') as mock_load:
            mock_load.return_value = {
                "openapi": "3.0.0",
                "paths": {
                    "/api/test": {
                        "get": {"responses": {"200": {"description": "OK"}}}
                    }
                }
            }
            
            endpoints = importer.import_from_file("/path/to/openapi.json")
            
            assert isinstance(endpoints, list)
    
    def test_create_endpoints(self):
        importer = OpenAPIImporter()
        target_id = uuid4()
        
        paths = {
            "/users": {"get": {}, "post": {}},
            "/products": {"get": {}}
        }
        
        endpoints = importer.create_endpoints(paths, target_id, "http://example.com")
        
        assert len(endpoints) == 3
    
    def test_handle_security_schemes(self):
        importer = OpenAPIImporter()
        
        spec = {
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
        
        security = importer.extract_security_schemes(spec)
        
        assert len(security) == 2
    
    def test_extract_base_url(self):
        importer = OpenAPIImporter()
        
        spec = {
            "openapi": "3.0.0",
            "servers": [
                {"url": "https://api.example.com/v1"}
            ]
        }
        
        base_url = importer.extract_base_url(spec)
        
        assert base_url == "https://api.example.com/v1"
    
    def test_extract_base_url_v2(self):
        importer = OpenAPIImporter()
        
        spec = {
            "swagger": "2.0",
            "host": "api.example.com",
            "basePath": "/v1",
            "schemes": ["https"]
        }
        
        base_url = importer.extract_base_url(spec)
        
        assert base_url == "https://api.example.com/v1"
    
    def test_parse_path_parameters(self):
        importer = OpenAPIImporter()
        
        path_item = {
            "get": {
                "parameters": [
                    {"name": "id", "in": "path", "required": True, "schema": {"type": "string"}},
                    {"name": "format", "in": "query", "schema": {"type": "string"}}
                ]
            }
        }
        
        params = importer.parse_path_parameters(path_item)
        
        assert len(params) == 2


class TestOpenAPIImportIntegration:
    """Integration tests for OpenAPI importer"""
    
    def test_full_spec_import(self):
        importer = OpenAPIImporter()
        target_id = uuid4()
        
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
        
        endpoints = importer.parse_spec(full_spec, target_id)
        
        # Should have 5 endpoints: GET /users, POST /users, GET /users/{id}, PUT /users/{id}, DELETE /users/{id}
        assert len(endpoints) == 5


if __name__ == "__main__":
    pytest.main([__file__, "-v"])