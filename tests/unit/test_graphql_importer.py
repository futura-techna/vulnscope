"""
VulnScope - GraphQL Importer Unit Tests
Tests for GraphQL schema introspection
"""

import pytest
from unittest.mock import Mock, patch
from uuid import uuid4

from src.discovery.graphql_importer import GraphQLImporter
from src.core.models import Endpoint


class TestGraphQLImporter:
    """Test GraphQLImporter class"""
    
    def test_initialization(self):
        importer = GraphQLImporter()
        assert importer is not None
    
    def test_initialization_with_url(self):
        importer = GraphQLImporter(url="http://example.com/graphql")
        assert importer.url == "http://example.com/graphql"
    
    def test_introspection_query(self):
        importer = GraphQLImporter()
        
        # The introspection query should be defined
        assert hasattr(importer, 'introspection_query')
        assert importer.introspection_query is not None
        assert "schema" in importer.introspection_query.lower()
    
    def test_parse_introspection_result(self):
        importer = GraphQLImporter()
        
        introspection_data = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {
                            "name": "Query",
                            "fields": [
                                {"name": "users", "type": {"name": "User"}},
                                {"name": "user", "type": {"name": "User"}}
                            ]
                        },
                        {
                            "name": "Mutation",
                            "fields": [
                                {"name": "createUser", "type": {"name": "User"}},
                                {"name": "deleteUser", "type": {"name": "Boolean"}}
                            ]
                        }
                    ]
                }
            }
        }
        
        result = importer.parse_introspection(introspection_data)
        
        assert "queries" in result
        assert "mutations" in result
        assert len(result["queries"]) == 2
        assert len(result["mutations"]) == 2
    
    def test_extract_operations(self):
        importer = GraphQLImporter()
        
        schema_types = [
            {
                "name": "Query",
                "fields": [
                    {"name": "allUsers", "args": []},
                    {"name": "userById", "args": [{"name": "id", "type": "ID!"}]}
                ]
            },
            {
                "name": "Mutation",
                "fields": [
                    {"name": "createUser", "args": [{"name": "input", "type": "UserInput"}]},
                    {"name": "updateUser", "args": [{"name": "id", "type": "ID!"}]}
                ]
            }
        ]
        
        operations = importer.extract_operations(schema_types)
        
        assert len(operations["queries"]) == 2
        assert len(operations["mutations"]) == 2
    
    def test_create_endpoints_from_schema(self):
        importer = GraphQLImporter()
        target_id = uuid4()
        
        operations = {
            "queries": ["users", "user"],
            "mutations": ["createUser", "deleteUser"]
        }
        
        endpoints = importer.create_endpoints(operations, target_id, "http://example.com/graphql")
        
        assert len(endpoints) > 0
        assert all(e.method == "POST" for e in endpoints)  # GraphQL uses POST
    
    @patch('requests.post')
    def test_fetch_schema(self, mock_post):
        importer = GraphQLImporter(url="http://example.com/graphql")
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "types": []
                }
            }
        }
        mock_post.return_value = mock_response
        
        result = importer.fetch_schema()
        
        assert result is not None
        mock_post.assert_called_once()
    
    def test_generate_query_documentation(self):
        importer = GraphQLImporter()
        
        query = {
            "name": "getUser",
            "description": "Get a user by ID",
            "args": [
                {"name": "id", "type": "ID!", "description": "User ID"}
            ],
            "type": {"name": "User"}
        }
        
        doc = importer.generate_query_documentation(query)
        
        assert "getUser" in doc
        assert "User ID" in doc
    
    def test_handle_input_types(self):
        importer = GraphQLImporter()
        
        types = [
            {
                "name": "UserInput",
                "kind": "INPUT_OBJECT",
                "inputFields": [
                    {"name": "name", "type": "String"},
                    {"name": "email", "type": "String"}
                ]
            }
        ]
        
        input_types = importer.extract_input_types(types)
        
        assert len(input_types) == 1
        assert "UserInput" in input_types
    
    def test_handle_enums(self):
        importer = GraphQLImporter()
        
        types = [
            {
                "name": "Status",
                "kind": "ENUM",
                "enumValues": [
                    {"name": "ACTIVE"},
                    {"name": "INACTIVE"}
                ]
            }
        ]
        
        enums = importer.extract_enums(types)
        
        assert len(enums) == 1
        assert "ACTIVE" in enums["Status"]
    
    def test_handle_interfaces(self):
        importer = GraphQLImporter()
        
        types = [
            {
                "name": "Node",
                "kind": "INTERFACE",
                "fields": [
                    {"name": "id", "type": {"name": "ID"}}
                ]
            }
        ]
        
        interfaces = importer.extract_interfaces(types)
        
        assert "Node" in interfaces
    
    def test_handle_unions(self):
        importer = GraphQLImporter()
        
        types = [
            {
                "name": "SearchResult",
                "kind": "UNION",
                "possibleTypes": [
                    {"name": "User"},
                    {"name": "Post"}
                ]
            }
        ]
        
        unions = importer.extract_unions(types)
        
        assert len(unions) == 1


class TestGraphQLImportIntegration:
    """Integration tests for GraphQL importer"""
    
    @patch('requests.post')
    def test_full_schema_import(self, mock_post):
        importer = GraphQLImporter()
        target_id = uuid4()
        
        mock_response = Mock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "data": {
                "__schema": {
                    "queryType": {"name": "Query"},
                    "mutationType": {"name": "Mutation"},
                    "types": [
                        {
                            "name": "Query",
                            "fields": [
                                {
                                    "name": "users",
                                    "args": [],
                                    "type": {"name": "User"}
                                },
                                {
                                    "name": "user",
                                    "args": [{"name": "id", "type": {"name": "ID"}}],
                                    "type": {"name": "User"}
                                }
                            ]
                        },
                        {
                            "name": "Mutation",
                            "fields": [
                                {
                                    "name": "createUser",
                                    "args": [{"name": "input", "type": {"name": "UserInput"}}],
                                    "type": {"name": "User"}
                                }
                            ]
                        }
                    ]
                }
            }
        }
        mock_post.return_value = mock_response
        
        endpoints = importer.import_from_url("http://example.com/graphql", target_id)
        
        assert isinstance(endpoints, list)
    
    def test_error_handling(self):
        importer = GraphQLImporter()
        
        with patch('requests.post') as mock_post:
            mock_post.side_effect = Exception("Connection error")
            
            with pytest.raises(Exception):
                importer.fetch_schema()
    
    def test_nested_type_resolution(self):
        importer = GraphQLImporter()
        
        types = [
            {
                "name": "User",
                "fields": [
                    {"name": "id", "type": {"name": "ID"}},
                    {"name": "profile", "type": {"name": "Profile", "ofType": None}}
                ]
            },
            {
                "name": "Profile",
                "fields": [
                    {"name": "bio", "type": {"name": "String"}},
                    {"name": "avatar", "type": {"name": "String"}}
                ]
            }
        ]
        
        type_map = importer.build_type_map(types)
        
        assert "User" in type_map
        assert "Profile" in type_map


if __name__ == "__main__":
    pytest.main([__file__, "-v"])