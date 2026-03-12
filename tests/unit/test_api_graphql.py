"""
VulnScope - GraphQL API Tests
Tests for GraphQL endpoints and schema
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock
from datetime import datetime
from uuid import uuid4

from src.api.graphql import (
    GraphQLSchema, GraphQLQuery, GraphQLMutation,
    GraphQLError, GraphQLContext
)


class TestGraphQLSchema:
    """Test GraphQL schema definition"""
    
    def test_schema_init(self):
        schema = GraphQLSchema()
        
        assert schema.queries is not None
        assert schema.mutations is not None
    
    def test_add_query(self):
        schema = GraphQLSchema()
        
        schema.add_query("targets", "Target", lambda: [])
        
        assert "targets" in schema.queries
    
    def test_add_mutation(self):
        schema = GraphQLSchema()
        
        schema.add_mutation("createTarget", "Target", lambda x: x)
        
        assert "createTarget" in schema.mutations
    
    def test_get_query_type(self):
        schema = GraphQLSchema()
        schema.add_query("findings", "Finding", lambda: [])
        
        query_type = schema.get_query_type("findings")
        
        assert query_type == "Finding"
    
    def test_get_mutation_type(self):
        schema = GraphQLSchema()
        schema.add_mutation("createScan", "Scan", lambda x: x)
        
        mutation_type = schema.get_mutation_type("createScan")
        
        assert mutation_type == "Scan"


class TestGraphQLQuery:
    """Test GraphQL query execution"""
    
    @pytest.fixture
    def query(self):
        return GraphQLQuery()
    
    def test_parse_simple_query(self, query):
        query_str = """
        query {
            targets {
                id
                name
                url
            }
        }
        """
        
        parsed = query.parse(query_str)
        
        assert parsed["operation"] == "query"
        assert "targets" in parsed["fields"]
    
    def test_parse_query_with_arguments(self, query):
        query_str = """
        query {
            target(id: "target-123") {
                id
                name
            }
        }
        """
        
        parsed = query.parse(query_str)
        
        assert parsed["operation"] == "query"
        assert "target" in parsed["fields"]
    
    def test_parse_query_with_variables(self, query):
        query_str = """
        query GetTarget($id: ID!) {
            target(id: $id) {
                id
                name
            }
        }
        """
        
        parsed = query.parse(query_str)
        
        assert "GetTarget" in parsed.get("name", "")
    
    def test_parse_nested_query(self, query):
        query_str = """
        query {
            scans {
                id
                name
                findings {
                    id
                    severity
                }
            }
        }
        """
        
        parsed = query.parse(query_str)
        
        assert "scans" in parsed["fields"]
        assert "findings" in parsed["fields"]["scans"]["nested"]


class TestGraphQLMutation:
    """Test GraphQL mutation execution"""
    
    @pytest.fixture
    def mutation(self):
        return GraphQLMutation()
    
    def test_parse_mutation(self, mutation):
        mutation_str = """
        mutation {
            createTarget(name: "Test", url: "https://example.com") {
                id
                name
            }
        }
        """
        
        parsed = mutation.parse(mutation_str)
        
        assert parsed["operation"] == "mutation"
        assert "createTarget" in parsed["fields"]
    
    def test_parse_mutation_with_variables(self, mutation):
        mutation_str = """
        mutation CreateScan($input: ScanInput!) {
            createScan(input: $input) {
                id
                status
            }
        }
        """
        
        parsed = mutation.parse(mutation_str)
        
        assert "CreateScan" in parsed.get("name", "")


class TestGraphQLError:
    """Test GraphQL error handling"""
    
    def test_simple_error(self):
        error = GraphQLError("Target not found")
        
        assert error.message == "Target not found"
    
    def test_error_with_code(self):
        error = GraphQLError("Invalid input", code="VALIDATION_ERROR")
        
        assert error.code == "VALIDATION_ERROR"
    
    def test_error_with_path(self):
        error = GraphQLError(
            "Field not found",
            path=["query", "target", "invalidField"]
        )
        
        assert error.path == ["query", "target", "invalidField"]
    
    def test_error_to_dict(self):
        error = GraphQLError(
            "Something went wrong",
            code="INTERNAL_ERROR",
            path=["mutation", "createTarget"]
        )
        
        error_dict = error.to_dict()
        
        assert error_dict["message"] == "Something went wrong"
        assert error_dict["extensions"]["code"] == "INTERNAL_ERROR"


class TestGraphQLContext:
    """Test GraphQL context"""
    
    def test_create_context(self):
        context = GraphQLContext(
            user_id="user-123",
            roles=["admin", "scanner"]
        )
        
        assert context.user_id == "user-123"
        assert "admin" in context.roles
    
    def test_has_role(self):
        context = GraphQLContext(roles=["viewer"])
        
        assert context.has_role("viewer") is True
        assert context.has_role("admin") is False
    
    def test_is_authenticated(self):
        context = GraphQLContext(user_id="user-123")
        
        assert context.is_authenticated() is True
    
    def test_is_not_authenticated(self):
        context = GraphQLContext()
        
        assert context.is_authenticated() is False


class TestGraphQLResolvers:
    """Test GraphQL resolvers"""
    
    @pytest.mark.asyncio
    async def test_resolve_targets(self):
        from src.api.graphql import resolve_targets
        
        # Mock context
        context = GraphQLContext(user_id="user-123", roles=["scanner"])
        
        # Mock database
        with patch('src.api.graphql.get_targets') as mock_get:
            mock_get.return_value = [
                {"id": "target-1", "name": "Target 1"}
            ]
            
            result = await resolve_targets(context)
            
            assert len(result) == 1
    
    @pytest.mark.asyncio
    async def test_resolve_findings(self):
        from src.api.graphql import resolve_findings
        
        context = GraphQLContext(user_id="user-123", roles=["scanner"])
        
        with patch('src.api.graphql.get_findings') as mock_get:
            mock_get.return_value = [
                {"id": "finding-1", "severity": "High"}
            ]
            
            result = await resolve_findings(context, scan_id="scan-1")
            
            assert len(result) == 1
    
    @pytest.mark.asyncio
    async def test_mutation_create_target(self):
        from src.api.graphql import mutate_create_target
        
        context = GraphQLContext(user_id="user-123", roles=["admin"])
        
        with patch('src.api.graphql.create_target') as mock_create:
            mock_create.return_value = {
                "id": "target-new",
                "name": "New Target"
            }
            
            result = await mutate_create_target(
                context,
                name="New Target",
                url="https://example.com"
            )
            
            assert result["id"] == "target-new"


class TestGraphQLSubscription:
    """Test GraphQL subscriptions"""
    
    @pytest.mark.asyncio
    async def test_scan_progress_subscription(self):
        from src.api.graphql import subscribe_scan_progress
        
        context = GraphQLContext(user_id="user-123", roles=["scanner"])
        
        # Mock async generator
        async def mock_generator():
            yield {"scan_id": "scan-1", "progress": 50}
            yield {"scan_id": "scan-1", "progress": 100}
        
        with patch('src.api.graphql.subscribe_to_scan') as mock_sub:
            mock_sub.return_value = mock_generator()
            
            results = []
            async for result in subscribe_scan_progress(context, scan_id="scan-1"):
                results.append(result)
                if len(results) >= 2:
                    break
            
            assert len(results) == 2


if __name__ == "__main__":
    pytest.main([__file__, "-v"])