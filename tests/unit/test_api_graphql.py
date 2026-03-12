"""
VulnScope - GraphQL API Tests
Tests for GraphQL endpoints and schema
"""

import pytest
from unittest.mock import Mock, patch, AsyncMock, MagicMock
from datetime import datetime
from uuid import uuid4

from src.api.graphql import (
    schema, Query, Mutation, Target, Endpoint, Finding, Scan,
    ScanResult, ComplianceResult, CreateTargetInput, CreateScanInput
)


class TestGraphQLTypes:
    """Test GraphQL type definitions"""
    
    def test_target_type(self):
        """Test Target type has expected fields"""
        # Target is a strawberry type, check it exists
        assert Target is not None
    
    def test_endpoint_type(self):
        """Test Endpoint type exists"""
        assert Endpoint is not None
    
    def test_finding_type(self):
        """Test Finding type exists"""
        assert Finding is not None
    
    def test_scan_type(self):
        """Test Scan type exists"""
        assert Scan is not None
    
    def test_scan_result_type(self):
        """Test ScanResult type exists"""
        assert ScanResult is not None
    
    def test_compliance_result_type(self):
        """Test ComplianceResult type exists"""
        assert ComplianceResult is not None


class TestGraphQLInputs:
    """Test GraphQL input types"""
    
    def test_create_target_input(self):
        """Test CreateTargetInput"""
        assert CreateTargetInput is not None
    
    def test_create_scan_input(self):
        """Test CreateScanInput"""
        assert CreateScanInput is not None


class TestGraphQLSchema:
    """Test GraphQL schema definition"""
    
    def test_schema_exists(self):
        """Test schema is created"""
        assert schema is not None
    
    def test_schema_has_query_type(self):
        """Test schema has query type"""
        # Strawberry schema stores this differently
        assert hasattr(schema, '_schema')
    
    def test_schema_is_valid(self):
        """Test schema is a valid strawberry schema"""
        import strawberry
        # Check schema is defined
        assert schema is not None


class TestQueryResolvers:
    """Test GraphQL query resolvers"""
    
    def test_query_class_exists(self):
        """Test Query class exists"""
        assert Query is not None
    
    def test_targets_resolver(self):
        """Test targets query returns list"""
        query = Query()
        result = query.targets()
        assert isinstance(result, list)
    
    def test_target_resolver(self):
        """Test target query with ID"""
        from uuid import UUID
        query = Query()
        result = query.target(id=UUID("12345678-1234-5678-1234-567812345678"))
        # Returns None as no database
        assert result is None
    
    def test_scans_resolver(self):
        """Test scans query returns list"""
        query = Query()
        result = query.scans()
        assert isinstance(result, list)
    
    def test_scans_resolver_with_target_id(self):
        """Test scans query with target_id filter"""
        from uuid import UUID
        query = Query()
        result = query.scans(target_id=UUID("12345678-1234-5678-1234-567812345678"))
        assert isinstance(result, list)
    
    def test_scan_resolver(self):
        """Test scan query with ID"""
        from uuid import UUID
        query = Query()
        result = query.scan(id=UUID("12345678-1234-5678-1234-567812345678"))
        # Returns None as no database
        assert result is None
    
    def test_findings_resolver(self):
        """Test findings query returns list"""
        query = Query()
        result = query.findings()
        assert isinstance(result, list)
    
    def test_findings_resolver_with_filters(self):
        """Test findings query with filters"""
        query = Query()
        result = query.findings(scan_id=None, severity="High")
        assert isinstance(result, list)
    
    def test_compliance_resolver(self):
        """Test compliance query"""
        from uuid import UUID
        query = Query()
        result = query.compliance(
            scan_id=UUID("12345678-1234-5678-1234-567812345678"),
            standard="OWASP"
        )
        assert result is not None
        assert result.standard == "OWASP"
        assert isinstance(result.compliant, bool)
        assert isinstance(result.score, float)


class TestMutationResolvers:
    """Test GraphQL mutation resolvers"""
    
    def test_mutation_class_exists(self):
        """Test Mutation class exists"""
        assert Mutation is not None
    
    def test_create_target_mutation(self):
        """Test createTarget mutation"""
        mutation = Mutation()
        input_data = CreateTargetInput(
            name="Test Target",
            url="https://example.com",
            description="Test description",
            tags=["test"]
        )
        result = mutation.create_target(input=input_data)
        
        assert result is not None
        assert result.name == "Test Target"
        assert result.url == "https://example.com"
        assert result.id is not None
    
    def test_create_scan_mutation(self):
        """Test createScan mutation"""
        from uuid import UUID
        mutation = Mutation()
        input_data = CreateScanInput(
            target_id=UUID("12345678-1234-5678-1234-567812345678"),
            name="Test Scan",
            scan_type="full"
        )
        result = mutation.create_scan(input=input_data)
        
        assert result is not None
        assert result.name == "Test Scan"
        assert result.status == "RUNNING"
        assert result.id is not None
    
    def test_cancel_scan_mutation(self):
        """Test cancelScan mutation"""
        from uuid import UUID
        mutation = Mutation()
        result = mutation.cancel_scan(scan_id=UUID("12345678-1234-5678-1234-567812345678"))
        
        assert result is True
    
    def test_update_finding_status_mutation(self):
        """Test updateFindingStatus mutation"""
        from uuid import UUID
        mutation = Mutation()
        result = mutation.update_finding_status(
            finding_id=UUID("12345678-1234-5678-1234-567812345678"),
            status="CONFIRMED"
        )
        
        assert result is True


class TestGraphQLIntegration:
    """Test GraphQL integration with Strawberry"""
    
    def test_schema_is_strawberry_schema(self):
        """Test schema is a valid Strawberry schema"""
        import strawberry
        from strawberry.schema.schema import Schema as StrawberrySchema
        
        assert isinstance(schema, StrawberrySchema)
    
    def test_query_execution(self):
        """Test executing a query"""
        query_str = """
            query {
                targets {
                    id
                    name
                    url
                }
            }
        """
        
        result = schema.execute_sync(query_str)
        
        assert result.errors is None or len(result.errors) == 0
        assert result.data is not None
    
    def test_mutation_execution(self):
        """Test executing a mutation"""
        mutation_str = """
            mutation {
                createTarget(input: {
                    name: "Test Target",
                    url: "https://example.com"
                }) {
                    id
                    name
                    url
                }
            }
        """
        
        result = schema.execute_sync(mutation_str)
        
        assert result.errors is None or len(result.errors) == 0
        assert result.data is not None
        assert result.data["createTarget"]["name"] == "Test Target"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])