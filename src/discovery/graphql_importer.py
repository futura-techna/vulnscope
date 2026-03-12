"""
VulnScope - GraphQL Importer
Import and parse GraphQL schemas for endpoint discovery
"""

import json
from typing import List, Dict, Any, Optional
from dataclasses import dataclass
import requests

from ..core.models import Endpoint, Target
from ..core.exceptions import DiscoveryError


@dataclass
class GraphQLImportResult:
    """Result of GraphQL import"""
    endpoints: List[Endpoint] = None
    schema: Dict[str, Any] = None
    queries: List[str] = None
    mutations: List[str] = None
    
    def __post_init__(self):
        self.endpoints = self.endpoints or []
        self.schema = self.schema or {}
        self.queries = self.queries or []
        self.mutations = self.mutations or []


class GraphQLImporter:
    """
    Import GraphQL schemas
    
    Supports:
    - Introspection queries
    - SDL (Schema Definition Language)
    - Introspection results
    """
    
    # GraphQL introspection query
    INTROSPECTION_QUERY = """
    query IntrospectionQuery {
      __schema {
        queryType { name }
        mutationType { name }
        subscriptionType { name }
        types {
          ...FullType
        }
        directives {
          name
          description
          locations
          args {
            ...InputValue
          }
        }
      }
    }
    
    fragment FullType on __Type {
      kind
      name
      description
      fields(includeDeprecated: true) {
        name
        description
        args {
          ...InputValue
        }
        type {
          ...TypeRef
        }
        isDeprecated
        deprecationReason
      }
      inputFields {
        ...InputValue
      }
      interfaces {
        ...TypeRef
      }
      enumValues(includeDeprecated: true) {
        name
        description
        isDeprecated
        deprecationReason
      }
      possibleTypes {
        ...TypeRef
      }
    }
    
    fragment InputValue on __InputValue {
      name
      description
      type {
        ...TypeRef
      }
      defaultValue
    }
    
    fragment TypeRef on __Type {
      kind
      name
      ofType {
        kind
        name
        ofType {
          kind
          name
          ofType {
            kind
            name
            ofType {
              kind
              name
              ofType {
                kind
                name
                ofType {
                  kind
                  name
                }
              }
            }
          }
        }
      }
    }
    """
    
    def __init__(self):
        self.schema: Optional[Dict[str, Any]] = None
        self.endpoint_url: str = ""
    
    def _extract_operations(self) -> tuple:
        """Extract queries and mutations from schema"""
        queries = []
        mutations = []
        
        if not self.schema:
            return queries, mutations
        
        # Find query and mutation types
        schema_data = self.schema.get('__schema', {})
        if not schema_data:
            return queries, mutations
            
        query_type = schema_data.get('queryType', {}).get('name', 'Query')
        mutation_type = schema_data.get('mutationType', {}).get('name', 'Mutation')
        
        # Find all fields in types
        types = {t['name']: t for t in schema_data.get('types', [])}
        
        # Extract queries
        if query_type in types:
            query_fields = types[query_type].get('fields', [])
            for field in query_fields:
                queries.append(field['name'])
        
        # Extract mutations
        if mutation_type in types:
            mutation_fields = types[mutation_type].get('fields', [])
            for field in mutation_fields:
                mutations.append(field['name'])
        
        return queries, mutations
    
    def _create_endpoints(self, target: Target) -> List[Endpoint]:
        """Create endpoints from GraphQL operations"""
        endpoints = []
        queries, mutations = self._extract_operations()
        
        # Create query endpoint (POST)
        for query in queries:
            endpoint = Endpoint(
                target_id=str(target.id),
                url=self.endpoint_url,
                method='POST',
                path='/graphql',
                parameters=[{
                    'name': 'query',
                    'in': 'body',
                    'type': 'string',
                    'required': True,
                }],
                source='graphql',
                is_api=True,
                has_body=True,
                content_type='application/json',
            )
            endpoints.append(endpoint)
        
        # Create mutation endpoint (POST)
        for mutation in mutations:
            endpoint = Endpoint(
                target_id=str(target.id),
                url=self.endpoint_url,
                method='POST',
                path='/graphql',
                parameters=[{
                    'name': 'mutation',
                    'in': 'body',
                    'type': 'string',
                    'required': True,
                }],
                source='graphql',
                is_api=True,
                has_body=True,
                content_type='application/json',
            )
            endpoints.append(endpoint)
        
        # Add GET endpoint for GraphQL (for queries)
        endpoint = Endpoint(
            target_id=str(target.id),
            url=self.endpoint_url,
            method='GET',
            path='/graphql',
            parameters=[
                {'name': 'query', 'in': 'query', 'type': 'string', 'required': True},
            ],
            source='graphql',
            is_api=True,
            has_params=True,
        )
        endpoints.append(endpoint)
        
        return endpoints
    
    def import_from_introspection(self, endpoint_url: str, 
                                   target: Target) -> GraphQLImportResult:
        """
        Import GraphQL schema via introspection
        
        Args:
            endpoint_url: GraphQL endpoint URL
            target: Target application
            
        Returns:
            GraphQLImportResult with discovered endpoints
        """
        result = GraphQLImportResult()
        self.endpoint_url = endpoint_url
        
        try:
            response = requests.post(
                endpoint_url,
                json={'query': self.INTROSPECTION_QUERY},
                headers={'Content-Type': 'application/json'},
                timeout=30
            )
            response.raise_for_status()
            
            data = response.json()
            if 'errors' in data:
                raise DiscoveryError(f"GraphQL errors: {data['errors']}")
            
            self.schema = data.get('data', {})
            result.schema = self.schema
            
        except requests.RequestException as e:
            raise DiscoveryError(f"Failed to fetch GraphQL schema: {e}")
        
        # Extract operations and create endpoints
        result.queries, result.mutations = self._extract_operations()
        result.endpoints = self._create_endpoints(target)
        
        return result
    
    def import_from_sdl(self, sdl_content: str, endpoint_url: str,
                        target: Target) -> GraphQLImportResult:
        """
        Import GraphQL schema from SDL
        
        Args:
            sdl_content: GraphQL SDL content
            endpoint_url: GraphQL endpoint URL
            target: Target application
            
        Returns:
            GraphQLImportResult with discovered endpoints
        """
        result = GraphQLImportResult()
        self.endpoint_url = endpoint_url
        
        # Parse SDL (simplified - in production use graphql library)
        queries = []
        mutations = []
        
        lines = sdl_content.split('\n')
        current_type = None
        
        for line in lines:
            stripped = line.strip()
            if stripped.startswith('type Query'):
                current_type = 'query'
            elif stripped.startswith('type Mutation'):
                current_type = 'mutation'
            elif stripped.startswith('type '):
                current_type = None
            elif current_type and stripped and ':' in stripped and not stripped.startswith('#'):
                # This is a field inside Query or Mutation type
                field_name = stripped.split('(')[0].split(':')[0].strip()
                if field_name and not field_name.startswith('}'):
                    if current_type == 'query':
                        queries.append(field_name)
                    elif current_type == 'mutation':
                        mutations.append(field_name)
        
        result.queries = queries
        result.mutations = mutations
        
        # Create endpoints
        result.endpoints = self._create_endpoints(target)
        
        return result
    
    def import_from_file(self, schema_path: str, endpoint_url: str,
                         target: Target) -> GraphQLImportResult:
        """
        Import GraphQL schema from file
        
        Args:
            schema_path: Path to GraphQL schema file
            endpoint_url: GraphQL endpoint URL
            target: Target application
            
        Returns:
            GraphQLImportResult with discovered endpoints
        """
        import yaml
        
        path = schema_path.lower()
        
        try:
            with open(schema_path, 'r') as f:
                if path.endswith('.json'):
                    self.schema = json.load(f)
                elif path.endswith(('.yaml', '.yml')):
                    self.schema = yaml.safe_load(f)
                elif path.endswith('.graphql') or path.endswith('.graphqls'):
                    content = f.read()
                    return self.import_from_sdl(content, endpoint_url, target)
                else:
                    raise ValueError(f"Unsupported schema format: {path}")
        except Exception as e:
            raise DiscoveryError(f"Failed to load GraphQL schema: {e}")
        
        result = GraphQLImportResult()
        result.schema = self.schema
        self.endpoint_url = endpoint_url
        
        # Extract operations
        result.queries, result.mutations = self._extract_operations()
        result.endpoints = self._create_endpoints(target)
        
        return result
    
    def get_introspection_url(self, endpoint_url: str) -> str:
        """Get URL for GraphQL playground/introspection"""
        # Common GraphQL playground paths
        playground_paths = [
            '/graphql',
            '/playground',
            '/graphiql',
            '/api/graphql',
        ]
        
        return endpoint_url.rstrip('/') + playground_paths[0]
