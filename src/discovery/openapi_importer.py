"""
VulnScope - OpenAPI Importer
Import and parse OpenAPI specifications for endpoint discovery
"""

from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
from dataclasses import dataclass

from ..core.models import Endpoint, Target
from ..core.exceptions import DiscoveryError
from ..config.loaders import load_openapi_spec


@dataclass
class OpenAPIImportResult:
    """Result of OpenAPI import"""
    endpoints: List[Endpoint] = None
    schemas: Dict[str, Any] = None
    security_schemes: Dict[str, Any] = None
    base_url: str = ""
    
    def __post_init__(self):
        self.endpoints = self.endpoints or []
        self.schemas = self.schemas or {}
        self.security_schemes = self.security_schemes or {}


class OpenAPIImporter:
    """
    Import OpenAPI (Swagger) specifications
    
    Supports:
    - OpenAPI 3.0/3.1
    - Swagger 2.0
    - JSON and YAML formats
    """
    
    def __init__(self):
        self.spec: Optional[Dict[str, Any]] = None
        self.base_url: str = ""
    
    def _get_base_url(self, target: Target) -> str:
        """Determine base URL from spec or target"""
        if self.spec:
            # OpenAPI 3.0
            if 'servers' in self.spec and self.spec['servers']:
                return self.spec['servers'][0].get('url', str(target.url))
            
            # Try to construct from info
            if 'info' in self.spec:
                host = self.spec.get('host', '')
                base_path = self.spec.get('basePath', '/')
                schemes = self.spec.get('schemes', ['https'])
                if host:
                    return f"{schemes[0]}://{host}{base_path}"
        
        return str(target.url)
    
    def _parse_path(self, path: str, methods: Dict[str, Any], 
                    target_id: str, base_url: str) -> List[Endpoint]:
        """Parse a single OpenAPI path"""
        endpoints = []
        
        for method, details in methods.items():
            if method.upper() not in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'OPTIONS', 'HEAD']:
                continue
            
            # Extract parameters
            parameters = []
            if 'parameters' in details:
                for param in details['parameters']:
                    parameters.append({
                        'name': param.get('name'),
                        'in': param.get('in'),  # query, path, header, cookie
                        'type': param.get('schema', {}).get('type', 'string'),
                        'required': param.get('required', False),
                        'description': param.get('description'),
                    })
            
            # Extract request body (OpenAPI 3.0)
            request_body = details.get('requestBody')
            has_body = request_body is not None
            
            # Extract request body (Swagger 2.0)
            if 'parameters' in details:
                for param in details['parameters']:
                    if param.get('in') == 'body':
                        has_body = True
                        break
            
            # Create endpoint
            full_url = urljoin(base_url, path)
            
            endpoint = Endpoint(
                target_id=target_id,
                url=full_url,
                method=method.upper(),
                path=path,
                parameters=parameters,
                source='openapi',
                is_api=True,
                has_params=len(parameters) > 0,
                has_body=has_body,
            )
            
            # Extract content type
            if request_body and 'content' in request_body:
                content_types = list(request_body['content'].keys())
                if content_types:
                    endpoint.content_type = content_types[0]
            
            endpoints.append(endpoint)
        
        return endpoints
    
    def _extract_security_schemes(self) -> Dict[str, Any]:
        """Extract security schemes from spec"""
        security_schemes = {}
        
        # OpenAPI 3.0
        if 'components' in self.spec:
            components = self.spec['components']
            if 'securitySchemes' in components:
                security_schemes = components['securitySchemes']
        
        # Swagger 2.0
        elif 'securityDefinitions' in self.spec:
            security_schemes = self.spec['securityDefinitions']
        
        return security_schemes
    
    def _extract_schemas(self) -> Dict[str, Any]:
        """Extract data schemas from spec"""
        schemas = {}
        
        # OpenAPI 3.0
        if 'components' in self.spec and 'schemas' in self.spec['components']:
            schemas = self.spec['components']['schemas']
        
        # Swagger 2.0
        elif 'definitions' in self.spec:
            schemas = self.spec['definitions']
        
        return schemas
    
    def import_from_file(self, spec_path: str, target: Target) -> OpenAPIImportResult:
        """
        Import endpoints from OpenAPI file
        
        Args:
            spec_path: Path to OpenAPI JSON/YAML file
            target: Target application
            
        Returns:
            OpenAPIImportResult with discovered endpoints
        """
        try:
            self.spec = load_openapi_spec(spec_path)
        except Exception as e:
            raise DiscoveryError(f"Failed to load OpenAPI spec: {e}")
        
        return self._parse_spec(target)
    
    def import_from_dict(self, spec: Dict[str, Any], target: Target) -> OpenAPIImportResult:
        """
        Import endpoints from OpenAPI dict
        
        Args:
            spec: OpenAPI specification dictionary
            target: Target application
            
        Returns:
            OpenAPIImportResult with discovered endpoints
        """
        self.spec = spec
        return self._parse_spec(target)
    
    def import_from_url(self, spec_url: str, target: Target) -> OpenAPIImportResult:
        """
        Import endpoints from OpenAPI URL
        
        Args:
            spec_url: URL to OpenAPI JSON/YAML file
            target: Target application
            
        Returns:
            OpenAPIImportResult with discovered endpoints
        """
        import requests
        
        try:
            response = requests.get(spec_url, timeout=30)
            response.raise_for_status()
            
            if spec_url.endswith('.yaml') or spec_url.endswith('.yml'):
                import yaml
                self.spec = yaml.safe_load(response.text)
            else:
                self.spec = response.json()
                
        except Exception as e:
            raise DiscoveryError(f"Failed to fetch OpenAPI spec from URL: {e}")
        
        return self._parse_spec(target)
    
    def _parse_spec(self, target: Target) -> OpenAPIImportResult:
        """Parse OpenAPI spec and extract endpoints"""
        result = OpenAPIImportResult()
        
        self.base_url = self._get_base_url(target)
        result.base_url = self.base_url
        
        if not self.spec:
            return result
        
        # Get paths
        paths = self.spec.get('paths', {})
        
        for path, methods in paths.items():
            endpoints = self._parse_path(path, methods, str(target.id), self.base_url)
            result.endpoints.extend(endpoints)
        
        # Extract schemas and security schemes
        result.schemas = self._extract_schemas()
        result.security_schemes = self._extract_security_schemes()
        
        return result
    
    def get_endpoint_coverage(self, discovered: List[Endpoint]) -> float:
        """
        Calculate endpoint coverage percentage
        
        Args:
            discovered: List of discovered endpoints
            
        Returns:
            Coverage percentage (0-100)
        """
        if not self.spec or not result.endpoints:
            return 0.0
        
        spec_endpoints = set()
        for path, methods in self.spec.get('paths', {}).items():
            for method in methods.keys():
                if method.upper() in ['GET', 'POST', 'PUT', 'DELETE', 'PATCH']:
                    spec_endpoints.add(f"{method.upper()} {path}")
        
        discovered_set = set()
        for ep in discovered:
            discovered_set.add(f"{ep.method} {ep.path}")
        
        if not spec_endpoints:
            return 100.0
        
        matched = len(spec_endpoints.intersection(discovered_set))
        return (matched / len(spec_endpoints)) * 100
