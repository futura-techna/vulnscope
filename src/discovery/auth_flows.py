"""
VulnScope - Authentication Flows
Handle various authentication mechanisms for scanning
"""

from typing import Dict, Any, Optional
from enum import Enum
from dataclasses import dataclass
import requests
from urllib.parse import urljoin

from ..core.exceptions import AuthenticationError


class AuthType(str, Enum):
    """Authentication types supported"""
    NONE = "none"
    BASIC = "basic"
    BEARER = "bearer"
    API_KEY = "api_key"
    OAuth2 = "oauth2"
    OIDC = "oidc"
    JWT = "jwt"
    COOKIE = "cookie"


@dataclass
class AuthResult:
    """Result of authentication attempt"""
    success: bool
    session: Optional[requests.Session] = None
    token: Optional[str] = None
    cookies: Optional[Dict[str, str]] = None
    error: Optional[str] = None


class AuthHandler:
    """
    Handle various authentication flows for security scanning
    
    Supports:
    - Basic Authentication
    - Bearer Token
    - API Key
    - OAuth 2.0
    - OIDC
    - JWT
    - Cookie-based Auth
    """
    
    def __init__(self):
        self.session: Optional[requests.Session] = None
        self.auth_type: Optional[AuthType] = None
        self.auth_config: Dict[str, Any] = {}
    
    def _create_session(self) -> requests.Session:
        """Create a new session for requests"""
        session = requests.Session()
        session.headers.update({
            'User-Agent': 'VulnScope-Scanner/1.0'
        })
        return session
    
    def authenticate_basic(self, url: str, username: str, 
                          password: str) -> AuthResult:
        """
        Authenticate using Basic Authentication
        
        Args:
            url: Target URL
            username: Username
            password: Password
            
        Returns:
            AuthResult with session and status
        """
        session = self._create_session()
        
        try:
            response = session.get(
                url,
                auth=(username, password),
                timeout=30
            )
            
            if response.status_code in [200, 201, 204]:
                return AuthResult(
                    success=True,
                    session=session,
                )
            elif response.status_code == 401:
                return AuthResult(
                    success=False,
                    error="Authentication failed - invalid credentials"
                )
            else:
                return AuthResult(
                    success=False,
                    error=f"Unexpected status code: {response.status_code}"
                )
                
        except requests.RequestException as e:
            return AuthResult(
                success=False,
                error=str(e)
            )
    
    def authenticate_bearer(self, url: str, token: str) -> AuthResult:
        """
        Authenticate using Bearer Token
        
        Args:
            url: Target URL
            token: Bearer token
            
        Returns:
            AuthResult with session
        """
        session = self._create_session()
        session.headers.update({
            'Authorization': f'Bearer {token}'
        })
        
        try:
            response = session.get(url, timeout=30)
            
            if response.status_code in [200, 201, 204]:
                return AuthResult(
                    success=True,
                    session=session,
                    token=token,
                )
            else:
                return AuthResult(
                    success=False,
                    error=f"Authentication failed - status: {response.status_code}"
                )
                
        except requests.RequestException as e:
            return AuthResult(
                success=False,
                error=str(e)
            )
    
    def authenticate_api_key(self, url: str, key: str, 
                            header_name: str = "X-API-Key") -> AuthResult:
        """
        Authenticate using API Key
        
        Args:
            url: Target URL
            key: API key
            header_name: Header name for API key
            
        Returns:
            AuthResult with session
        """
        session = self._create_session()
        session.headers.update({
            header_name: key
        })
        
        try:
            response = session.get(url, timeout=30)
            
            if response.status_code in [200, 201, 204]:
                return AuthResult(
                    success=True,
                    session=session,
                    token=key,
                )
            else:
                return AuthResult(
                    success=False,
                    error=f"Authentication failed - status: {response.status_code}"
                )
                
        except requests.RequestException as e:
            return AuthResult(
                success=False,
                error=str(e)
            )
    
    def authenticate_oauth2(self, auth_url: str, token_url: str,
                           client_id: str, client_secret: str,
                           scope: str = "openid profile email") -> AuthResult:
        """
        Authenticate using OAuth 2.0 Resource Owner Password Credentials
        
        Args:
            auth_url: Authorization URL
            token_url: Token endpoint URL
            client_id: OAuth client ID
            client_secret: OAuth client secret
            scope: OAuth scope
            
        Returns:
            AuthResult with access token
        """
        session = self._create_session()
        
        try:
            # Get authorization code (simplified flow)
            auth_params = {
                'response_type': 'code',
                'client_id': client_id,
                'redirect_uri': 'http://localhost/callback',
                'scope': scope,
            }
            
            # For password credentials flow
            token_data = {
                'grant_type': 'password',
                'client_id': client_id,
                'client_secret': client_secret,
                'scope': scope,
            }
            
            # This is a simplified implementation
            # In production, implement proper OAuth2 flows
            response = session.post(token_url, data=token_data, timeout=30)
            
            if response.status_code == 200:
                token_response = response.json()
                access_token = token_response.get('access_token')
                
                if access_token:
                    session.headers.update({
                        'Authorization': f'Bearer {access_token}'
                    })
                    
                    return AuthResult(
                        success=True,
                        session=session,
                        token=access_token,
                    )
            
            return AuthResult(
                success=False,
                error=f"OAuth2 authentication failed - status: {response.status_code}"
            )
            
        except requests.RequestException as e:
            return AuthResult(
                success=False,
                error=str(e)
            )
    
    def authenticate_oidc(self, issuer_url: str, username: str,
                          password: str, client_id: str,
                          client_secret: str = None) -> AuthResult:
        """
        Authenticate using OIDC (OpenID Connect)
        
        Args:
            issuer_url: OIDC issuer URL
            username: Username
            password: Password
            client_id: Client ID
            client_secret: Optional client secret
            
        Returns:
            AuthResult with tokens
        """
        session = self._create_session()
        
        try:
            # Discover OIDC configuration
            discovery_url = urljoin(issuer_url, '/.well-known/openid-configuration')
            response = session.get(discovery_url, timeout=30)
            
            if response.status_code != 200:
                return AuthResult(
                    success=False,
                    error="Failed to discover OIDC configuration"
                )
            
            oidc_config = response.json()
            token_url = oidc_config.get('token_endpoint')
            
            # Authenticate using resource owner password credentials
            token_data = {
                'grant_type': 'password',
                'username': username,
                'password': password,
                'client_id': client_id,
            }
            
            if client_secret:
                token_data['client_secret'] = client_secret
            
            response = session.post(token_url, data=token_data, timeout=30)
            
            if response.status_code == 200:
                token_response = response.json()
                access_token = token_response.get('access_token')
                id_token = token_response.get('id_token')
                
                if access_token:
                    session.headers.update({
                        'Authorization': f'Bearer {access_token}'
                    })
                    
                    return AuthResult(
                        success=True,
                        session=session,
                        token=access_token,
                    )
            
            return AuthResult(
                success=False,
                error=f"OIDC authentication failed - status: {response.status_code}"
            )
            
        except requests.RequestException as e:
            return AuthResult(
                success=False,
                error=str(e)
            )
    
    def authenticate_jwt(self, url: str, token: str) -> AuthResult:
        """
        Authenticate using JWT token
        
        Args:
            url: Target URL
            token: JWT token
            
        Returns:
            AuthResult with session
        """
        return self.authenticate_bearer(url, token)
    
    def authenticate_cookie(self, url: str, cookies: Dict[str, str]) -> AuthResult:
        """
        Authenticate using cookies
        
        Args:
            url: Target URL
            cookies: Dictionary of cookies
            
        Returns:
            AuthResult with session
        """
        session = self._create_session()
        
        for name, value in cookies.items():
            session.cookies.set(name, value)
        
        try:
            response = session.get(url, timeout=30)
            
            if response.status_code in [200, 201, 204]:
                return AuthResult(
                    success=True,
                    session=session,
                    cookies=cookies,
                )
            else:
                return AuthResult(
                    success=False,
                    error=f"Cookie authentication failed - status: {response.status_code}"
                )
                
        except requests.RequestException as e:
            return AuthResult(
                success=False,
                error=str(e)
            )
    
    def authenticate(self, url: str, auth_type: AuthType, 
                   auth_config: Dict[str, Any]) -> AuthResult:
        """
        Generic authentication method
        
        Args:
            url: Target URL
            auth_type: Type of authentication
            auth_config: Authentication configuration
            
        Returns:
            AuthResult with session
        """
        self.auth_type = auth_type
        self.auth_config = auth_config
        
        if auth_type == AuthType.NONE:
            return AuthResult(
                success=True,
                session=self._create_session()
            )
        
        elif auth_type == AuthType.BASIC:
            return self.authenticate_basic(
                url,
                auth_config.get('username', ''),
                auth_config.get('password', '')
            )
        
        elif auth_type == AuthType.BEARER:
            return self.authenticate_bearer(
                url,
                auth_config.get('token', '')
            )
        
        elif auth_type == AuthType.API_KEY:
            return self.authenticate_api_key(
                url,
                auth_config.get('key', ''),
                auth_config.get('header_name', 'X-API-Key')
            )
        
        elif auth_type == AuthType.OAuth2:
            return self.authenticate_oauth2(
                auth_config.get('auth_url', ''),
                auth_config.get('token_url', ''),
                auth_config.get('client_id', ''),
                auth_config.get('client_secret', ''),
                auth_config.get('scope', 'openid profile email')
            )
        
        elif auth_type == AuthType.OIDC:
            return self.authenticate_oidc(
                auth_config.get('issuer_url', ''),
                auth_config.get('username', ''),
                auth_config.get('password', ''),
                auth_config.get('client_id', '')
            )
        
        elif auth_type == AuthType.JWT:
            return self.authenticate_jwt(
                url,
                auth_config.get('token', '')
            )
        
        elif auth_type == AuthType.COOKIE:
            return self.authenticate_cookie(
                url,
                auth_config.get('cookies', {})
            )
        
        else:
            return AuthResult(
                success=False,
                error=f"Unsupported authentication type: {auth_type}"
            )


class AuthFlow:
    """Pre-configured authentication flow patterns"""
    
    @staticmethod
    def create_oauth2_flow(config: Dict[str, Any]) -> Dict[str, Any]:
        """Create OAuth2 authentication configuration"""
        return {
            'auth_type': AuthType.OAuth2,
            'config': {
                'auth_url': config.get('auth_url'),
                'token_url': config.get('token_url'),
                'client_id': config.get('client_id'),
                'client_secret': config.get('client_secret'),
                'scope': config.get('scope', 'openid profile email'),
            }
        }
    
    @staticmethod
    def create_oidc_flow(config: Dict[str, Any]) -> Dict[str, Any]:
        """Create OIDC authentication configuration"""
        return {
            'auth_type': AuthType.OIDC,
            'config': {
                'issuer_url': config.get('issuer_url'),
                'username': config.get('username'),
                'password': config.get('password'),
                'client_id': config.get('client_id'),
                'client_secret': config.get('client_secret'),
            }
        }
    
    @staticmethod
    def create_api_key_flow(api_key: str, header_name: str = "X-API-Key") -> Dict[str, Any]:
        """Create API key authentication configuration"""
        return {
            'auth_type': AuthType.API_KEY,
            'config': {
                'key': api_key,
                'header_name': header_name,
            }
        }
