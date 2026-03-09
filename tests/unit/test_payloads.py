"""
VulnScope - Payloads Unit Tests
Tests for vulnerability payload generation
"""

import pytest
from src.scanner.payloads import PayloadGenerator


class TestPayloadGenerator:
    """Test PayloadGenerator class"""
    
    def test_initialization(self):
        generator = PayloadGenerator()
        assert generator is not None
    
    def test_get_sql_payloads(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads("sql")
        
        assert len(payloads) > 0
        assert any("'" in p for p in payloads)
    
    def test_get_sqli_payloads(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads("sqli")
        
        assert len(payloads) > 0
    
    def test_get_xss_payloads(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads("xss")
        
        assert len(payloads) > 0
        assert any("<script>" in p for p in payloads)
    
    def test_get_ssrf_payloads(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads("ssrf")
        
        assert len(payloads) > 0
        assert any("localhost" in p or "127.0.0.1" in p for p in payloads)
    
    def test_get_path_traversal_payloads(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads("path_traversal")
        
        assert len(payloads) > 0
        assert any("../" in p for p in payloads)
    
    def test_get_command_injection_payloads(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads("command_injection")
        
        assert len(payloads) > 0
    
    def test_get_xxe_payloads(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads("xxe")
        
        assert len(payloads) > 0
    
    def test_get_credentials_payloads(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads("credentials")
        
        assert len(payloads) > 0
        assert any(":" in p for p in payloads)
    
    def test_get_api_keys_payloads(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads("api_keys")
        
        assert len(payloads) > 0
    
    def test_get_unknown_category(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads("unknown_category")
        
        assert isinstance(payloads, list)
        assert len(payloads) == 0
    
    def test_get_payloads_for_parameter_sql(self):
        generator = PayloadGenerator()
        
        # Parameters with 'id' should get SQL payloads
        payloads = generator.get_payloads_for_parameter("id", "string")
        
        assert len(payloads) > 0
    
    def test_get_payloads_for_parameter_xss(self):
        generator = PayloadGenerator()
        
        # Parameters with 'name' should get XSS payloads
        payloads = generator.get_payloads_for_parameter("name", "string")
        
        assert len(payloads) > 0
    
    def test_get_payloads_for_parameter_ssrf(self):
        generator = PayloadGenerator()
        
        # Parameters with 'url' should get SSRF payloads
        payloads = generator.get_payloads_for_parameter("url", "string")
        
        assert len(payloads) > 0
    
    def test_get_payloads_for_parameter_integer(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads_for_parameter("count", "integer")
        
        assert "1" in payloads
        assert "0" in payloads
    
    def test_get_payloads_for_parameter_email(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads_for_parameter("email", "email")
        
        assert len(payloads) > 0
        assert any("@" in p for p in payloads)
    
    def test_get_payloads_for_parameter_url(self):
        generator = PayloadGenerator()
        
        payloads = generator.get_payloads_for_parameter("redirect", "url")
        
        assert len(payloads) > 0
    
    def test_add_custom_payloads(self):
        generator = PayloadGenerator()
        
        generator.add_custom_payloads("custom", ["payload1", "payload2"])
        
        payloads = generator.get_payloads("custom")
        
        assert "payload1" in payloads
        assert "payload2" in payloads
    
    def test_generate_fuzzing_payloads(self):
        generator = PayloadGenerator()
        
        payloads = generator.generate_fuzzing_payloads("test", count=50)
        
        assert len(payloads) > 0
        assert "test" in payloads
    
    def test_get_all_categories(self):
        generator = PayloadGenerator()
        
        categories = generator.get_all_categories()
        
        assert "sql" in categories
        assert "xss" in categories
        assert "ssrf" in categories
        assert "path_traversal" in categories


if __name__ == "__main__":
    pytest.main([__file__, "-v"])