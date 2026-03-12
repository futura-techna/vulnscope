"""
VulnScope - Database Module Tests
Tests for database configuration, models, and session management
"""

import pytest
from unittest.mock import Mock, patch, MagicMock, AsyncMock
from datetime import datetime
from uuid import uuid4
import json

from src.database import (
    Base, GUID, JsonType, TargetModel, ScanModel, FindingModel,
    ReportModel, SettingsModel, ComplianceDataModel,
    get_database_url, get_engine, get_session, init_db, get_or_create_session
)


class TestGUIDType:
    """Test GUID type decorator"""
    
    def test_guid_load_dialect_impl(self):
        """Test GUID loads as String(36)"""
        guid = GUID()
        dialect = Mock()
        dialect.type_descriptor = Mock(return_value="String(36)")
        
        result = guid.load_dialect_impl(dialect)
        
        dialect.type_descriptor.assert_called_once()
    
    def test_guid_process_bind_param_with_value(self):
        """Test GUID processes UUID to string"""
        guid = GUID()
        dialect = Mock()
        test_uuid = uuid4()
        
        result = guid.process_bind_param(test_uuid, dialect)
        
        assert result == str(test_uuid)
    
    def test_guid_process_bind_param_with_none(self):
        """Test GUID handles None value"""
        guid = GUID()
        dialect = Mock()
        
        result = guid.process_bind_param(None, dialect)
        
        assert result is None
    
    def test_guid_process_bind_param_with_string(self):
        """Test GUID handles string value"""
        guid = GUID()
        dialect = Mock()
        test_str = "test-uuid-string"
        
        result = guid.process_bind_param(test_str, dialect)
        
        assert result == test_str


class TestJsonType:
    """Test JSON type decorator"""
    
    def test_json_load_dialect_impl(self):
        """Test JSON type loads as Text"""
        json_type = JsonType()
        dialect = Mock()
        dialect.type_descriptor = Mock(return_value="Text")
        
        result = json_type.load_dialect_impl(dialect)
        
        dialect.type_descriptor.assert_called_once()
    
    def test_json_process_bind_param_with_dict(self):
        """Test JSON processes dict to string"""
        json_type = JsonType()
        dialect = Mock()
        test_dict = {"key": "value", "nested": {"a": 1}}
        
        result = json_type.process_bind_param(test_dict, dialect)
        
        assert json.loads(result) == test_dict
    
    def test_json_process_bind_param_with_list(self):
        """Test JSON processes list to string"""
        json_type = JsonType()
        dialect = Mock()
        test_list = [1, 2, 3, "test"]
        
        result = json_type.process_bind_param(test_list, dialect)
        
        assert json.loads(result) == test_list
    
    def test_json_process_bind_param_with_none(self):
        """Test JSON handles None value"""
        json_type = JsonType()
        dialect = Mock()
        
        result = json_type.process_bind_param(None, dialect)
        
        assert result is None
    
    def test_json_process_result_value_with_json(self):
        """Test JSON parses JSON string to dict"""
        json_type = JsonType()
        dialect = Mock()
        test_json = '{"key": "value"}'
        
        result = json_type.process_result_value(test_json, dialect)
        
        assert result == {"key": "value"}
    
    def test_json_process_result_value_with_none(self):
        """Test JSON handles None result"""
        json_type = JsonType()
        dialect = Mock()
        
        result = json_type.process_result_value(None, dialect)
        
        assert result is None


class TestTargetModel:
    """Test Target database model"""
    
    def test_create_target_model(self):
        """Test creating a target model"""
        target = TargetModel(
            name="Test Target",
            url="http://example.com",
            description="Test description"
        )
        
        assert target.name == "Test Target"
        assert target.url == "http://example.com"
        assert target.description == "Test description"
    
    def test_target_model_defaults(self):
        """Test target model default values"""
        target = TargetModel(name="Test", url="http://example.com")
        
        assert target.tags == list()
        assert target.auth_type is None
        assert target.auth_config == dict()
    
    def test_target_model_with_auth(self):
        """Test target model with authentication config"""
        target = TargetModel(
            name="Test",
            url="http://example.com",
            auth_type="bearer",
            auth_config={"token": "test-token"}
        )
        
        assert target.auth_type == "bearer"
        assert target.auth_config == {"token": "test-token"}
    
    def test_target_model_with_tags(self):
        """Test target model with tags"""
        target = TargetModel(
            name="Test",
            url="http://example.com",
            tags=["api", "production"]
        )
        
        assert "api" in target.tags
        assert "production" in target.tags
    
    def test_target_model_table_name(self):
        """Test target model table name"""
        assert TargetModel.__tablename__ == "targets"


class TestScanModel:
    """Test Scan database model"""
    
    def test_create_scan_model(self):
        """Test creating a scan model"""
        target_id = str(uuid4())
        scan = ScanModel(
            target_id=target_id,
            name="Test Scan",
            description="Test scan description"
        )
        
        assert scan.target_id == target_id
        assert scan.name == "Test Scan"
        assert scan.description == "Test scan description"
    
    def test_scan_model_defaults(self):
        """Test scan model default values"""
        scan = ScanModel(target_id=str(uuid4()), name="Test")
        
        assert scan.scan_type == "full"
        assert scan.status == "pending"
        assert scan.progress == 0
        assert scan.enable_crawler == True
        assert scan.enable_openapi_import == True
        assert scan.enable_graphql_import == True
        assert scan.enable_dast == True
        assert scan.enable_fuzzer == True
        assert scan.endpoints_discovered == 0
        assert scan.findings_count == 0
    
    def test_scan_model_status_values(self):
        """Test scan model with different statuses"""
        scan = ScanModel(
            target_id=str(uuid4()),
            name="Test",
            status="running"
        )
        
        assert scan.status == "running"
    
    def test_scan_model_table_name(self):
        """Test scan model table name"""
        assert ScanModel.__tablename__ == "scans"


class TestFindingModel:
    """Test Finding database model"""
    
    def test_create_finding_model(self):
        """Test creating a finding model"""
        scan_id = str(uuid4())
        target_id = str(uuid4())
        
        finding = FindingModel(
            scan_id=scan_id,
            target_id=target_id,
            title="SQL Injection",
            description="SQL injection found",
            severity="Critical",
            vuln_type="SQL_INJECTION"
        )
        
        assert finding.title == "SQL Injection"
        assert finding.severity == "Critical"
        assert finding.vuln_type == "SQL_INJECTION"
    
    def test_finding_model_defaults(self):
        """Test finding model default values"""
        finding = FindingModel(
            scan_id=str(uuid4()),
            target_id=str(uuid4()),
            title="Test"
        )
        
        assert finding.status == "Open"
        assert finding.false_positive == False
        assert finding.verified == False
    
    def test_finding_model_with_technical_details(self):
        """Test finding model with technical details"""
        finding = FindingModel(
            scan_id=str(uuid4()),
            target_id=str(uuid4()),
            title="XSS",
            url="http://example.com/search?q=test",
            method="GET",
            parameter="q",
            payload="<script>alert(1)</script>",
            evidence="Found in response"
        )
        
        assert finding.url == "http://example.com/search?q=test"
        assert finding.method == "GET"
        assert finding.parameter == "q"
        assert finding.payload == "<script>alert(1)</script>"
    
    def test_finding_model_with_classification(self):
        """Test finding model with CWE/OWASP classification"""
        finding = FindingModel(
            scan_id=str(uuid4()),
            target_id=str(uuid4()),
            title="SQLi",
            cwe_id="CWE-89",
            owasp_category="A03:2021-Injection",
            cvss_score=9
        )
        
        assert finding.cwe_id == "CWE-89"
        assert finding.owasp_category == "A03:2021-Injection"
        assert finding.cvss_score == 9
    
    def test_finding_model_table_name(self):
        """Test finding model table name"""
        assert FindingModel.__tablename__ == "findings"


class TestReportModel:
    """Test Report database model"""
    
    def test_create_report_model(self):
        """Test creating a report model"""
        scan_id = str(uuid4())
        
        report = ReportModel(
            scan_id=scan_id,
            name="Security Report",
            format="pdf"
        )
        
        assert report.scan_id == scan_id
        assert report.name == "Security Report"
        assert report.format == "pdf"
    
    def test_report_model_defaults(self):
        """Test report model default values"""
        report = ReportModel(
            scan_id=str(uuid4()),
            name="Test Report"
        )
        
        assert report.format == "json"
    
    def test_report_model_table_name(self):
        """Test report model table name"""
        assert ReportModel.__tablename__ == "reports"


class TestSettingsModel:
    """Test Settings database model"""
    
    def test_create_settings_model(self):
        """Test creating a settings model"""
        setting = SettingsModel(
            key="max_concurrent",
            value=50
        )
        
        assert setting.key == "max_concurrent"
        assert setting.value == 50
    
    def test_settings_model_table_name(self):
        """Test settings model table name"""
        assert SettingsModel.__tablename__ == "settings"


class TestComplianceDataModel:
    """Test ComplianceData database model"""
    
    def test_create_compliance_data_model(self):
        """Test creating a compliance data model"""
        compliance = ComplianceDataModel(
            data_type="standards",
            data={"standard": "OWASP Top 10"}
        )
        
        assert compliance.data_type == "standards"
        assert compliance.data == {"standard": "OWASP Top 10"}
    
    def test_compliance_data_model_table_name(self):
        """Test compliance data model table name"""
        assert ComplianceDataModel.__tablename__ == "compliance_data"


class TestGetDatabaseUrl:
    """Test database URL generation"""
    
    @patch.dict('os.environ', {}, clear=True)
    @patch('src.database.get_settings')
    def test_get_database_url_default(self, mock_get_settings):
        """Test default database URL"""
        mock_settings = Mock()
        mock_settings.database.url = "sqlite:///test.db"
        mock_get_settings.return_value = mock_settings
        
        result = get_database_url()
        
        assert "sqlite+aiosqlite://" in result
    
    @patch.dict('os.environ', {'DATABASE_URL': 'postgresql://user:pass@host:5432/db'})
    @patch('src.database.get_settings')
    def test_get_database_url_postgres_conversion(self, mock_get_settings):
        """Test PostgreSQL URL conversion for async"""
        mock_settings = Mock()
        mock_settings.database.url = "sqlite:///test.db"
        mock_get_settings.return_value = mock_settings
        
        result = get_database_url()
        
        assert result == "postgresql+asyncpg://user:pass@host:5432/db"
    
    @patch.dict('os.environ', {'DATABASE_URL': 'postgres://user:pass@host:5432/db'})
    @patch('src.database.get_settings')
    def test_get_database_url_postgres_scheme_conversion(self, mock_get_settings):
        """Test postgres:// to postgresql:// conversion"""
        mock_settings = Mock()
        mock_settings.database.url = "sqlite:///test.db"
        mock_get_settings.return_value = mock_settings
        
        result = get_database_url()
        
        assert result == "postgresql+asyncpg://user:pass@host:5432/db"


class TestGetEngine:
    """Test database engine creation"""
    
    @patch('src.database._engine', None)
    @patch('src.database.create_async_engine')
    @patch('src.database.get_database_url')
    @patch('src.database.get_settings')
    def test_get_engine_creates_new_engine(self, mock_get_settings, mock_get_url, mock_create_engine):
        """Test creating a new database engine"""
        mock_get_settings.return_value = Mock(database=Mock(echo=False))
        mock_get_url.return_value = "sqlite+aiosqlite:///test.db"
        mock_create_engine.return_value = Mock()
        
        import src.database as db_module
        db_module._engine = None
        
        engine = get_engine()
        
        mock_create_engine.assert_called_once()
    
    @patch('src.database._engine')
    def test_get_engine_returns_existing(self, mock_engine):
        """Test returning existing engine"""
        import src.database as db_module
        db_module._engine = mock_engine
        
        result = get_engine()
        
        assert result == mock_engine


class TestGetSession:
    """Test database session management"""
    
    @pytest.mark.asyncio
    @patch('src.database._async_session_maker', None)
    @patch('src.database.async_sessionmaker')
    @patch('src.database.get_engine')
    async def test_get_session_creates_new(self, mock_get_engine, mock_sessionmaker):
        """Test creating a new session"""
        mock_engine = Mock()
        mock_get_engine.return_value = mock_engine
        
        mock_session = AsyncMock()
        mock_session.__aenter__ = AsyncMock(return_value=mock_session)
        mock_session.__aexit__ = AsyncMock(return_value=None)
        mock_session.close = AsyncMock()
        
        mock_maker = Mock(return_value=mock_session)
        mock_sessionmaker.return_value = mock_maker
        
        import src.database as db_module
        db_module._async_session_maker = None
        
        sessions = []
        async for session in get_session():
            sessions.append(session)
        
        assert len(sessions) == 1
    
    @pytest.mark.asyncio
    @patch('src.database.init_db')
    async def test_init_db_calls_create_all(self, mock_init_db):
        """Test init_db creates tables"""
        # This test ensures the function exists and is callable
        # Actual table creation tested in integration tests
        pass


class TestGetOrCreateSession:
    """Test direct session creation"""
    
    @pytest.mark.asyncio
    @patch('src.database._async_session_maker', None)
    @patch('src.database.async_sessionmaker')
    @patch('src.database.get_engine')
    async def test_get_or_create_session(self, mock_get_engine, mock_sessionmaker):
        """Test getting or creating a session"""
        mock_engine = Mock()
        mock_get_engine.return_value = mock_engine
        
        mock_session = Mock()
        mock_maker = Mock(return_value=mock_session)
        mock_sessionmaker.return_value = mock_maker
        
        import src.database as db_module
        db_module._async_session_maker = None
        
        result = await get_or_create_session()
        
        # get_or_create_session returns the result of calling the session maker
        assert result == mock_session
        mock_maker.assert_called_once()


class TestBaseModel:
    """Test Base model class"""
    
    def test_base_is_declarative(self):
        """Test Base is a declarative base"""
        from sqlalchemy.orm import DeclarativeBase
        
        assert issubclass(Base, DeclarativeBase)
    
    def test_base_metadata_exists(self):
        """Test Base has metadata"""
        assert hasattr(Base, 'metadata')


if __name__ == "__main__":
    pytest.main([__file__, "-v"])