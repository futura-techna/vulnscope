"""
VulnScope - Zero Trust & Advanced Security Configuration
Configuration for recommended security detectors and compliance mappings
"""

from dataclasses import dataclass
from typing import Dict, List, Any
from enum import Enum


class SecurityGroup(str, Enum):
    """Security groups for detector organization"""
    APPLICATION_SECURITY = "Application Security"
    CLOUD_SECURITY = "Cloud Security"
    CRYPTOGRAPHIC = "Cryptographic Hygiene"
    ZERO_TRUST = "Zero Trust Architecture"
    NETWORK_SECURITY = "Endpoint & Network Security"
    SUPPLY_CHAIN = "Software Supply Chain Security"
    IAM = "Identity & Access Management"


@dataclass
class DetectorConfig:
    """Configuration for individual detectors"""
    name: str
    enabled: bool = True
    severity_threshold: str = "MEDIUM"
    timeout: int = 30
    concurrency: int = 5
    priority: int = 1  # 1-5, higher = more important


class AdvancedSecurityConfig:
    """Configuration for advanced security features"""
    
    def __init__(self):
        # Zero Trust Architecture Configuration (NIST SP 800-207)
        self.zero_trust_config = {
            'enabled': True,
            'enforce_mfa': True,
            'device_compliance_required': True,
            'network_segmentation': True,
            'anomaly_detection_enabled': True,
            'continuous_monitoring': True,
            'minimum_tls_version': 1.2,
            'cipher_suites': [
                'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
                'TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305',
                'TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384',
            ],
        }
        
        # Network Security Configuration
        self.network_config = {
            'port_scan_enabled': True,
            'ports_to_scan': [
                # Web services
                80, 443, 8080, 8443, 3000, 5000, 8000,
                # Database
                3306, 5432, 27017, 6379,
                # Remote access
                22, 23, 445, 3389,
                # Other services
                21, 25, 53, 110, 143, 389, 11211,
            ],
            'waf_detection_enabled': True,
            'service_discovery_enabled': True,
            'network_segmentation_analysis': True,
        }
        
        # Cloud Security Configuration
        self.cloud_config = {
            'aws_enabled': True,
            'azure_enabled': True,
            'gcp_enabled': True,
            'check_metadata_services': True,
            'check_storage_exposure': True,
            'check_iam_config': True,
            'check_encryption': True,
            'check_credential_exposure': True,
        }
        
        # Anomaly Detection Configuration
        self.anomaly_config = {
            'enabled': True,
            'volume_threshold_multiplier': 3.0,
            'location_change_alert': True,
            'privilege_escalation_alert': True,
            'data_exfiltration_detection': True,
            'behavioral_baseline_size': 100,
            'statistical_model': 'zscore',  # or 'isolation_forest', 'autoencoder'
        }
        
        # Compliance Configuration
        self.compliance_config = {
            'standards': [
                'NIST_SP_800_207',  # Zero Trust
                'NIST_SP_800_53',   # Security & Privacy Controls
                'PCI_DSS',
                'SOC_2',
                'HIPAA',
                'ISO_27001',
            ],
            'nist_zero_trust_mapping': True,
            'continuous_compliance': True,
        }
        
        # Detector registry with priorities
        self.detector_registry = self._build_detector_registry()
    
    def _build_detector_registry(self) -> Dict[SecurityGroup, List[DetectorConfig]]:
        """Build detector registry with priorities"""
        return {
            SecurityGroup.ZERO_TRUST: [
                DetectorConfig('ContextAwareAccessDetector', priority=5),
                DetectorConfig('DevicePostureDetector', priority=5),
                DetectorConfig('MicroSegmentationDetector', priority=5),
                DetectorConfig('AnomalyDetectionDetector', priority=4),
                DetectorConfig('EncryptionVerificationDetector', priority=5),
                DetectorConfig('VisibilitySensitivityDetector', priority=4),
            ],
            SecurityGroup.NETWORK_SECURITY: [
                DetectorConfig('PortScannerDetector', priority=4),
                DetectorConfig('ServiceDiscoveryDetector', priority=3),
                DetectorConfig('NetworkSegmentationDetector', priority=4),
                DetectorConfig('FirewallDetectionDetector', priority=3),
            ],
            SecurityGroup.CLOUD_SECURITY: [
                DetectorConfig('AWSMisconfigurationDetector', priority=4),
                DetectorConfig('AzureMisconfigurationDetector', priority=4),
                DetectorConfig('GCPMisconfigurationDetector', priority=4),
            ],
            SecurityGroup.CRYPTOGRAPHIC: [
                DetectorConfig('EncryptionVerificationDetector', priority=5),
            ],
            SecurityGroup.SUPPLY_CHAIN: [
                DetectorConfig('SupplyChainDetector', priority=4),
            ],
        }
    
    def get_enabled_detectors(self) -> List[str]:
        """Get list of enabled detectors"""
        detectors = []
        for group, configs in self.detector_registry.items():
            for config in configs:
                if config.enabled:
                    detectors.append(config.name)
        return detectors
    
    def get_high_priority_detectors(self) -> List[str]:
        """Get high-priority detectors"""
        detectors = []
        for group, configs in self.detector_registry.items():
            for config in configs:
                if config.enabled and config.priority >= 4:
                    detectors.append(config.name)
        return detectors
    
    def get_detector_config(self, detector_name: str) -> DetectorConfig:
        """Get configuration for specific detector"""
        for group, configs in self.detector_registry.items():
            for config in configs:
                if config.name == detector_name:
                    return config
        raise ValueError(f"Detector not found: {detector_name}")


# Global configuration instance
advanced_security_config = AdvancedSecurityConfig()
