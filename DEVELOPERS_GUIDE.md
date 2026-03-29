# VulnScope Advanced Detectors - Developer Guide

## 🎯 Overview

This guide explains how to use the newly implemented advanced security detectors in VulnScope.

---

## 📚 Quick Reference

### Import All Advanced Detectors

```python
# Zero Trust
from src.scanner.zero_trust_detectors import (
    ContextAwareAccessDetector,
    DevicePostureDetector,
    MicroSegmentationDetector,
    AnomalyDetectionDetector,
    EncryptionVerificationDetector,
    VisibilitySensitivityDetector,
)

# Network Security
from src.scanner.network_security_detectors import (
    PortScannerDetector,
    ServiceDiscoveryDetector,
    NetworkSegmentationDetector,
    FirewallDetectionDetector,
)

# Cloud
from src.scanner.cloud_advanced_detectors import (
    AWSMisconfigurationDetector,
    AzureMisconfigurationDetector,
    GCPMisconfigurationDetector,
)

# NIST Mapping
from src.scanner.nist_zero_trust_mapping import zero_trust_service

# Anomaly Detection
from src.scanner.anomaly_detection import (
    BehavioralAnalyzer,
    RiskScorer,
    ContinuousThreatAssessment,
)

# Configuration
from src.scanner.advanced_security_config import advanced_security_config
```

---

## 🔍 Using Individual Detectors

### Basic Detector Usage

All detectors implement the same interface:

```python
from src.scanner.zero_trust_detectors import ContextAwareAccessDetector
from src.core.models import Endpoint
import requests

# Create detector
detector = ContextAwareAccessDetector()

# Create endpoint
endpoint = Endpoint(
    url="https://api.example.com/api/users",
    method="GET",
    path="/api/users"
)

# Create session
session = requests.Session()

# Run detection
findings = detector.detect(endpoint, session)

# Process findings
for finding in findings:
    print(f"{finding.title}: {finding.severity}")
    print(f"Description: {finding.description}")
    print(f"Evidence: {finding.evidence}")
```

---

## 🛡️ Zero Trust Detectors

### ContextAwareAccessDetector

Verifies context-aware access controls (Pillar 1):

```python
from src.scanner.zero_trust_detectors import ContextAwareAccessDetector

detector = ContextAwareAccessDetector()

# Detects endpoints requiring but missing:
# - USER_IDENTITY: Authorization headers
# - DEVICE_POSTURE: X-Device-Compliance header
# - LOCATION: X-Location-Verified header
# - RISK_SCORE: X-Risk-Score header
# etc.
```

### DevicePostureDetector

Checks device compliance (Pillar 2):

```python
from src.scanner.zero_trust_detectors import DevicePostureDetector

detector = DevicePostureDetector()

# Checks for device compliance headers:
# - X-Device-Compliance
# - X-Device-Trust
# - X-Device-Health
# - X-Antivirus-Status
# - X-Firewall-Status
```

### MicroSegmentationDetector

Validates network segmentation (Pillar 3):

```python
from src.scanner.zero_trust_detectors import MicroSegmentationDetector

detector = MicroSegmentationDetector()

# Checks for:
# - Network boundary information
# - East-West traffic controls
# - mTLS requirements
# - Service mesh implementation
```

### EncryptionVerificationDetector

Validates encryption (Pillar 5):

```python
from src.scanner.zero_trust_detectors import EncryptionVerificationDetector

detector = EncryptionVerificationDetector()

# Checks for:
# - HTTPS/TLS in transit
# - TLS 1.2+
# - Strong cipher suites
# - Data at rest encryption
```

---

## 🌐 Network Security Detectors

### PortScannerDetector

Scans for open dangerous ports:

```python
from src.scanner.network_security_detectors import PortScannerDetector

detector = PortScannerDetector()

# Scans these ports:
# Web: 80, 443, 8080, 8443, 3000, 5000, 8000
# Databases: 3306 (MySQL), 5432 (PostgreSQL), 27017 (MongoDB)
# Caches: 6379 (Redis), 11211 (Memcached)
# Services: 21 (FTP), 22 (SSH), 23 (Telnet), 445 (SMB)
# And 10+ more...

findings = detector.detect(endpoint, session)
for finding in findings:
    if finding.severity == "CRITICAL":
        print(f"CRITICAL: {finding.evidence['service']} on port {finding.evidence['port']}")
```

### ServiceDiscoveryDetector

Identifies service versions:

```python
from src.scanner.network_security_detectors import ServiceDiscoveryDetector

detector = ServiceDiscoveryDetector()

# Detects:
# - Server: Apache/2.4.41
# - X-Powered-By: Express
# - X-AspNet-Version: 4.5.2
# - X-Framework-Version: 1.2.3

findings = detector.detect(endpoint, session)
```

### FirewallDetectionDetector

Identifies WAF/Firewall:

```python
from src.scanner.network_security_detectors import FirewallDetectionDetector

detector = FirewallDetectionDetector()

# Detects:
# - Cloudflare
# - AWS WAF
# - Azure WAF
# - Imperva
# - F5
# - Palo Alto
# - Akamai

findings = detector.detect(endpoint, session)
for finding in findings:
    if "detected" not in finding.title.lower():
        print(f"WARNING: {finding.title}")
```

---

## ☁️ Cloud Detectors

### AWSMisconfigurationDetector

Detects AWS security issues:

```python
from src.scanner.cloud_advanced_detectors import AWSMisconfigurationDetector

detector = AWSMisconfigurationDetector()

# Detects:
# - Metadata service exposure (169.254.169.254)
# - Publicly accessible S3 buckets
# - Leaked AWS credentials (AKIA* pattern)
# - Unencrypted RDS/DynamoDB/S3

findings = detector.detect(endpoint, session)
for finding in findings:
    print(f"AWS Issue: {finding.title}")
    print(f"Bucket: {finding.evidence.get('bucket_name')}")
```

### AzureMisconfigurationDetector

Detects Azure security issues:

```python
from src.scanner.cloud_advanced_detectors import AzureMisconfigurationDetector

detector = AzureMisconfigurationDetector()

# Detects:
# - Azure metadata service exposure
# - Publicly accessible blob containers
# - Overly permissive RBAC roles
# - Unencrypted storage

findings = detector.detect(endpoint, session)
```

### GCPMisconfigurationDetector

Detects GCP security issues:

```python
from src.scanner.cloud_advanced_detectors import GCPMisconfigurationDetector

detector = GCPMisconfigurationDetector()

# Detects:
# - GCP metadata service exposure
# - Publicly accessible storage buckets
# - Overly permissive IAM roles
# - Unencrypted data
```

---

## 🔬 Anomaly Detection

### BehavioralAnalyzer

Analyzes user behavior patterns:

```python
from src.scanner.anomaly_detection import (
    BehavioralAnalyzer,
    RequestProfile,
    AnomalyType,
)
from datetime import datetime

analyzer = BehavioralAnalyzer()

# Create request profile
profile = RequestProfile(
    timestamp=datetime.utcnow(),
    user_id="user123",
    ip_address="192.168.1.100",
    method="POST",
    path="/api/data",
    data_size=1000000,
    is_authenticated=True,
    privileges=["admin"]
)

# Analyze for anomalies
anomalies = analyzer.analyze_request(profile)

for anomaly in anomalies:
    print(f"Anomaly: {anomaly.anomaly_type.value}")
    print(f"Risk: {anomaly.risk_level.value}")
    print(f"Score: {anomaly.score}")
    print(f"Description: {anomaly.description}")
```

### RiskScorer

Calculates request risk scores:

```python
from src.scanner.anomaly_detection import RiskScorer

scorer = RiskScorer()

# Weights are:
# - authentication: 20%
# - authorization: 20%
# - encryption: 15%
# - logging: 10%
# - anomaly: 25%
# - compliance: 10%

risk_score = scorer.calculate_request_risk(profile, anomalies)
print(f"Risk Score: {risk_score}/100")

if risk_score >= 80:
    print("CRITICAL: Block request immediately")
elif risk_score >= 60:
    print("HIGH: Require MFA challenge")
elif risk_score >= 40:
    print("MEDIUM: Monitor closely")
```

### ContinuousThreatAssessment

Full threat assessment system:

```python
from src.scanner.anomaly_detection import ContinuousThreatAssessment

assessor = ContinuousThreatAssessment()

# Assess a request
assessment = assessor.assess_request(profile)

print(f"Risk Score: {assessment['risk_score']}")
print(f"Threat Level: {assessment['threat_level']}")
print(f"Recommendation: {assessment['recommendation']}")
print(f"Anomalies: {assessment['anomalies']}")

# Store threat events for analysis
if assessment['threat_level'] == 'CRITICAL':
    # Send to SIEM
    # Trigger incident response
    # Notify security team
    pass
```

---

## 🗺️ NIST Zero Trust Mapping

### Get vulnerability mappings

```python
from src.scanner.nist_zero_trust_mapping import zero_trust_service
from src.core.models import VulnerabilityType

# Get NIST mappings for a vulnerability
mappings = zero_trust_service.get_mappings_for_vulnerability(
    VulnerabilityType.BROKEN_AUTH
)

for mapping in mappings:
    print(f"Pillar: {mapping.pillar.value}")
    print(f"CWE IDs: {mapping.cwe_ids}")
    print(f"NIST Control: {mapping.nist_control}")
    print(f"Mitigation: {mapping.mitigation}")
    print(f"Priority: {mapping.priority}")
```

### Get pillar-specific assessment

```python
from src.scanner.nist_zero_trust_mapping import (
    zero_trust_service,
    NISTZeroTrustPillar,
)

# Assess specific pillar
assessment = zero_trust_service.get_pillar_assessment(
    NISTZeroTrustPillar.IDENTITY,
    findings  # list of findings
)

print(f"Pillar: {assessment['pillar']}")
print(f"Compliance Score: {assessment['compliance_score']}")
print(f"Status: {assessment['status']}")
print(f"Findings: {assessment['findings_count']}")
```

### Get comprehensive Zero Trust assessment

```python
# Get full Zero Trust maturity assessment
assessment = zero_trust_service.get_zero_trust_assessment(findings)

print(f"Overall Score: {assessment['overall_score']}/100")
print(f"Status: {assessment['compliance_status']}")
print(f"Total Findings: {assessment['total_findings']}")

for pillar_assessment in assessment['pillar_assessments']:
    print(f"\n{pillar_assessment['pillar']}: {pillar_assessment['compliance_score']}%")
    
print(f"\nRecommendations:")
for rec in assessment['recommendations']:
    print(f"- {rec}")
```

---

## ⚙️ Configuration

### Use Advanced Security Config

```python
from src.scanner.advanced_security_config import advanced_security_config

# Get all enabled detectors
enabled = advanced_security_config.get_enabled_detectors()
print(f"Enabled detectors: {enabled}")

# Get high-priority detectors
priority = advanced_security_config.get_high_priority_detectors()
print(f"High-priority detectors: {priority}")

# Get specific detector config
detector_config = advanced_security_config.get_detector_config('PortScannerDetector')
print(f"Timeout: {detector_config.timeout}s")
print(f"Concurrency: {detector_config.concurrency}")
```

### Modify configuration

```python
# Enable/disable features
advanced_security_config.zero_trust_config['enforce_mfa'] = True
advanced_security_config.network_config['port_scan_enabled'] = True
advanced_security_config.cloud_config['aws_enabled'] = True
advanced_security_config.anomaly_config['enabled'] = True

# Adjust thresholds
advanced_security_config.anomaly_config['volume_threshold_multiplier'] = 2.5
advanced_security_config.anomaly_config['behavioral_baseline_size'] = 50
```

---

## 🔌 Integration with Scanner

### Use Scanner with all detectors

```python
from src.scanner.scanner import Scanner
from src.core.models import Target, Scan

# Create scanner (includes all 30+ detectors)
scanner = Scanner()

# Run scan
target = Target(name="MyApp", url="https://api.example.com")
scan = Scan(target_id=target.id, name="Full Scan")

result = scanner.scan_endpoints(endpoints, target, scan)

# Analyze results with NIST mapping
from src.scanner.nist_zero_trust_mapping import zero_trust_service

assessment = zero_trust_service.get_zero_trust_assessment([
    {
        'vulnerability_type': f.vulnerability_type,
        'severity': f.severity
    } for f in result.findings
])

print(f"Zero Trust Score: {assessment['overall_score']}/100")
```

---

## 📊 Real-World Example

### Complete security assessment

```python
from src.scanner.scanner import Scanner
from src.scanner.anomaly_detection import ContinuousThreatAssessment, RequestProfile
from src.scanner.nist_zero_trust_mapping import zero_trust_service
from src.core.models import Target, Scan
from datetime import datetime

# 1. Run vulnerability scan
scanner = Scanner()
result = scanner.scan_endpoints(endpoints, target, scan)

# 2. Assess Zero Trust compliance
zt_assessment = zero_trust_service.get_zero_trust_assessment([
    {
        'vulnerability_type': f.vulnerability_type,
        'severity': f.severity
    } for f in result.findings
])

print("=== Zero Trust Assessment ===")
print(f"Score: {zt_assessment['overall_score']}/100")
print(f"Status: {zt_assessment['compliance_status']}")

# 3. Perform threat assessment on requests
assessor = ContinuousThreatAssessment()

for request in recent_requests:
    profile = RequestProfile(
        user_id=request['user_id'],
        ip_address=request['ip'],
        method=request['method'],
        path=request['path'],
        is_authenticated=request['authenticated']
    )
    
    threat = assessor.assess_request(profile)
    
    if threat['threat_level'] == 'CRITICAL':
        print(f"\n⚠️  CRITICAL THREAT DETECTED")
        print(f"   Risk: {threat['risk_score']}")
        print(f"   Recommendation: {threat['recommendation']}")

# 4. Generate recommendations
print("\n=== Recommendations ===")
for rec in zt_assessment['recommendations']:
    print(f"- {rec}")
```

---

## 🧪 Testing

### Unit test a detector

```python
import pytest
from src.scanner.zero_trust_detectors import ContextAwareAccessDetector
from src.core.models import Endpoint

def test_context_aware_access():
    detector = ContextAwareAccessDetector()
    endpoint = Endpoint(
        url="https://api.example.com/admin",
        method="GET",
        path="/admin"
    )
    
    import requests
    session = requests.Session()
    findings = detector.detect(endpoint, session)
    
    # Should find missing context controls
    assert len(findings) > 0
    assert "Context-Aware" in findings[0].title
```

---

## 📖 More Information

- See [SECURITY_RECOMMENDATIONS.md](../SECURITY_RECOMMENDATIONS.md) for complete feature documentation
- See [IMPLEMENTATION_SUMMARY.md](../IMPLEMENTATION_SUMMARY.md) for architecture overview
- See [DEPLOYMENT_CHECKLIST.md](../DEPLOYMENT_CHECKLIST.md) for deployment guide

---

**Last Updated:** March 29, 2026
**Version:** 2.5.0
**Status:** Production Ready
