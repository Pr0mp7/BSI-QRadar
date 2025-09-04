# SIGMA Detection Rules

This directory contains SIGMA detection rules specifically designed for BSI-compliant QRadar SIEM deployments. These rules provide comprehensive threat detection capabilities aligned with German regulatory requirements and cybersecurity best practices.

## Overview

SIGMA is a generic signature format for SIEM systems that allows for writing detection rules in a vendor-agnostic way. These rules can be converted to various SIEM query languages, including QRadar AQL, Splunk SPL, Elastic Query DSL, and others.

## Directory Structure

```
sigma-rules/
├── apt/                        # Advanced Persistent Threat detection
│   └── spear_phishing_government.yml
├── compliance/                 # Regulatory compliance rules
│   ├── bsi-grundschutz/       # BSI IT-Grundschutz specific rules
│   │   └── bsi-sys11-system-configuration.yml
│   ├── gdpr/                  # GDPR compliance monitoring
│   ├── iso-27001/             # ISO 27001 compliance rules
│   ├── kritis/                # KRITIS requirements
│   ├── nis2/                  # NIS2 directive compliance
│   ├── nist-csf/              # NIST Cybersecurity Framework
│   ├── pci-dss/               # PCI DSS compliance
│   └── pci_dss_cardholder_access.yml
├── standard/                  # Standard detection use cases
│   ├── account-anomaly/       # Account behavior anomalies
│   ├── authentication/        # Authentication monitoring
│   ├── dns/                   # DNS analysis and monitoring
│   ├── exfiltration/          # Data exfiltration detection
│   ├── insider-threat/        # Insider threat detection
│   ├── lateral-movement/      # Network lateral movement
│   ├── malware/               # Malware detection and analysis
│   ├── privilege-escalation/  # Privilege escalation detection
│   ├── reconnaissance/        # Network reconnaissance
│   ├── web-attacks/           # Web application attacks
│   ├── brute_force_authentication.yml
│   └── malware_c2_communication.yml
└── README.md                  # This file
```

## Prerequisites

### SIGMA Tools Installation

#### Python Environment
```bash
# Install SIGMA tools
pip install sigmatools

# Verify installation
sigmac --help
sigma --help
```

#### Alternative Installation Methods
```bash
# Using conda
conda install -c conda-forge sigma

# Using Docker
docker pull sigmahq/sigma:latest
```

### Required Dependencies
- **Python 3.8+**: Core runtime environment
- **PyYAML**: YAML processing for rule parsing
- **Requests**: HTTP client for threat intelligence feeds
- **Jinja2**: Template processing for rule conversion

## SIGMA Rule Categories

### APT Detection (`apt/`)

Advanced Persistent Threat detection rules targeting sophisticated attack campaigns.

#### Key Features:
- **Government-Targeted Attacks**: Spear-phishing against government entities
- **APT Techniques**: MITRE ATT&CK framework alignment
- **German Context**: Rules specific to German threat landscape
- **Multi-Stage Detection**: Kill chain coverage from initial access to exfiltration

#### Example: APT Spear-Phishing Detection
```yaml
title: APT Spear-Phishing gegen Regierungsmitarbeiter
id: apt-spearphish-gov-001
description: Erkennt verdächtige E-Mails mit APT-typischen Spear-Phishing-Indikatoren
tags:
    - attack.initial_access
    - attack.t1566.001
    - apt.spearphishing
detection:
    selection_subject:
        subject|contains:
            - 'Dringend'
            - 'Vertraulich' 
            - 'Bundesamt'
    selection_attachment:
        has_attachment: true
        attachment_type: ['.exe', '.docm', '.xlsm']
    condition: selection_subject and selection_attachment
level: high
```

### Compliance Rules (`compliance/`)

Regulatory compliance monitoring aligned with German and European frameworks.

#### BSI IT-Grundschutz (`bsi-grundschutz/`)

Rules implementing BSI IT-Grundschutz building blocks:

##### SYS.1.1 - Allgemeiner Server
- System configuration monitoring
- Unauthorized configuration changes
- Security hardening validation
- Service availability tracking

##### NET.1.1 - Netzarchitektur und -design
- Network segmentation violations
- Unauthorized network access
- Traffic pattern anomalies
- Firewall rule violations

##### ORP.4 - Identitäts- und Berechtigungsmanagement
- Identity lifecycle management
- Privilege escalation detection
- Access control violations
- Authentication anomalies

##### DER.1 - Detektion von sicherheitsrelevanten Ereignissen
- Security event correlation
- Incident detection and classification
- Threat hunting support
- Forensic evidence collection

#### KRITIS (`kritis/`)

Critical Infrastructure Protection requirements:

- **Availability Monitoring**: Service uptime and performance
- **Integrity Validation**: Data and system integrity checks
- **Incident Reporting**: BSI-KRITIS incident notification preparation
- **Risk Assessment**: Automated risk scoring and prioritization

#### GDPR (`gdpr/`)

Personal data protection compliance:

- **Data Access Monitoring**: Personal data access tracking
- **Breach Detection**: Automated breach identification
- **Consent Tracking**: Data processing consent monitoring
- **Data Subject Rights**: Right to erasure and portability monitoring

#### NIS2 (`nis2/`)

Network and Information Systems Security Directive:

- **Cybersecurity Measures**: Mandatory security controls
- **Incident Reporting**: 24-hour reporting requirements
- **Risk Management**: Comprehensive risk assessment
- **Supply Chain Security**: Third-party risk monitoring

#### PCI DSS (`pci-dss/`)

Payment Card Industry Data Security Standard:

```yaml
title: PCI DSS - Cardholder Data Access
id: pci-10.2-001-access-monitoring
description: Monitors access to cardholder data environments
tags:
    - pci_dss
    - requirement_10.2
detection:
    selection:
        EventID: [4663, 4656]  # Object Access
        ObjectName|contains: ['cardholder', 'payment', 'card']
    condition: selection
level: high
```

### Standard Detection Rules (`standard/`)

Comprehensive threat detection across the cyber kill chain.

#### Authentication Monitoring (`authentication/`)

##### Brute Force Detection
```yaml
title: Brute Force Authentication Attack
id: 2e65ca67-31c2-4f7e-b4e0-7e123456789a
description: Detects brute force attacks via failed login attempts
detection:
    selection:
        EventID: 4625  # Failed Authentication
    timeframe: 5m
    count: 5
level: medium
```

##### Key Use Cases:
- **Failed Login Clustering**: Multiple failed attempts from same source
- **Account Lockout Patterns**: Suspicious lockout behaviors
- **Credential Stuffing**: Automated credential testing
- **Password Spraying**: Low-and-slow password attacks

#### Malware Detection (`malware/`)

##### C2 Communication Detection
```yaml
title: Malware Command and Control Communication
detection:
    selection_ports:
        DestinationPort: [6667, 6668, 1337, 31337]
    selection_domains:
        query|endswith: ['.bit', '.onion']
    condition: selection_ports or selection_domains
level: high
```

##### Detection Categories:
- **Command & Control**: C2 channel identification
- **Lateral Movement**: Malware propagation patterns
- **Data Exfiltration**: Suspicious outbound communications
- **Persistence Mechanisms**: Malware persistence techniques

#### Network Security (`dns/`, `reconnaissance/`, `lateral-movement/`)

##### DNS Analysis
- **DNS Tunneling**: Covert channel detection
- **Domain Generation Algorithms**: DGA domain identification
- **DNS Over HTTPS**: DoH abuse detection
- **Suspicious TLD Usage**: Malicious top-level domains

##### Reconnaissance Detection
- **Port Scanning**: Network enumeration attempts
- **Service Discovery**: Service fingerprinting activities
- **Vulnerability Scanning**: Automated vulnerability assessments
- **OSINT Collection**: Open source intelligence gathering

#### Insider Threat (`insider-threat/`)

##### Behavioral Analytics
- **Data Access Anomalies**: Unusual data access patterns
- **Off-Hours Activity**: Suspicious after-hours access
- **Privilege Abuse**: Unauthorized privilege usage
- **Policy Violations**: Corporate policy breaches

## Rule Development Guidelines

### SIGMA Rule Structure

#### Required Fields
```yaml
title: [Descriptive rule name]
id: [Unique identifier (UUID recommended)]
description: [Detailed rule description]
author: [Rule author/team]
date: [Creation date (YYYY/MM/DD)]
tags: [MITRE ATT&CK and custom tags]
logsource: [Log source specification]
detection: [Detection logic]
falsepositives: [Known false positive scenarios]
level: [Risk level: low/medium/high/critical]
```

#### Detection Logic Structure
```yaml
detection:
    selection: [Primary selection criteria]
    filter: [Exclusion criteria (optional)]
    condition: [Boolean logic combining selections]
    timeframe: [Time window for correlation (optional)]
    count: [Event count threshold (optional)]
```

### Rule Quality Standards

#### 1. Accuracy Requirements
- **Low False Positives**: < 5% false positive rate in production
- **High Detection Rate**: > 90% detection rate for target scenarios
- **Performance Optimization**: Query execution time < 30 seconds
- **Resource Efficiency**: Minimal system impact during execution

#### 2. Documentation Standards
```yaml
# Complete example with all required fields
title: BSI SYS.1.1 - Unauthorized System Configuration Change
id: bsi-sys11-config-change-001
status: stable
description: |
    Detects unauthorized changes to system configuration files
    in compliance with BSI IT-Grundschutz SYS.1.1 requirements
author: BSI Compliance Team
date: 2024/01/01
modified: 2024/01/15
references:
    - https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/it-grundschutz_node.html
tags:
    - bsi.sys.1.1
    - attack.defense_evasion
    - attack.t1562.001
logsource:
    product: windows
    service: system
detection:
    selection:
        EventID: 4719  # System audit policy change
        SubjectUserSid: 'S-1-5-18'  # SYSTEM account
    filter:
        ProcessName|endswith: '\svchost.exe'
    condition: selection and not filter
falsepositives:
    - Legitimate system updates
    - Authorized configuration management tools
level: medium
```

#### 3. Testing Requirements
- **Unit Testing**: Individual rule validation
- **Integration Testing**: SIEM platform compatibility
- **Performance Testing**: Resource impact assessment
- **False Positive Testing**: Baseline environment validation

### Rule Conversion Process

#### 1. QRadar AQL Conversion
```bash
# Convert SIGMA rule to QRadar AQL
sigmac -t qradar rule.yml

# Convert with custom configuration
sigmac -t qradar -c qradar-config.yml rule.yml

# Batch conversion
find . -name "*.yml" -exec sigmac -t qradar {} \;
```

#### 2. Other SIEM Platforms
```bash
# Splunk SPL
sigmac -t splunk rule.yml

# Elastic Query DSL  
sigmac -t elasticsearch-ecs rule.yml

# Microsoft Sentinel KQL
sigmac -t azure-sentinel rule.yml
```

#### 3. Custom Backend Configuration
```yaml
# qradar-config.yml
title: QRadar Configuration
backends:
  qradar:
    identifier: qradar
    config:
      rulecomment: '-- SIGMA Rule: %s'
      alerting: true
      es_dsl_output: false
```

## Deployment Instructions

### 1. Automated Deployment

#### Using Deployment Script
```bash
# Run the automated deployment script
./scripts/deployment/deploy-sigma-rules.sh production

# Deploy specific rule categories
./scripts/deployment/deploy-sigma-rules.sh --category compliance

# Deploy with custom configuration
./scripts/deployment/deploy-sigma-rules.sh --config custom-config.yml
```

#### Deployment Process:
1. **Rule Validation**: SIGMA syntax validation
2. **Conversion**: Target platform conversion (QRadar AQL)
3. **Testing**: Rule logic verification
4. **Import**: SIEM platform import
5. **Monitoring**: Post-deployment validation

### 2. Manual Deployment

#### Individual Rule Deployment
```bash
# Validate SIGMA rule
sigma check rule.yml

# Convert to QRadar format
sigmac -t qradar rule.yml > rule.sql

# Import to QRadar (via API or console)
curl -X POST -H "SEC: $API_TOKEN" \
  "https://qradar-host/api/analytics/rules" \
  -d @rule-definition.json
```

### 3. CI/CD Integration

#### GitLab CI Pipeline
```yaml
sigma-deployment:
  stage: deploy
  script:
    - pip install sigmatools
    - ./scripts/deployment/deploy-sigma-rules.sh
  rules:
    - changes:
        - sigma-rules/**/*.yml
```

#### GitHub Actions Workflow
```yaml
name: SIGMA Rule Deployment
on:
  push:
    paths:
      - 'sigma-rules/**/*.yml'
jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Deploy SIGMA Rules
        run: ./scripts/deployment/deploy-sigma-rules.sh
```

## Rule Tuning and Optimization

### Performance Optimization

#### Query Optimization Techniques
```yaml
# Use indexed fields for better performance
detection:
    selection:
        EventID: 4625        # Indexed field
        SourceIP: 10.0.0.0/8 # Network range instead of wildcards
        
# Avoid expensive operations
detection:
    selection:
        ProcessName|endswith: '.exe'  # Better than |contains
        CommandLine|re: '^.*malware.*$'  # Use anchored regex
```

#### Time Window Optimization
```yaml
# Short time windows for real-time detection
timeframe: 5m   # 5 minutes for brute force
timeframe: 1h   # 1 hour for data exfiltration
timeframe: 24h  # 24 hours for insider threat patterns
```

### False Positive Reduction

#### Whitelist Implementation
```yaml
detection:
    selection:
        EventID: 4625
        SourceIP: '*'
    filter:
        SourceIP: 
            - 10.0.0.0/8     # Internal networks
            - 192.168.0.0/16 # Private networks
        ProcessName|endswith: 
            - '\backup.exe'   # Legitimate processes
            - '\monitoring.exe'
    condition: selection and not filter
```

#### Context Enhancement
```yaml
# Add business context to reduce false positives
detection:
    selection:
        EventID: 4648  # Explicit logon
        TargetUserName: 'admin'
    business_hours:
        TimeGenerated: '08:00-18:00'  # Business hours filter
    condition: selection and not business_hours
```

## Threat Intelligence Integration

### IOC Integration

#### Domain Indicators
```yaml
detection:
    selection:
        query|endswith:
            - '.tk'      # Suspicious TLDs
            - '.ml'
            - '.bit'
    threat_intel:
        query: '%THREAT_DOMAINS%'  # External threat feed
    condition: selection or threat_intel
```

#### Hash-Based Detection
```yaml
detection:
    selection:
        Hashes|contains:
            - 'SHA256=a1b2c3...'  # Known malware hashes
            - 'MD5=d4e5f6...'
    condition: selection
```

### MISP Integration

#### Attribute Correlation
```yaml
# MISP attribute integration
detection:
    misp_indicators:
        SourceIP: '%MISP_IPS%'
        ProcessName: '%MISP_FILENAMES%'
        query: '%MISP_DOMAINS%'
    condition: misp_indicators
```

## Quality Assurance

### Rule Testing Framework

#### Unit Tests
```bash
# Test individual rules
sigma test rule.yml

# Validate rule syntax
sigma validate --strict rule.yml

# Performance benchmarking
sigma benchmark rule.yml
```

#### Integration Tests
```python
# Python test framework example
import sigma
import unittest

class TestSigmaRules(unittest.TestCase):
    def test_brute_force_rule(self):
        rule = sigma.load_rule('brute_force_authentication.yml')
        result = rule.test_against_logs('test-logs.json')
        self.assertTrue(result.detection_rate > 0.9)
        self.assertTrue(result.false_positive_rate < 0.05)
```

### Continuous Monitoring

#### Rule Effectiveness Metrics
- **Detection Rate**: Percentage of actual attacks detected
- **False Positive Rate**: Percentage of benign events flagged
- **Mean Time to Detection**: Average detection latency
- **Rule Performance**: Query execution time and resource usage

#### Automated Reporting
```bash
# Generate rule effectiveness report
./scripts/monitoring/rule-effectiveness-report.py --period 30d

# Export metrics to monitoring system
./scripts/monitoring/export-metrics.py --target prometheus
```

## Maintenance and Updates

### Regular Maintenance Tasks

#### Weekly Tasks
- Review new threat intelligence feeds
- Analyze false positive trends
- Update rule effectiveness metrics
- Performance optimization review

#### Monthly Tasks
- Update MITRE ATT&CK mappings
- Review and update compliance mappings
- Conduct rule performance analysis
- Update threat hunting rules

#### Quarterly Tasks
- Comprehensive rule effectiveness review
- Threat landscape assessment
- Rule retirement and optimization
- Training material updates

### Version Control

#### Git Workflow
```bash
# Feature branch for new rules
git checkout -b feature/new-apt-rules

# Commit with detailed messages
git commit -m "Add APT spear-phishing detection for government entities

- Implements detection for German government-targeted campaigns
- Covers MITRE ATT&CK T1566.001
- Includes German-specific indicators
- Tested against APT simulation data"

# Pull request for peer review
gh pr create --title "New APT Detection Rules"
```

#### Change Management
- **Peer Review**: All rule changes require peer review
- **Testing**: Mandatory testing in development environment
- **Documentation**: Update documentation for all changes
- **Rollback**: Maintain rollback procedures for production issues

## Support and Troubleshooting

### Common Issues

#### Rule Conversion Errors
```bash
# Debug conversion issues
sigmac -t qradar --debug rule.yml

# Check SIGMA syntax
sigma check --verbose rule.yml

# Validate against schema
sigma validate --schema-path schema/ rule.yml
```

#### Performance Issues
```bash
# Analyze rule performance
./scripts/monitoring/rule-performance-analysis.py

# Identify slow rules
grep "execution_time" /var/log/qradar/rules.log | sort -k3 -nr
```

#### False Positive Management
```bash
# Analyze false positives
./scripts/monitoring/false-positive-analysis.py --rule-id rule-001

# Generate tuning recommendations
./scripts/monitoring/tuning-recommendations.py --environment production
```

### Support Resources

#### Internal Documentation
- **Rule Development Guide**: Internal development standards
- **Testing Procedures**: QA and validation processes
- **Deployment Runbook**: Step-by-step deployment procedures
- **Troubleshooting Guide**: Common issues and solutions

#### External Resources
- **SIGMA Official Documentation**: https://github.com/SigmaHQ/sigma
- **MITRE ATT&CK Framework**: https://attack.mitre.org/
- **BSI IT-Grundschutz**: https://www.bsi.bund.de/
- **German CERT-Bund**: https://www.cert-bund.de/

## Contributing

### Contribution Guidelines

#### Rule Development Process
1. **Issue Creation**: Create GitHub issue for new rule requirements
2. **Rule Development**: Develop rule following established standards
3. **Testing**: Validate rule in development environment
4. **Documentation**: Update relevant documentation
5. **Peer Review**: Submit pull request for review
6. **Deployment**: Deploy to production after approval

#### Code Standards
- **YAML Format**: Follow SIGMA YAML specification
- **Naming Convention**: Use descriptive, consistent naming
- **Documentation**: Include comprehensive documentation
- **Testing**: Provide test cases and expected results

#### Review Criteria
- **Technical Accuracy**: Rule logic correctness
- **Performance Impact**: Resource utilization assessment
- **Compliance Alignment**: Regulatory requirement mapping
- **Documentation Quality**: Clear, comprehensive documentation

---

**Last Updated**: January 2025  
**Version**: 2.0  
**Maintainer**: Security Detection Team  
**Classification**: Internal Use