# QRadar Configuration Directory

This directory contains IBM QRadar SIEM configurations, detection rules, searches, and compliance frameworks specifically designed for BSI IT-Grundschutz compliance and German regulatory requirements.

## Directory Structure

```
qradar/
├── compliance/                 # Regulatory compliance configurations
│   ├── bsi-grundschutz/       # BSI IT-Grundschutz specific rules and queries
│   ├── gdpr/                  # GDPR compliance monitoring
│   ├── iso-27001/             # ISO 27001 compliance framework
│   ├── kritis/                # KRITIS (Critical Infrastructure) requirements
│   ├── nis2/                  # NIS2 Directive compliance
│   ├── nist-csf/              # NIST Cybersecurity Framework
│   ├── pci-dss/               # PCI DSS compliance rules
│   └── compliance-dashboard-queries.sql
├── properties/                # Custom QRadar property definitions
│   └── custom_properties.conf
├── rules/                     # Detection rules (AQL format)
│   ├── brute_force_detection.sql
│   └── malware_c2_detection.sql
├── searches/                  # Saved searches and dashboard queries
│   └── bsi_compliance_dashboard.sql
├── standard/                  # Standard use cases by attack category
│   ├── account-anomaly/       # Account anomaly detection
│   ├── authentication/        # Authentication monitoring
│   ├── dns/                   # DNS analysis and monitoring
│   ├── exfiltration/          # Data exfiltration detection
│   ├── insider-threat/        # Insider threat detection
│   ├── lateral-movement/      # Lateral movement detection
│   ├── malware/               # Malware detection and analysis
│   ├── privilege-escalation/  # Privilege escalation detection
│   ├── reconnaissance/        # Network reconnaissance detection
│   ├── web-attacks/           # Web application attack detection
│   └── standard-dashboard-queries.sql
└── README.md                  # This file
```

## Overview

This QRadar configuration implementation provides:

- **BSI-Compliant Detection**: Rules aligned with BSI IT-Grundschutz requirements
- **Multi-Framework Support**: Compliance with GDPR, ISO 27001, KRITIS, NIS2, and more
- **Advanced Use Cases**: Comprehensive detection across the cyber kill chain
- **Dashboard Integration**: Pre-built searches and visualizations
- **Threat Intelligence**: Custom properties for enhanced detection capabilities

## Prerequisites

### QRadar Requirements
- **IBM QRadar SIEM**: Version 7.4.0 or higher
- **Admin Privileges**: System administrator access for rule deployment
- **Log Sources**: Configured log sources for comprehensive monitoring
- **Network Access**: Connectivity to threat intelligence feeds

### German Regulatory Context
- **BSI IT-Grundschutz**: Compliance with German Federal Office for Information Security standards
- **KRITIS**: Critical Infrastructure Protection requirements
- **NIS2**: Network and Information Systems Security Directive
- **GDPR**: General Data Protection Regulation compliance

## Compliance Frameworks

### BSI IT-Grundschutz (`compliance/bsi-grundschutz/`)

Implementation of BSI IT-Grundschutz building blocks:

#### Key Controls Covered:
- **SYS.1.1** - General Server (Allgemeiner Server)
- **NET.1.1** - Network Architecture and Design (Netzarchitektur und -design)
- **ORP.4** - Identity and Access Management (Identitäts- und Berechtigungsmanagement)
- **DER.1** - Detection of Security-relevant Events (Detektion von sicherheitsrelevanten Ereignissen)
- **SYS.2.1** - General Client (Allgemeiner Client)
- **NET.3.1** - Router and Switches (Router und Switches)

#### Use Cases:
- System configuration monitoring
- Network traffic analysis
- Identity and access monitoring
- Incident detection and response
- Vulnerability management tracking

### KRITIS (`compliance/kritis/`)

Critical Infrastructure Protection monitoring:

- **Availability Monitoring**: Service availability tracking
- **Integrity Checks**: Data and system integrity verification
- **Confidentiality Controls**: Sensitive data access monitoring
- **Incident Reporting**: Automated BSI incident reporting preparation

### GDPR (`compliance/gdpr/`)

Personal data protection compliance:

- **Data Access Monitoring**: Personal data access tracking
- **Breach Detection**: Automated breach detection and notification preparation
- **Consent Management**: Data processing consent monitoring
- **Right to be Forgotten**: Data deletion tracking

## Standard Use Cases (`standard/`)

### Authentication Monitoring (`authentication/`)
- **Failed Login Detection**: Brute force attack identification
- **Account Lockout Monitoring**: Suspicious account lockout patterns
- **Privileged Access Tracking**: Administrative account usage monitoring
- **Multi-Factor Authentication**: MFA bypass attempts

### Malware Detection (`malware/`)
- **C2 Communication**: Command and control traffic detection
- **File Hash Analysis**: Known malware signature detection
- **Behavioral Analysis**: Anomalous process behavior detection
- **Lateral Movement**: Malware propagation patterns

### Network Security (`dns/`, `exfiltration/`, `lateral-movement/`)
- **DNS Tunneling**: Covert channel detection
- **Data Exfiltration**: Large data transfer monitoring
- **Network Reconnaissance**: Port scanning and enumeration
- **Lateral Movement**: East-west traffic analysis

### Insider Threat (`insider-threat/`)
- **Privilege Abuse**: Unauthorized privilege usage
- **Data Access Anomalies**: Unusual data access patterns
- **Off-Hours Activity**: Suspicious after-hours access
- **Policy Violations**: Corporate policy breach detection

## Custom Properties (`properties/`)

### Key Property Definitions

#### Authentication Properties
```sql
authentication_event_category=select * from events where eventname MATCHES '.*[Aa]uth.*'
failed_login_count=select sourceip, count(*) from events where eventname='Authentication Failed' and eventtime > (NOW() - INTERVAL '1' HOUR) group by sourceip
```

#### BSI Grundschutz Properties
```sql
bsi_system_events=select * from events where eventname MATCHES '.*Policy.*' OR eventname MATCHES '.*Configuration.*'
privilege_event_category=select * from events where eventname MATCHES '.*[Pp]rivilege.*' OR eventname MATCHES '.*[Aa]dmin.*'
```

#### Threat Intelligence Properties
```sql
suspicious_domains=select * from flows where hostname MATCHES '.*\.tk' OR hostname MATCHES '.*\.ml' OR hostname MATCHES '.*\.bit'
apt_spearphish_indicators=select * from events where category=11002 and ("E-Mail Subject" MATCHES '.*[Dd]ringend.*' or "Sender Display Name" MATCHES '.*Bundesamt.*') and "Has Attachment"='true'
```

## Detection Rules (`rules/`)

### Sample Rules

#### Brute Force Detection
```sql
-- Detect multiple failed authentication attempts
SELECT
    sourceip,
    username,
    COUNT(*) as failed_attempts,
    MIN(devicetime) as first_attempt,
    MAX(devicetime) as last_attempt
FROM events
WHERE
    eventname = 'Authentication Failed' AND
    eventtime > NOW() - INTERVAL '5' MINUTE
GROUP BY sourceip, username
HAVING COUNT(*) >= 5
ORDER BY failed_attempts DESC
```

#### Malware C2 Detection
```sql
-- Detect potential command and control communications
SELECT
    sourceip,
    destinationip,
    COUNT(*) as connection_count,
    SUM(bytesreceived) as total_bytes
FROM flows
WHERE
    (destinationport IN (6667, 6668, 1337, 31337) OR
     hostname MATCHES '.*\.bit' OR
     hostname MATCHES '.*\.onion')
    AND eventtime > NOW() - INTERVAL '1' HOUR
GROUP BY sourceip, destinationip
HAVING connection_count > 10
```

## Dashboard Searches (`searches/`)

### BSI Compliance Dashboard

Comprehensive compliance monitoring dashboard queries:

- **Control Status Overview**: Real-time compliance status
- **Security Events Timeline**: Chronological security event visualization
- **Risk Assessment**: Automated risk scoring and prioritization
- **Incident Response Metrics**: Response time and effectiveness tracking

## Deployment Instructions

### 1. Prerequisites Check

```bash
# Verify QRadar version
curl -k -H "SEC: your-api-token" https://qradar-host/api/system/about

# Check available log sources
curl -k -H "SEC: your-api-token" https://qradar-host/api/config/event_sources/log_source_management/log_sources
```

### 2. Deploy Custom Properties

```bash
# Upload custom properties configuration
scp qradar/properties/custom_properties.conf admin@qradar-host:/opt/qradar/conf/custom_properties/

# Restart services (coordinate with QRadar administrator)
# systemctl restart hostcontext
```

### 3. Import Detection Rules

#### Using QRadar Console:
1. Navigate to **Log Activity** → **Rules**
2. Select **Actions** → **Create Rule**
3. Copy AQL content from `rules/*.sql` files
4. Configure rule parameters and offense creation

#### Using QRadar API:
```bash
# Create new rule via API
curl -k -X POST -H "SEC: your-api-token" \
  -H "Content-Type: application/json" \
  "https://qradar-host/api/analytics/rules" \
  -d @rule_definition.json
```

### 4. Create Saved Searches

1. Navigate to **Log Activity** → **Search**
2. Execute search queries from `searches/*.sql`
3. Save searches with descriptive names
4. Add to dashboards for visualization

### 5. Configure Compliance Dashboards

1. Navigate to **Dashboard** → **Create Dashboard**
2. Add widgets based on compliance framework requirements
3. Import queries from appropriate compliance subdirectories
4. Configure automatic refresh intervals

## Configuration Guidelines

### Rule Tuning

#### Threshold Adjustment
- **Development Environment**: Lower thresholds for comprehensive detection
- **Production Environment**: Tune thresholds to reduce false positives
- **High-Risk Assets**: Implement stricter detection criteria

#### Time Window Configuration
```sql
-- Short-term detection (real-time alerting)
eventtime > NOW() - INTERVAL '5' MINUTE

-- Medium-term analysis (correlation analysis)
eventtime > NOW() - INTERVAL '1' HOUR  

-- Long-term trending (compliance reporting)
eventtime > NOW() - INTERVAL '1' DAY
```

### Performance Optimization

#### Query Optimization
- Use indexed fields (sourceip, destinationip, eventtime)
- Limit time ranges appropriately
- Implement efficient GROUP BY clauses
- Use HAVING for post-aggregation filtering

#### Resource Management
- Schedule resource-intensive searches during off-peak hours
- Implement query result caching where appropriate
- Monitor system performance impact of custom rules

## Compliance Reporting

### Automated Reports

#### Daily Security Summary
- New security events count
- Top risk indicators
- Compliance status overview
- Action items requiring attention

#### Weekly Compliance Report
- BSI IT-Grundschutz control status
- Regulatory compliance metrics
- Trend analysis and recommendations
- False positive rate analysis

#### Monthly Executive Dashboard
- Overall security posture assessment
- Compliance framework status
- Risk trend analysis
- Budget and resource requirements

### Report Generation

```sql
-- Example: BSI Compliance Status Report
SELECT
    control_name,
    compliance_status,
    last_check_date,
    findings_count,
    remediation_status
FROM bsi_compliance_tracking
WHERE report_month = EXTRACT(MONTH FROM NOW())
ORDER BY risk_score DESC
```

## Integration with External Systems

### SIEM Integration
- **Splunk**: Export detection rules for Splunk correlation
- **ArcSight**: Convert AQL to ArcSight ESM rules
- **Elastic Stack**: Transform queries for Elasticsearch/Kibana

### Threat Intelligence Feeds
- **BSI CERT-Bund**: German federal threat intelligence
- **AlienVault OTX**: Open threat exchange integration
- **MISP**: Malware Information Sharing Platform
- **Commercial Feeds**: Integrate premium threat intelligence

### Compliance Tools
- **GRC Platforms**: Export compliance metrics
- **Audit Tools**: Automated evidence collection
- **Risk Management**: Integration with risk assessment tools

## Troubleshooting

### Common Issues

#### Rule Performance
```sql
-- Identify slow-running rules
SELECT rule_name, average_execution_time 
FROM qradar_rules_performance 
WHERE average_execution_time > 30000
ORDER BY average_execution_time DESC
```

#### False Positives
1. **Review Detection Logic**: Verify rule conditions
2. **Environmental Tuning**: Adjust thresholds for your environment
3. **Whitelist Creation**: Implement legitimate activity whitelists
4. **Context Enhancement**: Add additional context to improve accuracy

#### Compliance Gaps
1. **Control Mapping**: Verify proper BSI control implementation
2. **Log Source Coverage**: Ensure comprehensive log collection
3. **Detection Effectiveness**: Validate rule effectiveness with test scenarios
4. **Documentation Updates**: Maintain current compliance documentation

### Log Source Requirements

#### Windows Environment
- **Domain Controllers**: Authentication and authorization events
- **File Servers**: File access and modification monitoring
- **Workstations**: Endpoint security events
- **DNS Servers**: DNS query and response logging

#### Network Infrastructure  
- **Firewalls**: Allow/deny decision logging
- **Switches/Routers**: Network flow and configuration changes
- **IDS/IPS**: Intrusion detection and prevention alerts
- **Web Proxies**: Web traffic and content filtering

#### Linux/Unix Systems
- **System Logs**: Authentication, authorization, system events
- **Application Logs**: Custom application security events
- **Database Servers**: Database access and modification events
- **Web Servers**: HTTP access and error logs

## Security Considerations

### Rule Deployment Security
- **Change Management**: Follow established change control procedures
- **Testing**: Validate rules in development environment first
- **Rollback Procedures**: Maintain ability to quickly disable problematic rules
- **Documentation**: Document all rule changes and rationale

### Access Control
- **Principle of Least Privilege**: Limit QRadar access to necessary personnel
- **Role-Based Access**: Implement appropriate user role assignments  
- **API Security**: Secure API tokens and rotate regularly
- **Audit Logging**: Enable comprehensive audit logging for all changes

### Data Protection
- **Data Classification**: Classify and protect sensitive log data appropriately
- **Retention Policies**: Implement appropriate data retention policies
- **Encryption**: Ensure data encryption in transit and at rest
- **Privacy Compliance**: Maintain GDPR and other privacy regulation compliance

## Maintenance and Updates

### Regular Maintenance Tasks

#### Weekly
- Review rule performance metrics
- Analyze false positive rates
- Update threat intelligence feeds
- Check system resource utilization

#### Monthly
- Update detection rules based on new threats
- Review compliance status reports
- Conduct rule effectiveness assessments
- Update documentation as needed

#### Quarterly
- Comprehensive rule performance review
- Compliance framework updates
- Threat landscape assessment
- System capacity planning

### Version Control
- Maintain version control for all configurations
- Document changes with detailed commit messages
- Implement peer review process for rule changes
- Maintain rollback procedures for emergency situations

## Support and Documentation

### Internal Resources
- **QRadar Administrator Guide**: System-specific configuration details
- **Security Operations Playbook**: Incident response procedures
- **Compliance Matrix**: Mapping of rules to regulatory requirements
- **Training Materials**: Staff training and certification documentation

### External Resources
- **IBM QRadar Documentation**: Official IBM documentation and support
- **BSI IT-Grundschutz**: Official BSI guidance and requirements
- **MITRE ATT&CK Framework**: Threat modeling and detection strategies
- **NIST Cybersecurity Framework**: Implementation guidance and best practices

## Contributing

### Code Standards
- **Naming Conventions**: Use descriptive, consistent naming
- **Documentation**: Document all rules with purpose and context
- **Testing**: Validate rule effectiveness before deployment
- **Performance**: Consider performance impact of new rules

### Review Process
1. **Development**: Create and test rule in development environment
2. **Peer Review**: Review by senior security analyst
3. **Compliance Review**: Validation against regulatory requirements
4. **Deployment**: Coordinated deployment to production
5. **Monitoring**: Post-deployment effectiveness monitoring

---

**Last Updated**: January 2025  
**Version**: 2.0  
**Maintainer**: Security Operations Team  
**Classification**: Internal Use