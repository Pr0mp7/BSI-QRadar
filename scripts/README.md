# BSI-QRadar Scripts

This directory contains deployment and monitoring scripts for the BSI-compliant QRadar SIEM implementation. These scripts automate critical tasks including SIGMA rule deployment and BSI IT-Grundschutz compliance monitoring.

## Directory Structure

```
scripts/
├── deployment/          # Deployment automation scripts
│   └── deploy-sigma-rules.sh
├── monitoring/          # Compliance and system monitoring scripts
│   └── bsi-compliance-check.py
└── README.md           # This file
```

## Prerequisites

### System Requirements
- **Operating System**: Linux/Unix compatible system
- **Python**: Version 3.8 or higher (for monitoring scripts)
- **Bash**: Version 4.0 or higher (for deployment scripts)
- **Network Access**: Connectivity to QRadar SIEM instance

### Required Dependencies

#### For Deployment Scripts
```bash
# Install SIGMA tools
pip install sigmatools

# Verify installation
sigmac --help
```

#### For Monitoring Scripts
```bash
# Install Python dependencies
pip install pyyaml requests

# Optional: Create virtual environment
python -m venv bsi-qradar-env
source bsi-qradar-env/bin/activate
pip install -r requirements.txt
```

### QRadar Access Requirements
- Valid QRadar API token with appropriate permissions
- Network connectivity to QRadar Console
- Read/Write access to QRadar rules and configurations

## Deployment Scripts

### deploy-sigma-rules.sh

Converts SIGMA rules to QRadar AQL format and prepares them for deployment.

#### Description
This script automates the conversion of SIGMA detection rules to QRadar AQL (Ariel Query Language) format, making them compatible with IBM QRadar SIEM. It processes all SIGMA rules in the repository and generates corresponding QRadar detection rules.

#### Usage
```bash
# Basic usage (development environment)
./scripts/deployment/deploy-sigma-rules.sh

# Specify environment
./scripts/deployment/deploy-sigma-rules.sh production

# Run from any directory
bash /path/to/BSI-QRadar/scripts/deployment/deploy-sigma-rules.sh
```

#### Parameters
- `environment` (optional): Target environment (development, staging, production)
  - Default: `development`

#### Features
- **Automated Conversion**: Converts SIGMA YAML rules to QRadar AQL
- **Batch Processing**: Handles multiple rules simultaneously
- **Error Handling**: Graceful failure handling for problematic rules
- **Template Generation**: Creates AQL templates when direct conversion fails
- **Deployment Summary**: Generates detailed conversion reports
- **Directory Structure Preservation**: Maintains original rule organization

#### Output
- **Converted Rules**: Located in `qradar/rules/converted/`
- **Deployment Summary**: Timestamped reports in `qradar/rules/`
- **Console Output**: Real-time conversion status

#### Example Output
```bash
BSI-QRadar SIGMA Rules Deployment
==========================================
Environment: development
SIGMA Rules Directory: /path/to/sigma-rules
QRadar Rules Directory: /path/to/qradar/rules

Checking prerequisites...
✓ Prerequisites check passed

Converting SIGMA rules to QRadar AQL...
  ✓ Converted: network/lateral-movement/suspicious-smb-activity.yml
  ✓ Converted: windows/process-creation/malware-execution.yml
  ⚠ Failed: custom/complex-rule.yml (created template)

Conversion Summary:
  Total SIGMA rules found: 45
  Successfully converted: 42
```

#### Post-Deployment Steps
1. **Manual Review**: All converted rules require manual review
2. **Field Mapping Verification**: Ensure log source field mappings are correct
3. **Threshold Tuning**: Adjust detection thresholds for your environment
4. **Testing**: Validate rules in QRadar development environment
5. **Import to QRadar**: Use QRadar API or web interface to import rules

#### Troubleshooting
- **sigmac not found**: Install sigma tools with `pip install sigmatools`
- **Permission denied**: Ensure script has execute permissions (`chmod +x deploy-sigma-rules.sh`)
- **Conversion failures**: Review SIGMA rule syntax and QRadar compatibility

## Monitoring Scripts

### bsi-compliance-check.py

Automated BSI IT-Grundschutz compliance monitoring for QRadar SIEM.

#### Description
This Python script performs comprehensive compliance checks against BSI IT-Grundschutz requirements, specifically tailored for QRadar SIEM environments. It evaluates multiple security controls and generates detailed compliance reports.

#### Usage
```bash
# Basic usage with default configuration
python scripts/monitoring/bsi-compliance-check.py

# Use custom configuration file
python scripts/monitoring/bsi-compliance-check.py --config /path/to/config.yaml

# Generate JSON report
python scripts/monitoring/bsi-compliance-check.py --format json

# Save report to file
python scripts/monitoring/bsi-compliance-check.py --output compliance-report.txt

# Combined usage
python scripts/monitoring/bsi-compliance-check.py \
    --config production.yaml \
    --format json \
    --output /var/log/bsi-compliance-$(date +%Y%m%d).json
```

#### Parameters
- `--config`: Path to YAML configuration file (optional)
- `--format`: Output format - `text`, `json`, or `yaml` (default: `text`)
- `--output`: Output file path (default: stdout)

#### Monitored BSI Controls

##### SYS.1.1 - Allgemeiner Server
- Server hardening configuration validation
- Security monitoring status verification
- System update compliance checking
- Configuration change monitoring

##### NET.1.1 - Netzarchitektur und -design
- Network segmentation validation
- Access control verification
- Traffic monitoring compliance
- VLAN configuration assessment

##### ORP.4 - Identitäts- und Berechtigungsmanagement
- Identity management system integration
- Access logging compliance
- Privilege escalation monitoring
- Failed authentication tracking

##### DER.1 - Detektion von sicherheitsrelevanten Ereignissen
- Event detection capability assessment
- Incident response readiness
- Forensic capability validation
- Use case coverage analysis

#### Configuration File Format
```yaml
# config.yaml
qradar:
  host: "qradar.internal.domain"
  api_token: "your-api-token-here"
  verify_ssl: true
  timeout: 30

bsi_controls:
  SYS.1.1:
    name: "Allgemeiner Server"
    requirements:
      - secure_configuration
      - hardening_applied
      - monitoring_enabled
    thresholds:
      config_changes: 0
      monitoring_events: 1
  
  # Additional controls...
```

#### Sample Output

##### Text Format
```
BSI IT-Grundschutz Compliance Report
====================================
Report Date: 2025-01-15T10:30:45
Overall Status: COMPLIANT
Overall Score: 97.5%
Compliant Controls: 4/4

Control Details:

SYS.1.1 - Allgemeiner Server
Status: COMPLIANT (Score: 100%)
Findings:
  ✓ Server Hardening Configuration: No unauthorized configuration changes detected
  ✓ Security Monitoring Active: Security monitoring events being received
  ✓ System Updates Applied: System updates applied within last 7 days
```

##### JSON Format
```json
{
  "report_date": "2025-01-15T10:30:45.123456",
  "overall_status": "COMPLIANT",
  "overall_score": 97.5,
  "compliant_controls": 4,
  "total_controls": 4,
  "control_results": [
    {
      "control": "SYS.1.1",
      "name": "Allgemeiner Server",
      "status": "COMPLIANT",
      "score": 100,
      "findings": [...]
    }
  ],
  "recommendations": [
    "All BSI IT-Grundschutz controls are compliant - maintain current security posture"
  ]
}
```

#### Exit Codes
- `0`: Full compliance achieved
- `1`: Compliance issues detected
- `2`: Script execution error

#### Automation Integration

##### Cron Job Example
```bash
# Daily compliance check at 2 AM
0 2 * * * /usr/bin/python3 /path/to/bsi-compliance-check.py --config /etc/bsi-qradar/config.yaml --format json --output /var/log/compliance-$(date +\%Y\%m\%d).json
```

##### Systemd Timer Example
```ini
# /etc/systemd/system/bsi-compliance.timer
[Unit]
Description=BSI Compliance Check Timer

[Timer]
OnCalendar=daily
Persistent=true

[Install]
WantedBy=timers.target
```

## Integration with CI/CD

### GitLab CI/CD Example
```yaml
# .gitlab-ci.yml
bsi-compliance:
  stage: security
  script:
    - python scripts/monitoring/bsi-compliance-check.py --format json --output compliance-report.json
  artifacts:
    reports:
      junit: compliance-report.json
    paths:
      - compliance-report.json
  only:
    - schedules
```

### GitHub Actions Example
```yaml
# .github/workflows/bsi-compliance.yml
name: BSI Compliance Check
on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2 AM
jobs:
  compliance:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v2
      - name: Setup Python
        uses: actions/setup-python@v2
        with:
          python-version: '3.8'
      - name: Install dependencies
        run: pip install pyyaml
      - name: Run compliance check
        run: python scripts/monitoring/bsi-compliance-check.py --format json --output compliance-report.json
      - name: Upload results
        uses: actions/upload-artifact@v2
        with:
          name: compliance-report
          path: compliance-report.json
```

## Security Considerations

### Script Security
- **Secure Storage**: Store API tokens and credentials securely
- **Access Control**: Restrict script execution to authorized users
- **Audit Logging**: Enable logging for all script executions
- **Network Security**: Use encrypted connections (HTTPS/TLS)

### QRadar Integration
- **API Token Management**: Rotate tokens regularly
- **Least Privilege**: Grant minimal required permissions
- **SSL/TLS Verification**: Always verify SSL certificates
- **Rate Limiting**: Respect QRadar API rate limits

## Troubleshooting

### Common Issues

#### Permission Denied
```bash
# Fix script permissions
chmod +x scripts/deployment/deploy-sigma-rules.sh
```

#### Python Module Not Found
```bash
# Install missing dependencies
pip install pyyaml requests sigmatools
```

#### QRadar Connection Issues
1. **Verify Network Connectivity**
   ```bash
   ping your-qradar-host
   telnet your-qradar-host 443
   ```

2. **Test API Access**
   ```bash
   curl -k -H "SEC: your-api-token" https://your-qradar-host/api/help
   ```

3. **Check Firewall Rules**
   - Ensure ports 443 (HTTPS) and 32023 (QRadar Management) are accessible

#### SIGMA Conversion Failures
- **Invalid SIGMA Syntax**: Validate SIGMA rules using `sigmac --check`
- **Unsupported Features**: Some SIGMA features may not translate to QRadar
- **Missing Field Mappings**: Configure proper log source field mappings

### Log Files
- **Deployment Logs**: Check script output and deployment summaries
- **Compliance Logs**: Review compliance reports for detailed findings
- **QRadar Logs**: Monitor QRadar system logs for API errors

## Support and Maintenance

### Regular Tasks
1. **Weekly**: Review compliance reports for trends
2. **Monthly**: Update SIGMA rules and redeploy
3. **Quarterly**: Review and tune detection thresholds
4. **Annually**: Update BSI control requirements

### Monitoring
- Set up alerts for compliance failures
- Monitor script execution success/failure
- Track false positive rates from deployed rules

### Updates
- Keep SIGMA tools updated: `pip install --upgrade sigmatools`
- Monitor BSI IT-Grundschutz updates for new requirements
- Update QRadar API integrations as needed

## Contributing

When adding new scripts or modifying existing ones:

1. **Follow Naming Conventions**: Use descriptive, kebab-case filenames
2. **Add Documentation**: Include usage examples and parameter descriptions
3. **Error Handling**: Implement robust error handling and logging
4. **Testing**: Test scripts in development environment before production
5. **Security Review**: Ensure no hardcoded credentials or security vulnerabilities

## License

These scripts are part of the BSI-QRadar project and are subject to the same licensing terms. See the main repository LICENSE file for details.

---

**Last Updated**: January 2025  
**Version**: 1.0  
**Maintainer**: Security Operations Team