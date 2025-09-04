# QRadar Regulatory Compliance Use Cases

## Overview

This document provides specialized Use Cases for regulatory compliance requirements including PCI DSS, NIS2 Directive, KRITIS Regulation, and other critical compliance frameworks. Each use case is mapped to specific regulatory requirements and includes implementation guidance for QRadar SIEM.

## Table of Contents

1. [PCI DSS Compliance Use Cases](#pci-dss-compliance-use-cases)
2. [NIS2 Directive Use Cases](#nis2-directive-use-cases)
3. [KRITIS Regulation Use Cases](#kritis-regulation-use-cases)
4. [GDPR Compliance Use Cases](#gdpr-compliance-use-cases)
5. [BSI IT-Grundschutz Use Cases](#bsi-it-grundschutz-use-cases)
6. [ISO 27001 Use Cases](#iso-27001-use-cases)
7. [NIST Cybersecurity Framework Use Cases](#nist-cybersecurity-framework-use-cases)

---

## PCI DSS Compliance Use Cases

### Use Case: PCI DSS 10.2 - Audit Trail Monitoring

**Requirement**: PCI DSS 10.2 - Implement automated audit trails for all system components

**Description**: Monitor and log all access to cardholder data and ensure comprehensive audit trails are maintained.

#### SIGMA Rule

```yaml
title: PCI DSS - Cardholder Data Access
id: pci-10.2-001-access-monitoring
status: stable
description: Monitors access to cardholder data environments (CDE)
references:
    - https://www.pcisecuritystandards.org/
tags:
    - pci_dss
    - requirement_10.2
    - cardholder_data
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4663  # Object Access
            - 4656  # Handle to Object Requested
        ObjectType: 'File'
    filter:
        ObjectName|contains:
            - 'cardholder'
            - 'payment'
            - 'card'
            - 'PCI'
    condition: selection and filter
falsepositives:
    - Legitimate application access
    - Scheduled maintenance
level: high
```

#### QRadar Custom Rule

```sql
SELECT
    username,
    sourceip,
    destinationip,
    filename,
    eventtime,
    eventname
FROM events
WHERE
    (eventname MATCHES '.*File.*Access.*' OR eventname MATCHES '.*Object.*Access.*') AND
    (filename MATCHES '.*cardholder.*' OR 
     filename MATCHES '.*payment.*' OR 
     filename MATCHES '.*card.*' OR
     filename MATCHES '.*PCI.*') AND
    eventtime > NOW() - INTERVAL '1' HOUR
```

---

## NIS2 Directive Use Cases

### Use Case: NIS2 - Critical Infrastructure Incident Detection

**Requirement**: NIS2 Article 21 - Cybersecurity incident reporting

**Description**: Detect cybersecurity incidents that significantly impact the security of network and information systems.

#### SIGMA Rule

```yaml
title: NIS2 - Critical Infrastructure Incident Detection
id: nis2-21-001-incident-detection
status: experimental
description: Detects incidents affecting critical infrastructure per NIS2 requirements
references:
    - https://eur-lex.europa.eu/legal-content/EN/TXT/?uri=CELEX%3A32022L2555
tags:
    - nis2_directive
    - article_21
    - critical_infrastructure
logsource:
    category: security
detection:
    selection:
        event_severity:
            - 'critical'
            - 'high'
        impact_assessment:
            - 'service_disruption'
            - 'data_compromise'
            - 'operational_impact'
    condition: selection
falsepositives:
    - Planned maintenance activities
    - False positive alerts
level: critical
```

---

## BSI IT-Grundschutz Use Cases

### Use Case: BSI Grundschutz - System Hardening Verification

**Requirement**: BSI IT-Grundschutz - SYS.1.1 General Server

**Description**: Verify system hardening measures are in place and detect configuration violations.

#### SIGMA Rule

```yaml
title: BSI Grundschutz - System Configuration Monitoring
id: bsi-grundschutz-sys11-001
status: stable
description: Monitors system configurations per BSI IT-Grundschutz requirements
references:
    - https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/it-grundschutz_node.html
tags:
    - bsi_grundschutz
    - sys_1_1
    - system_hardening
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4719  # System audit policy changed
            - 4902  # Per-user audit policy table created
            - 4907  # Audit policy changed
    condition: selection
falsepositives:
    - Authorized policy changes
    - System maintenance
level: high
```

---

## Implementation Framework

### Compliance Dashboard Configuration

**QRadar Dashboard Components:**
1. **Compliance Overview Widget**
   - Real-time compliance status
   - Critical violations count
   - Trend analysis

2. **Regulatory Incident Tracker**
   - Incident classification by regulation
   - Time to detection metrics
   - Reporting status

3. **Audit Trail Visualization**
   - Access patterns to regulated data
   - Administrative activities
   - Policy violations

### Automated Compliance Reporting

```sql
-- Daily Compliance Summary Report
SELECT
    'PCI DSS' as regulation,
    COUNT(*) as violations,
    AVG(magnitude) as avg_severity
FROM offenses
WHERE
    rules MATCHES '.*PCI.*' AND
    starttime > NOW() - INTERVAL '24' HOUR

UNION

SELECT
    'NIS2' as regulation,
    COUNT(*) as violations,
    AVG(magnitude) as avg_severity
FROM offenses
WHERE
    rules MATCHES '.*NIS2.*' AND
    starttime > NOW() - INTERVAL '24' HOUR
```

### Regular Compliance Assessment

**Monthly Tasks:**
- Review compliance use case effectiveness
- Update regulatory requirement mappings
- Validate log source coverage
- Performance optimization

**Quarterly Tasks:**
- Compliance gap analysis
- Regulatory update review
- Stakeholder reporting
- Process improvement assessment

---

*Last Updated: 2024-01-01*
*Next Review: 2024-04-01*
*Compliance Owner: Legal & Compliance Team*
*Technical Owner: Security Operations Team*