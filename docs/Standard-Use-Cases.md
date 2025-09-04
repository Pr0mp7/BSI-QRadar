# QRadar Standard Use Cases

## Overview

This document provides comprehensive Use Cases for IBM QRadar SIEM implementation, following industry best practices and compliance requirements. Each Use Case includes SIGMA rules, QRadar-specific rules and properties, and log source configurations.

## Table of Contents

1. [Use Case 1: Brute Force Authentication Attacks](#use-case-1-brute-force-authentication-attacks)
2. [Use Case 2: Privilege Escalation Detection](#use-case-2-privilege-escalation-detection)
3. [Use Case 3: Malware Communication Detection](#use-case-3-malware-communication-detection)
4. [Use Case 4: Data Exfiltration Detection](#use-case-4-data-exfiltration-detection)
5. [Use Case 5: Lateral Movement Detection](#use-case-5-lateral-movement-detection)
6. [Use Case 6: Insider Threat Detection](#use-case-6-insider-threat-detection)
7. [Use Case 7: Web Application Attacks](#use-case-7-web-application-attacks)
8. [Use Case 8: DNS Tunneling Detection](#use-case-8-dns-tunneling-detection)
9. [Use Case 9: Account Anomaly Detection](#use-case-9-account-anomaly-detection)
10. [Use Case 10: Network Scanning Detection](#use-case-10-network-scanning-detection)

---

## Use Case 1: Brute Force Authentication Attacks

### Description
Detects multiple failed authentication attempts from the same source IP address within a specified time window, indicating potential brute force attacks.

### SIGMA Rule

```yaml
title: Brute Force Authentication Attack
id: 2e65ca67-31c2-4f7e-b4e0-7e123456789a
status: experimental
description: Detects brute force authentication attacks based on multiple failed login attempts
author: Security Team
date: 2024/01/01
modified: 2024/01/01
tags:
    - attack.credential_access
    - attack.t1110
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4625
    condition: selection
    timeframe: 5m
    count: 5
falsepositives:
    - Legitimate user with forgotten password
    - Service account misconfigurations
level: medium
```

### QRadar Custom Rule

```sql
SELECT
    sourceip,
    username,
    COUNT(*) as failed_attempts
FROM events
WHERE
    eventname = 'Authentication Failed' AND
    eventtime > NOW() - INTERVAL '5' MINUTE
GROUP BY sourceip, username
HAVING COUNT(*) >= 5
```

### QRadar Properties

```
# Custom Property: Authentication Event Category
authentication_event_category=select * from events where eventname MATCHES '.*[Aa]uth.*'

# Custom Property: Failed Login Count
failed_login_count=select sourceip, count(*) from events where eventname='Authentication Failed' and eventtime > (NOW() - INTERVAL '1' HOUR) group by sourceip
```

### Log Sources Configuration

**Required Log Sources:**
- Windows Security Event Logs (Event ID 4625)
- Linux Authentication Logs (/var/log/auth.log)
- Active Directory Domain Controllers
- VPN Concentrators
- Web Application Authentication Logs

**QRadar DSM Configuration:**
```
# Windows Security Event Log DSM
log_source_type_id=12
log_source_extension_id=Windows Security Event Log
protocol_type_id=0
gateway=false
enabled=true
```

### Detection Logic

1. **Threshold**: 5 failed authentication attempts within 5 minutes
2. **Correlation Fields**: Source IP, Username, Destination Host
3. **Time Window**: Rolling 5-minute window
4. **Baseline**: Normal authentication patterns per user/IP

### Response Procedures

**Automated Actions:**
- Block source IP at firewall
- Disable affected user account
- Generate high-priority offense

**Manual Investigation:**
- Verify source IP reputation
- Check for concurrent successful logins
- Review user account status
- Analyze authentication logs for patterns

### Metrics and KPIs

- Number of brute force attempts per day
- Average time to detection
- False positive rate
- Source IP geographic distribution

---

## Use Case 2: Privilege Escalation Detection

### Description
Identifies unauthorized attempts to escalate privileges within the network, focusing on suspicious administrative activities and privilege changes.

### SIGMA Rule

```yaml
title: Privilege Escalation Detection
id: 3f76db78-42d3-5g8f-c5f1-8f234567890b
status: experimental
description: Detects potential privilege escalation attempts
author: Security Team
date: 2024/01/01
modified: 2024/01/01
tags:
    - attack.privilege_escalation
    - attack.t1068
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection1:
        EventID: 4672
        PrivilegeList|contains: 'SeDebugPrivilege'
    selection2:
        EventID: 4624
        LogonType: 2
        TokenElevationType: 'TokenElevationTypeDefault'
    condition: selection1 or selection2
falsepositives:
    - Legitimate administrative activities
    - Scheduled maintenance tasks
level: high
```

### QRadar Custom Rule

```sql
SELECT
    username,
    sourceip,
    destinationip,
    eventname,
    eventtime
FROM events
WHERE
    (eventname MATCHES '.*Privilege.*' OR
     eventname MATCHES '.*Administrator.*' OR
     eventname MATCHES '.*Elevation.*') AND
    eventtime > NOW() - INTERVAL '1' HOUR
ORDER BY eventtime DESC
```

### QRadar Properties

```
# Custom Property: Privilege Event Category
privilege_event_category=select * from events where eventname MATCHES '.*[Pp]rivilege.*' OR eventname MATCHES '.*[Aa]dmin.*'

# Custom Property: Elevation Events
elevation_events=select * from events where eventname MATCHES '.*[Ee]levation.*' OR eventname MATCHES '.*sudo.*'
```

### Log Sources Configuration

**Required Log Sources:**
- Windows Security Event Logs (Event IDs 4672, 4624, 4648)
- Linux Sudo Logs
- Active Directory Audit Logs
- Privileged Access Management (PAM) Systems
- Database Administrative Logs

### Detection Logic

1. **Indicators**:
   - Unusual privilege assignments
   - Off-hours administrative activities
   - Non-standard elevation methods
   - Multiple privilege escalation attempts

2. **Correlation**:
   - User baseline behavior analysis
   - Geographic anomalies
   - Time-based patterns

### Response Procedures

**Immediate Actions:**
- Isolate affected systems
- Disable suspicious accounts
- Review privilege assignments
- Document all activities

---

## Use Case 3: Malware Communication Detection

### Description
Detects network communications indicative of malware command and control (C2) traffic, including known malicious domains and suspicious network patterns.

### SIGMA Rule

```yaml
title: Malware C2 Communication
id: 4g87ed89-53e4-6h9g-d6g2-9g345678901c
status: stable
description: Detects malware command and control communication patterns
author: Security Team
date: 2024/01/01
modified: 2024/01/01
tags:
    - attack.command_and_control
    - attack.t1071
    - attack.t1090
logsource:
    category: firewall
detection:
    selection:
        destination_port:
            - 8080
            - 443
            - 80
        protocol: tcp
    filter:
        destination_domain|contains:
            - '.tk'
            - '.ml'
            - 'pastebin.com'
    condition: selection and filter
falsepositives:
    - Legitimate traffic to flagged domains
    - Internal applications using suspicious ports
level: high
```

### QRadar Custom Rule

```sql
SELECT
    sourceip,
    destinationip,
    destinationport,
    hostname,
    eventtime,
    bytessent,
    bytesreceived
FROM flows
WHERE
    destinationport IN (8080, 1337, 6667, 443) AND
    (hostname MATCHES '.*\.tk' OR
     hostname MATCHES '.*\.ml' OR
     hostname MATCHES '.*pastebin\.com.*') AND
    eventtime > NOW() - INTERVAL '1' HOUR
```

### QRadar Properties

```
# Custom Property: Suspicious Domains
suspicious_domains=select * from flows where hostname MATCHES '.*\.tk' OR hostname MATCHES '.*\.ml' OR hostname MATCHES '.*\.bit'

# Custom Property: C2 Communication Patterns
c2_patterns=select sourceip, destinationip, count(*) from flows where destinationport IN (8080,1337,6667) and eventtime > (NOW() - INTERVAL '24' HOUR) group by sourceip, destinationip having count(*) > 10
```

### Log Sources Configuration

**Required Log Sources:**
- Firewall Logs
- Proxy Logs
- DNS Logs
- Network Flow Data (NetFlow/sFlow)
- IDS/IPS Alerts

---

## Use Case 4: Data Exfiltration Detection

### Description
Monitors for unusual data transfers and potential data theft activities, focusing on large volume transfers and access to sensitive data repositories.

### SIGMA Rule

```yaml
title: Data Exfiltration Detection
id: 5h98fe90-64f5-7i0h-e7h3-0h456789012d
status: experimental
description: Detects potential data exfiltration based on traffic patterns
author: Security Team
date: 2024/01/01
modified: 2024/01/01
tags:
    - attack.exfiltration
    - attack.t1041
    - attack.t1020
logsource:
    category: network
detection:
    selection:
        bytes_out: '>=10485760'  # 10MB
        protocol: tcp
    timeframe: 5m
    condition: selection
falsepositives:
    - Legitimate file transfers
    - Backup operations
    - Software updates
level: medium
```

### QRadar Custom Rule

```sql
SELECT
    sourceip,
    destinationip,
    SUM(bytessent) as total_bytes,
    COUNT(*) as connection_count
FROM flows
WHERE
    eventtime > NOW() - INTERVAL '5' MINUTE AND
    bytessent > 10485760
GROUP BY sourceip, destinationip
HAVING SUM(bytessent) > 52428800
```

---

## Use Case 5: Lateral Movement Detection

### Description
Identifies unauthorized movement within the network infrastructure, detecting attempts to compromise additional systems after initial breach.

### SIGMA Rule

```yaml
title: Lateral Movement Detection
id: 6i09gf01-75g6-8j1i-f8i4-1i567890123e
status: experimental
description: Detects lateral movement patterns in network traffic
author: Security Team
date: 2024/01/01
modified: 2024/01/01
tags:
    - attack.lateral_movement
    - attack.t1021
    - attack.t1076
logsource:
    category: network
detection:
    selection:
        destination_port:
            - 22
            - 3389
            - 445
            - 135
        protocol: tcp
    condition: selection | count(destination_ip) by source_ip > 5
    timeframe: 10m
falsepositives:
    - Administrative activities
    - Network scanning tools
level: high
```

---

## Use Case 6: Insider Threat Detection

### Description
Monitors for suspicious activities by internal users, including unusual data access patterns and policy violations.

### SIGMA Rule

```yaml
title: Insider Threat Detection
id: 7j10hg02-86h7-9k2j-g9j5-2j678901234f
status: experimental
description: Detects potential insider threat activities
author: Security Team
date: 2024/01/01
modified: 2024/01/01
tags:
    - attack.collection
    - attack.t1005
    - attack.t1039
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID:
            - 4663  # File access
            - 4656  # File handle requested
        ObjectType: 'File'
    filter:
        ObjectName|contains:
            - 'Confidential'
            - 'Secret'
            - 'Personal'
    condition: selection and filter
    timeframe: 1h
    count: 50
falsepositives:
    - Legitimate business activities
    - Automated processes
level: medium
```

---

## Use Case 7: Web Application Attacks

### Description
Detects common web application attacks including SQL injection, cross-site scripting (XSS), and other OWASP Top 10 vulnerabilities.

### SIGMA Rule

```yaml
title: Web Application Attack Detection
id: 8k21ih03-97i8-0l3k-h0k6-3k789012345g
status: stable
description: Detects web application attacks based on HTTP patterns
author: Security Team
date: 2024/01/01
modified: 2024/01/01
tags:
    - attack.initial_access
    - attack.t1190
    - attack.t1566
logsource:
    category: webserver
detection:
    selection:
        c-uri-query|contains:
            - 'UNION SELECT'
            - '<script>'
            - '../../../'
            - 'exec('
            - 'eval('
    condition: selection
falsepositives:
    - Legitimate application functionality
    - Development testing
level: high
```

---

## Use Case 8: DNS Tunneling Detection

### Description
Identifies DNS tunneling attempts used for data exfiltration or command and control communications.

### SIGMA Rule

```yaml
title: DNS Tunneling Detection
id: 9l32ji04-08j9-1m4l-i1l7-4l890123456h
status: experimental
description: Detects DNS tunneling based on query patterns
author: Security Team
date: 2024/01/01
modified: 2024/01/01
tags:
    - attack.exfiltration
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection:
        query_length: '>=50'
        query_type: 'TXT'
    condition: selection | count() by src_ip > 100
    timeframe: 5m
falsepositives:
    - Legitimate long DNS queries
    - DNS-based services
level: medium
```

---

## Use Case 9: Account Anomaly Detection

### Description
Monitors for unusual account activities including off-hours access, geographic anomalies, and behavioral changes.

### SIGMA Rule

```yaml
title: Account Anomaly Detection
id: 0m43kj05-19k0-2n5m-j2m8-5m901234567i
status: experimental
description: Detects anomalous user account activities
author: Security Team
date: 2024/01/01
modified: 2024/01/01
tags:
    - attack.persistence
    - attack.t1078
logsource:
    product: windows
    service: security
detection:
    selection:
        EventID: 4624
        LogonType:
            - 2  # Interactive
            - 10 # Remote interactive
    filter:
        LogonTime: '>=22:00'  # After hours
    condition: selection and filter
falsepositives:
    - Legitimate after-hours work
    - Shift workers
level: low
```

---

## Use Case 10: Network Scanning Detection

### Description
Detects network reconnaissance activities including port scanning and network enumeration attempts.

### SIGMA Rule

```yaml
title: Network Scanning Detection
id: 1n54lk06-20l1-3o6n-k3n9-6n012345678j
status: stable
description: Detects network scanning activities
author: Security Team
date: 2024/01/01
modified: 2024/01/01
tags:
    - attack.discovery
    - attack.t1046
    - attack.t1018
logsource:
    category: firewall
detection:
    selection:
        action: 'block'
        protocol: 'tcp'
    condition: selection | count(destination_port) by source_ip > 20
    timeframe: 2m
falsepositives:
    - Vulnerability scanners
    - Network monitoring tools
level: medium
```

---

## Implementation Guidelines

### QRadar Rule Deployment

1. **Import SIGMA Rules**: Convert SIGMA rules to QRadar format using sigma2qradar tool
2. **Test Rules**: Deploy in test environment first
3. **Tune Thresholds**: Adjust based on environment baseline
4. **Schedule Reviews**: Regular rule effectiveness reviews

### Log Source Integration

1. **Prioritize High-Value Sources**:
   - Domain Controllers
   - Critical Servers
   - Network Perimeter Devices
   - Security Tools

2. **Configure Parsing**:
   - Ensure proper DSM configuration
   - Validate event normalization
   - Test custom properties

### Performance Considerations

- **Rule Optimization**: Minimize resource-intensive rules
- **Indexing**: Ensure proper database indexing
- **Retention**: Configure appropriate data retention
- **Archiving**: Implement log archiving strategy

### Compliance Mapping

| Use Case | NIST CSF | ISO 27001 | BSI Grundschutz |
|----------|----------|-----------|-----------------|
| Brute Force | PR.AC-7 | A.9.4.2 | ORP.4 |
| Privilege Escalation | PR.AC-4 | A.9.2.3 | ORP.4 |
| Malware Communication | DE.CM-1 | A.12.2.1 | SYS.1.1 |
| Data Exfiltration | DE.CM-3 | A.13.1.1 | NET.1.1 |
| Lateral Movement | DE.CM-1 | A.13.1.1 | NET.1.1 |

---

## Maintenance and Updates

### Monthly Tasks
- Review false positive rates
- Update threat intelligence feeds
- Validate rule effectiveness
- Performance optimization

### Quarterly Tasks
- Compliance assessment
- Rule coverage analysis
- Threat landscape updates
- Training updates

### Annual Tasks
- Complete use case review
- Technology stack evaluation
- Process improvement assessment
- Disaster recovery testing

---

*Last Updated: 2024-01-01*
*Next Review: 2024-04-01*
*Document Owner: Security Operations Team*