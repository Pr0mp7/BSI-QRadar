# APT Use Cases für Behörden und Regierungseinrichtungen

## Überblick

Dieses Dokument enthält spezialisierte Use Cases zur Erkennung von Advanced Persistent Threat (APT) Aktivitäten, die speziell auf Behörden und Regierungseinrichtungen abzielen. Die Use Cases basieren auf bekannten APT-Taktiken und sind mit MITRE ATT&CK Framework kategorisiert.

## APT-Bedrohungslandschaft für Behörden

### Bekannte APT-Gruppen mit Fokus auf Regierungseinrichtungen

```yaml
High_Priority_APT_Groups:
  APT28_Fancy_Bear:
    origin: Russia
    targets: ["Government", "Military", "NATO"]
    ttps: ["Zero-day exploits", "Credential harvesting", "DLL side-loading"]
    iocs: ["185.*.*.* IP ranges", "CHOPSTICK", "SOURFACE"]
    
  APT29_Cozy_Bear:
    origin: Russia
    targets: ["Government", "Think tanks", "NGOs"]
    ttps: ["Supply chain attacks", "Cloud infrastructure abuse", "Steganography"]
    iocs: ["CloudApp usage", "PowerShell Empire", "CobaltStrike"]
    
  APT40_Leviathan:
    origin: China
    targets: ["Maritime", "Government", "Research"]
    ttps: ["Web application exploits", "Password spraying", "DNS tunneling"]
    iocs: ["*.temp-dns.com", "SysUpdate", "China Chopper"]
```

## Spear-Phishing gegen Regierungsmitarbeiter

### Use Case: APT Spear-Phishing Detection

**Bedrohungskontext**: APT-Gruppen verwenden hochgezielte Spear-Phishing-E-Mails gegen Regierungsmitarbeiter mit personalisierten Inhalten.

#### SIGMA Rule

```yaml
title: APT Spear-Phishing gegen Regierungsmitarbeiter
id: apt-spearphish-gov-001
status: experimental
description: Erkennt verdächtige E-Mails mit APT-typischen Spear-Phishing-Indikatoren
references:
    - https://attack.mitre.org/techniques/T1566/001/
tags:
    - attack.initial_access
    - attack.t1566.001
    - apt.spearphishing
    - government.targeted
logsource:
    product: email_security_gateway
    service: email
detection:
    selection_subject:
        subject|contains:
            - 'Dringend'
            - 'Vertraulich'
            - 'Geheim'
            - 'Klassifiziert'
            - 'Sicherheitsupdate'
    selection_sender:
        sender_domain|endswith:
            - '.gov.fake'
            - '.government.fake' 
            - '.bundesamt.fake'
        sender_display_name|contains:
            - 'Bundesamt'
            - 'Ministerium'
            - 'BSI'
    selection_attachment:
        has_attachment: true
        attachment_type:
            - '.exe'
            - '.docm'
            - '.xlsm'
    condition: selection_subject and selection_sender and selection_attachment
falsepositives:
    - Legitimate government communications
level: high
```

#### QRadar Custom Rule

```sql
-- APT Spear-Phishing Detection Rule
SELECT
    devicetime as timestamp,
    sourceip as sender_ip,
    username as recipient, 
    "E-Mail Subject" as subject,
    "Sender Display Name" as sender_name,
    "Attachment Name" as attachment
FROM events
WHERE
    category = 11002 AND -- Email category
    (
        ("E-Mail Subject" MATCHES '.*[Dd]ringend.*' OR
         "E-Mail Subject" MATCHES '.*[Vv]ertraulich.*' OR
         "E-Mail Subject" MATCHES '.*[Ss]icherheitsupdate.*')
        AND
        ("Sender Display Name" MATCHES '.*Bundesamt.*' OR
         "Sender Display Name" MATCHES '.*Ministerium.*' OR
         "Sender Display Name" MATCHES '.*BSI.*')
        AND
        "Has Attachment" = 'true'
    )
    AND eventtime > NOW() - INTERVAL '1' HOUR
ORDER BY devicetime DESC
```

## Credential Harvesting Campaigns

### Use Case: APT Credential Harvesting Detection

#### SIGMA Rule

```yaml
title: APT Credential Harvesting Campaign
id: apt-credharvest-gov-002
status: stable
description: Erkennt APT-typische Credential Harvesting Aktivitäten
tags:
    - attack.credential_access
    - attack.t1056
    - apt.credential_harvesting
logsource:
    category: proxy
detection:
    selection_domains:
        request_url|contains:
            - 'login-government.com'
            - 'secure-portal.gov'
            - 'auth-bundesamt.de'
    selection_suspicious_params:
        request_url|contains:
            - 'username='
            - 'password='
            - 'credentials='
    condition: selection_domains and selection_suspicious_params
    timeframe: 5m
    count: 3
level: high
```

## Living off the Land Techniques

### Use Case: LotL Detection

#### SIGMA Rule

```yaml
title: APT Living off the Land Techniques
id: apt-lotl-gov-004
status: stable
description: Erkennt verdächtige Nutzung legitimer System-Tools
tags:
    - attack.defense_evasion
    - attack.execution
    - attack.t1059.001
    - apt.living_off_the_land
logsource:
    category: process_creation
detection:
    selection_powershell:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'DownloadString'
            - 'FromBase64String'
            - 'EncodedCommand'
            - '-ExecutionPolicy Bypass'
    selection_wmi:
        Image|endswith: '\wmic.exe'
        CommandLine|contains:
            - 'process call create'
            - '/format:'
    condition: selection_powershell or selection_wmi
level: medium
```

## Data Exfiltration über verdeckte Kanäle

### Use Case: APT Data Exfiltration Detection

#### SIGMA Rule

```yaml
title: APT Data Exfiltration über verdeckte Kanäle
id: apt-exfiltration-gov-005
status: experimental
description: Erkennt APT-typische Datenexfiltration über verdeckte Kanäle
tags:
    - attack.exfiltration
    - attack.t1041
    - attack.t1071.004
logsource:
    category: dns
detection:
    selection_dns_tunneling:
        query_type: 'TXT'
        query_length: '>100'
        query_subdomain_count: '>5'
    selection_dns_suspicious:
        query_name|contains:
            - '.tk'
            - '.ml'
            - '.ga'
        query_entropy: '>4.5'
    condition: selection_dns_tunneling or selection_dns_suspicious
level: high
```

## Command and Control Detection

### Use Case: Encrypted C2 Channel Detection

#### SIGMA Rule

```yaml
title: APT Encrypted C2 Communication
id: apt-c2-encrypted-gov-007
status: experimental
description: Erkennt verdächtige verschlüsselte C2-Kommunikation
tags:
    - attack.command_and_control
    - attack.t1071.001
    - attack.t1573
logsource:
    category: firewall
detection:
    selection_tls_anomaly:
        protocol: 'https'
        tls_version: 'TLSv1.0'  # Outdated TLS
        certificate_validation: 'failed'
    selection_ja3_hash:
        ja3_hash:
            - 'e7d705a3286e19ea42f587b344ee6865'  # Known APT tool
            - 'a0e9f5d64349fb13191bc781f81f42e1'  # CobaltStrike
    condition: selection_tls_anomaly or selection_ja3_hash
level: medium
```

## Threat Hunting Queries

### Advanced APT Hunting Queries

```sql
-- Hunt 1: Suspicious PowerShell with Network Activity
SELECT
    p.sourceip as host,
    p."Process Name" as process,
    p."Command Line" as command,
    n.destinationip as network_destination
FROM events p
JOIN events n ON p.sourceip = n.sourceip
WHERE
    p.category = 4000 AND -- Process creation
    p."Process Name" = 'powershell.exe' AND
    (p."Command Line" MATCHES '.*DownloadString.*' OR
     p."Command Line" MATCHES '.*Invoke-Expression.*') AND
    n.category = 5000 AND -- Network connection
    n.destinationport NOT IN (80, 443, 53) AND
    n.devicetime BETWEEN p.devicetime AND p.devicetime + INTERVAL '5' MINUTE;

-- Hunt 2: Rare Binary Execution from Temp Directories  
SELECT
    "Process Name" as process,
    "File Path" as path,
    sourceip as host,
    COUNT(*) as execution_count
FROM events
WHERE
    category = 4000 AND
    ("File Path" MATCHES '.*\\Temp\\.*' OR
     "File Path" MATCHES '.*\\ProgramData\\.*') AND
    eventtime > NOW() - INTERVAL '7' DAY
GROUP BY "Process Name", "File Path", sourceip
HAVING COUNT(*) < 5  -- Rare execution
ORDER BY execution_count DESC;
```

## APT Attribution Framework

### Technical Indicators

```python
# APT Intelligence Integration
class APTIntelligenceFramework:
    def __init__(self):
        self.intelligence_sources = {
            'government': ['BSI', 'BKA', 'BfV'],
            'commercial': ['CrowdStrike', 'FireEye', 'Microsoft'],
            'open_source': ['MITRE', 'CISA', 'ENISA']
        }
    
    def correlate_indicators(self, incident_data):
        correlation_results = {
            'possible_attributions': [],
            'confidence_scores': {},
            'supporting_evidence': {}
        }
        
        # Technical correlation
        technical_matches = self._correlate_technical_indicators(
            incident_data['iocs']
        )
        
        # Behavioral correlation  
        behavioral_matches = self._correlate_behavioral_patterns(
            incident_data['ttps']
        )
        
        return correlation_results
```

## BSI Meldepflicht Integration

### BSI Incident Reporting

```python
class BSIIncidentReporting:
    def __init__(self):
        self.reporting_thresholds = {
            'critical_infrastructure': True,
            'government_agency': True,
            'severity_threshold': 7
        }
    
    def evaluate_reporting_requirement(self, incident_data):
        reporting_required = False
        reporting_reasons = []
        
        if incident_data['organization_type'] in ['critical_infrastructure', 'government']:
            reporting_required = True
            reporting_reasons.append('Organization type requires reporting')
        
        if incident_data['severity_score'] >= 7:
            reporting_required = True
            reporting_reasons.append('Severity exceeds threshold')
        
        return {
            'reporting_required': reporting_required,
            'reasons': reporting_reasons,
            'deadline': self._calculate_reporting_deadline(incident_data)
        }
```

## Success Metrics

```yaml
Key_Performance_Indicators:
  detection_metrics:
    - "Mean Time to Detection (MTTD): <30 minutes"
    - "False Positive Rate: <5%"
    - "APT Campaign Detection Rate: >95%"
    
  response_metrics:
    - "Mean Time to Response (MTTR): <2 hours"
    - "Containment Success Rate: >90%"
    - "Attribution Accuracy: >85%"
```

---

*Letzte Aktualisierung: 2024-01-01*
*Klassifizierung: VS-NfD (Nur für den Dienstgebrauch)*
*Dokumentenverantwortlicher: APT Analysis Team*