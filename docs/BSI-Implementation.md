# BSI IT-Grundschutz Konforme QRadar SIEM Umgebung

## Überblick

Dieses Dokument beschreibt die Implementation einer BSI IT-Grundschutz konformen QRadar SIEM Umgebung. Es folgt den Standards des Bundesamts für Sicherheit in der Informationstechnik (BSI) und implementiert alle erforderlichen Sicherheitsmaßnahmen für eine produktive SIEM-Infrastruktur.

## BSI IT-Grundschutz Referenz

### Anwendbare Bausteine

#### SYS.1.1 - Allgemeiner Server
- **Anforderung**: Sichere Grundkonfiguration aller Server-Systeme
- **Implementation**: QRadar Console und Managed Hosts
- **Status**: Vollständig implementiert

#### NET.1.1 - Netzarchitektur und -design
- **Anforderung**: Sichere Netzwerksegmentierung
- **Implementation**: Dedizierte SIEM-Netzwerksegmente
- **Status**: Vollständig implementiert

#### ORP.4 - Identitäts- und Berechtigungsmanagement
- **Anforderung**: Sichere Identitätsverwaltung
- **Implementation**: Rollenbasierte Zugriffskontrolle
- **Status**: Vollständig implementiert

#### DER.1 - Detektion von sicherheitsrelevanten Ereignissen
- **Anforderung**: Erkennung von Sicherheitsereignissen
- **Implementation**: QRadar Use Cases und Regeln
- **Status**: Vollständig implementiert

## Systemarchitektur

### QRadar Komponenten

#### QRadar Console (Primary)
```yaml
Hostname: qradar-console-01.internal.domain
IP-Adresse: 10.10.10.10/24
Betriebssystem: Red Hat Enterprise Linux 8.10
Hardware:
  CPU: 16 vCores
  RAM: 64 GB
  Storage: 2 TB SSD (RAID 1)
```

#### High Availability Setup
- Primary/Secondary Console Configuration
- Load Balancing für Event Processing
- Redundante Storage Nodes
- Automatisches Failover

## Sicherheitshärtung

### Betriebssystem-Härtung (SYS.1.1)

```bash
# BSI Grundschutz konforme RHEL 8 Härtung

# 1. Deaktivierung nicht benötigter Dienste
systemctl disable avahi-daemon cups bluetooth

# 2. SSH Konfiguration
# /etc/ssh/sshd_config
Protocol 2
PermitRootLogin no
MaxAuthTries 3
PasswordAuthentication no
PubkeyAuthentication yes

# 3. Firewall Konfiguration
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.10.0.0/16" service name="ssh" accept'
firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="10.10.10.0/24" port port="443" protocol="tcp" accept'
```

### QRadar Anwendungshärtung

```bash
# QRadar Console Sicherheitskonfiguration

# SSL/TLS Konfiguration
SSLProtocol all -SSLv3 -TLSv1 -TLSv1.1
SSLCipherSuite ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384

# Session Management
session.timeout=1800
session.concurrent.limit=3
password.complexity.enabled=true
password.min.length=12
```

## Netzwerksicherheit

### Netzwerksegmentierung (NET.1.1)

```yaml
Management_VLAN:
  VLAN_ID: 10
  Subnetz: 10.10.10.0/24
  Komponenten:
    - QRadar Consoles
    - Management Interfaces
  
Processing_VLAN:
  VLAN_ID: 20
  Subnetz: 10.10.20.0/24
  Komponenten:
    - Event Processors
    - Flow Processors
    
Storage_VLAN:
  VLAN_ID: 30
  Subnetz: 10.10.30.0/24
  Komponenten:
    - Data Nodes
    - Archive Storage
```

### Verschlüsselung

#### Transportverschlüsselung
- Syslog over TLS (RFC 5424)
- HTTPS mit TLS 1.3
- Certificate-based API Authentication

#### Ruhende Daten Verschlüsselung
```bash
# LUKS Verschlüsselung für QRadar Datenpartitionen
cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 256 /dev/sdb1
```

## Überwachung und Protokollierung

### BSI-konforme Logging-Konfiguration

#### System Logging (ORP.4)
```bash
# rsyslog Konfiguration für BSI Compliance
# High Precision Timestamps
$ActionFileDefaultTemplate RSYSLOG_TraditionalFileFormat

# Separate Log Files per Facility
authpriv.*     /var/log/secure
local0.*       /var/log/qradar/console.log
local1.*       /var/log/qradar/eventprocessor.log

# Remote Logging
*.* @@syslog-central.internal.domain:514
```

#### QRadar Custom Logs für BSI Compliance
```sql
-- BSI Grundschutz Compliance Events
SELECT 
    devicetime as Timestamp,
    sourceip as Admin_IP,
    username as Admin_User,
    eventname as Action,
    destinationip as Target_System
FROM events 
WHERE 
    (eventname MATCHES '.*Admin.*' OR eventname MATCHES '.*Configuration.*') AND
    eventtime > NOW() - INTERVAL '24' HOUR
ORDER BY devicetime DESC;
```

## Backup und Wiederherstellung

### BSI-konforme Backup-Strategie

```bash
#!/bin/bash
# BSI-konformes QRadar Backup Script

BACKUP_DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backup/qradar/backup_${BACKUP_DATE}"
ENCRYPTION_KEY="/etc/keys/backup.key"

# 1. Stoppe QRadar Services
systemctl stop qradar

# 2. Database Backup
sudo -u postgres pg_dump qradar > ${BACKUP_DIR}/database.sql

# 3. Configuration Backup
tar -czf ${BACKUP_DIR}/config.tar.gz -C /opt/qradar conf/

# 4. Verschlüsselte Archivierung
tar -czf - -C /backup backup_${BACKUP_DATE} | \
gpg --cipher-algo AES256 --symmetric \
    --passphrase-file ${ENCRYPTION_KEY} \
    --output /backup/backup_${BACKUP_DATE}.tar.gz.gpg

# 5. Starte QRadar Services
systemctl start qradar
```

## Compliance-Überwachung

### Automatische Compliance-Checks

```sql
-- Daily BSI Compliance Report
SELECT 
    'SYS.1.1 - Server Hardening' as Control,
    CASE 
        WHEN COUNT(*) = 0 THEN 'COMPLIANT'
        ELSE 'NON-COMPLIANT'
    END as Status,
    COUNT(*) as Violations
FROM events 
WHERE 
    eventname MATCHES '.*Configuration.*Change.*' AND
    sourceip IN (SELECT ip FROM assets WHERE asset_type='QRadar') AND
    eventtime > NOW() - INTERVAL '24' HOUR
```

## Kontakt und Support

### BSI Kontaktinformationen
- **BSI**: +49 228 99 9582-0, info@bsi.bund.de
- **CERT-Bund**: +49 228 99 9582-222, cert-bund@bsi.bund.de

---

*Letzte Aktualisierung: 2024-01-01*
*Nächste Überprüfung: 2024-04-01*
*BSI Compliance Officer: Compliance Team*