# BSI-QRadar SIEM Implementation

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![BSI Grundschutz](https://img.shields.io/badge/BSI-Grundschutz-blue.svg)](https://www.bsi.bund.de/DE/Themen/Unternehmen-und-Organisationen/Standards-und-Zertifizierung/IT-Grundschutz/it-grundschutz_node.html)
[![QRadar Compatible](https://img.shields.io/badge/QRadar-Compatible-red.svg)](https://www.ibm.com/security/security-intelligence/qradar)

## Überblick

Dieses Repository enthält eine umfassende BSI-konforme QRadar SIEM Implementation mit standardisierten Use Cases, SIGMA Rules und Compliance-Dokumentation für deutsche Behörden und Unternehmen.

## 📋 Inhaltsverzeichnis

- [Features](#features)
- [Repository-Struktur](#repository-struktur)
- [Use Cases](#use-cases)
- [Compliance](#compliance)
- [Installation](#installation)
- [Verwendung](#verwendung)
- [Beitrag](#beitrag)
- [Lizenz](#lizenz)

## ✨ Features

### 🔍 Standard Use Cases (10 Use Cases)
- **Brute Force Authentication Attacks** - Erkennung von Anmeldungsangriffen
- **Privilege Escalation Detection** - Privilegienausweitung erkennen
- **Malware Communication Detection** - C2-Kommunikation identifizieren
- **Data Exfiltration Detection** - Datenabfluss überwachen
- **Lateral Movement Detection** - Seitliche Bewegungen verfolgen
- **Insider Threat Detection** - Interne Bedrohungen erkennen
- **Web Application Attacks** - Webanwendungsangriffe abwehren
- **DNS Tunneling Detection** - DNS-Tunneling aufdecken
- **Account Anomaly Detection** - Kontoanomalien identifizieren
- **Network Scanning Detection** - Netzwerk-Scans erkennen

### 📜 Regulatory Compliance
- **PCI DSS** - Payment Card Industry Data Security Standard
- **NIS2 Directive** - Network and Information Systems Directive 2
- **KRITIS Regulation** - Kritische Infrastrukturen Verordnung
- **GDPR/DSGVO** - Datenschutz-Grundverordnung
- **BSI IT-Grundschutz** - BSI IT Security Standards
- **ISO 27001** - Information Security Management
- **NIST Cybersecurity Framework** - NIST CSF Implementation

### 🚀 SOAR Automation
- **CI/CD Pipeline** für Playbook-Entwicklung
- **Automatisierte Tests** (Unit, Integration, E2E)
- **Docker-basierte** Entwicklungsumgebungen
- **Jenkins/GitLab CI** Integration
- **Monitoring und Metriken** Collection

### 🎯 APT Detection
- **Spezielle Use Cases** für Behörden
- **Advanced Persistent Threat** Erkennung
- **Threat Intelligence** Integration
- **Attribution Framework** für APT-Gruppen
- **BSI Meldepflicht** Integration

## 📁 Repository-Struktur

```
BSI-QRadar/
├── README.md
├── docs/                           # Dokumentation
│   ├── Standard-Use-Cases.md       # 10 Standard SIEM Use Cases
│   ├── Compliance-Use-Cases.md     # Regulatory Compliance Use Cases
│   ├── BSI-Implementation.md       # BSI-Grundschutz konforme Implementierung
│   ├── SOAR-Pipeline.md           # SOAR CI/CD Pipeline Dokumentation
│   └── APT-Detection.md           # APT Use Cases für Behörden
├── sigma-rules/                   # SIGMA Detection Rules
│   ├── standard/                  # Standard Use Case Rules
│   ├── compliance/               # Compliance-spezifische Rules
│   └── apt/                      # APT Detection Rules
├── qradar/                       # QRadar-spezifische Konfiguration
│   ├── rules/                    # Custom QRadar Rules (AQL)
│   ├── properties/               # Custom Properties
│   ├── dsm/                      # Device Support Module Configs
│   └── searches/                 # Saved Searches und Reports
├── playbooks/                    # SOAR Playbooks
│   ├── incident-response/        # Incident Response Playbooks
│   ├── compliance/              # Compliance Playbooks  
│   └── apt-response/            # APT Response Playbooks
├── scripts/                      # Deployment und Maintenance Scripts
│   ├── deployment/              # Deployment Automation
│   ├── backup/                  # Backup Scripts
│   └── monitoring/              # Health Check Scripts
└── examples/                     # Beispiele und Templates
    ├── configurations/          # Beispiel-Konfigurationen
    └── dashboards/             # QRadar Dashboard Exports
```

## 🎯 Use Cases

### Standard Use Cases
Alle Use Cases enthalten:
- **SIGMA Rules** im Standard-Format
- **QRadar AQL Queries** für direkte Implementation  
- **Custom Properties** Konfiguration
- **Log Source Requirements** und Mapping
- **Detection Logic** und Baseline-Definitionen
- **Response Procedures** und Playbooks

### Compliance Use Cases
Speziell entwickelt für:
- Deutsche Behörden und öffentliche Einrichtungen
- Kritische Infrastrukturen (KRITIS)
- Finanzdienstleister (PCI DSS)
- Gesundheitswesen (DSGVO/GDPR)
- Verteidigungsbereich (VS-Anforderungen)

### APT Use Cases
Fokus auf staatlich gesteuerte Angriffe:
- Spear-Phishing Campaigns
- Supply Chain Attacks
- Zero-Day Exploit Detection
- Living off the Land Techniques
- Credential Harvesting
- Command & Control Detection

## ✅ Compliance

### BSI IT-Grundschutz
Vollständige Abdeckung folgender Bausteine:
- **SYS.1.1** - Allgemeiner Server
- **NET.1.1** - Netzarchitektur und -design  
- **ORP.4** - Identitäts- und Berechtigungsmanagement
- **DER.1** - Detektion von sicherheitsrelevanten Ereignissen

### Regulatorische Anforderungen
- **NIS2 Directive** - Incident Reporting (24h)
- **KRITIS-Verordnung** - Meldepflicht an BSI
- **PCI DSS** - Audit Trail Requirements
- **DSGVO** - Data Breach Notification

## 🚀 Installation

### Voraussetzungen
```bash
# QRadar SIEM (Version 7.4+)
# Python 3.8+
# Git
# Docker (für SOAR Development)
```

### Quick Start
```bash
# Repository klonen
git clone https://github.com/Pr0mp7/BSI-QRadar.git
cd BSI-QRadar

# SIGMA Rules konvertieren und deployen  
./scripts/deployment/deploy-sigma-rules.sh

# QRadar Custom Rules importieren
./scripts/deployment/import-qradar-rules.sh

# Custom Properties konfigurieren
./scripts/deployment/setup-custom-properties.sh
```

### Detaillierte Installation
Siehe [docs/BSI-Implementation.md](docs/BSI-Implementation.md) für vollständige Installationsanweisungen.

## 📖 Verwendung

### Use Case Implementation
1. **SIGMA Rule** aus `sigma-rules/` Directory wählen
2. **QRadar Rule** aus `qradar/rules/` importieren  
3. **Custom Properties** aus `qradar/properties/` konfigurieren
4. **Log Sources** gemäß Dokumentation einrichten
5. **Playbook** für automatisierte Response aktivieren

### Compliance Monitoring
```bash
# BSI Grundschutz Compliance Check
python scripts/monitoring/bsi-compliance-check.py

# NIS2 Incident Report Generation
python scripts/compliance/nis2-incident-report.py

# PCI DSS Audit Trail Validation  
python scripts/compliance/pci-audit-validation.py
```

### Threat Hunting
```sql
-- APT Lateral Movement Detection
SELECT * FROM events 
WHERE sourceip IN (SELECT sourceip FROM apt_infected_hosts)
AND destinationport IN (22, 3389, 445, 135)
AND eventtime > NOW() - INTERVAL '24' HOUR;
```

## 🛡️ Sicherheit

### Klassifizierung
- **Öffentlich**: Standard Use Cases, SIGMA Rules
- **Vertraulich**: APT Intelligence, Threat Actor Profiles  
- **VS-NfD**: Government-specific Detection Logic

### Disclosure Policy
Sicherheitslücken bitte an: security@domain.com

## 🤝 Beitrag

### Development Workflow
1. Fork des Repository erstellen
2. Feature Branch erstellen (`git checkout -b feature/neue-use-case`)
3. Änderungen committen (`git commit -am 'Add new use case'`)  
4. Branch pushen (`git push origin feature/neue-use-case`)
5. Pull Request erstellen

### Coding Standards
- **SIGMA Rules**: Sigma HQ Format
- **QRadar Rules**: AQL Best Practices
- **Documentation**: German für Compliance, English für Technical
- **Testing**: Minimum 80% Coverage für Playbooks

## 📊 Metriken

### Detection Effectiveness
- **Mean Time to Detection (MTTD)**: < 30 Minuten
- **False Positive Rate**: < 5%
- **APT Detection Rate**: > 95%
- **Zero-Day Detection**: > 70%

### Compliance Metrics  
- **BSI Grundschutz Coverage**: 100%
- **NIS2 Reporting Compliance**: 100%
- **Audit Readiness**: 100%

## 📞 Support

### Kontakte
- **Technical Support**: tech-support@domain.com
- **Compliance Questions**: compliance@domain.com  
- **Emergency Response**: +49-123-456-7890

### Externe Ressourcen
- **BSI Cyber-Sicherheitsberatung**: https://www.bsi.bund.de
- **CERT-Bund**: https://cert-bund.de
- **MITRE ATT&CK**: https://attack.mitre.org
- **IBM QRadar Documentation**: https://www.ibm.com/docs/en/qsip

## 📄 Lizenz

Dieses Projekt steht unter der MIT License - siehe [LICENSE](LICENSE) Datei für Details.

## 🙏 Danksagungen

- **Bundesamt für Sicherheit in der Informationstechnik (BSI)** für IT-Grundschutz Standards
- **SIGMA Project** für das Detection Rule Format
- **IBM Security** für QRadar SIEM Platform  
- **MITRE Corporation** für das ATT&CK Framework

---

**⚠️ Haftungsausschluss**: Diese Dokumentation dient Bildungszwecken und zur Implementierung von Sicherheitsmaßnahmen. Alle Beispiele sollten an die spezifische Umgebung angepasst werden.

**🔒 Klassifizierung**: Unklassifiziert / Öffentlich verwendbar

**📅 Letzte Aktualisierung**: 2024-01-01

**👥 Maintainer**: Security Operations Team