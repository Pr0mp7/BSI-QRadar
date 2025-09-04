# SOAR CI/CD Pipeline für Playbooks

## Überblick

Dieses Dokument beschreibt die Implementation einer CI/CD Pipeline für Security Orchestration, Automation and Response (SOAR) Playbooks. Die Pipeline automatisiert die Entwicklung, Tests und Deployment von Incident Response Playbooks für QRadar SIEM.

## Pipeline-Architektur

### Komponenten-Übersicht

```yaml
SOAR_Pipeline_Components:
  Source_Control:
    Platform: GitLab/GitHub Enterprise
    Repository: soar-playbooks
    Branching_Strategy: GitFlow
    
  CI_CD_Platform:
    Primary: Jenkins/GitLab CI
    Secondary: GitHub Actions
    
  Testing_Framework:
    Unit_Tests: pytest
    Integration_Tests: Robot Framework
    Security_Tests: SAST/DAST tools
```

### Jenkins Pipeline

```groovy
// Jenkinsfile für SOAR Playbook Deployment

pipeline {
    agent any
    
    parameters {
        choice(
            name: 'ENVIRONMENT',
            choices: ['development', 'staging', 'production'],
            description: 'Target deployment environment'
        )
        booleanParam(
            name: 'SKIP_TESTS', 
            defaultValue: false, 
            description: 'Skip automated testing'
        )
    }
    
    environment {
        PHANTOM_CREDENTIALS = credentials('phantom-api-credentials')
        QRADAR_CREDENTIALS = credentials('qradar-api-credentials')
        SOAR_VERSION = "${BUILD_NUMBER}"
    }
    
    stages {
        stage('Checkout') {
            steps {
                checkout scm
                script {
                    def gitCommit = sh(returnStdout: true, script: 'git rev-parse HEAD').trim()
                    env.GIT_COMMIT = gitCommit.take(7)
                }
            }
        }
        
        stage('Build') {
            steps {
                sh '''
                    echo "Building SOAR Playbooks v${SOAR_VERSION}"
                    
                    # Validate Python syntax
                    python3 -m py_compile playbooks/**/*.py
                    
                    # Validate YAML files
                    find . -name "*.yml" -o -name "*.yaml" | xargs yamllint
                    
                    # Package playbooks
                    tar -czf soar-playbooks-${SOAR_VERSION}.tar.gz playbooks/ templates/ environments/
                '''
            }
        }
        
        stage('Unit Tests') {
            when {
                not { params.SKIP_TESTS }
            }
            steps {
                sh '''
                    echo "Running unit tests..."
                    
                    # Install test dependencies
                    pip3 install -r requirements-test.txt
                    
                    # Run pytest with coverage
                    pytest tests/unit/ --junitxml=unit-test-results.xml --cov=playbooks
                '''
                
                publishTestResults testResultsPattern: 'unit-test-results.xml'
            }
        }
        
        stage('Deploy to Production') {
            when {
                branch 'main'
            }
            steps {
                script {
                    deployPlaybooks('production')
                }
            }
        }
    }
    
    post {
        success {
            script {
                if (env.BRANCH_NAME == 'main') {
                    slackSend(
                        channel: '#deployments',
                        color: 'good',
                        message: "✅ SOAR Playbooks v${SOAR_VERSION} successfully deployed"
                    )
                }
            }
        }
        
        failure {
            script {
                emailext(
                    subject: "SOAR Pipeline Failure - ${env.JOB_NAME} #${env.BUILD_NUMBER}",
                    body: "The SOAR playbook deployment pipeline has failed.",
                    recipientProviders: [developers()]
                )
            }
        }
    }
}

def deployPlaybooks(environment) {
    sh """
        echo "Deploying SOAR Playbooks to ${environment}..."
        
        # Extract playbooks
        tar -xzf soar-playbooks-${SOAR_VERSION}.tar.gz
        
        # Deploy using Phantom API
        python3 scripts/deploy_playbooks.py \
            --environment=${environment} \
            --version=${SOAR_VERSION}
    """
}
```

## Playbook-Standards

### Base Playbook Class

```python
# Standard Base Class für alle SOAR Playbooks

import logging
from typing import Dict, List, Optional, Any
from dataclasses import dataclass
from enum import Enum

logger = logging.getLogger(__name__)

class PlaybookStatus(Enum):
    """Standard playbook execution statuses"""
    NOT_STARTED = "not_started"
    IN_PROGRESS = "in_progress"
    SUCCESS = "success"
    FAILED = "failed"
    TIMEOUT = "timeout"

@dataclass
class PlaybookConfig:
    """Standard configuration structure"""
    name: str
    version: str
    author: str
    description: str
    timeout_minutes: int = 30
    max_retries: int = 3
    auto_containment: bool = False
    
class BasePlaybook:
    """Base class for all SOAR playbooks"""
    
    def __init__(self, container: Dict[str, Any], config: PlaybookConfig):
        self.container = container
        self.config = config
        self.status = PlaybookStatus.NOT_STARTED
        self.successful_actions = []
        self.failed_actions = []
        
        # Setup correlation ID for tracking
        self.correlation_id = f"{container['id']}_{time.time()}"
        self.logger = logging.getLogger(f"{__name__}.{self.correlation_id}")
        
    def execute(self) -> PlaybookStatus:
        """Main execution method - must be implemented by subclasses"""
        raise NotImplementedError("Subclasses must implement execute method")
    
    def validate_prerequisites(self) -> bool:
        """Validate prerequisites before execution"""
        if not self.container.get('artifacts'):
            self.logger.error("No artifacts found in container")
            return False
        return True
        
    def send_notification(self, message: str, severity: str) -> bool:
        """Send notification about playbook status"""
        try:
            notification_data = {
                'playbook': self.config.name,
                'container_id': self.container['id'],
                'message': message,
                'severity': severity
            }
            return self._send_to_notification_system(notification_data)
        except Exception as e:
            self.logger.error(f"Error sending notification: {str(e)}")
            return False
```

## QRadar Integration

### QRadar Connector

```python
# QRadar SIEM Integration für SOAR Playbooks

import requests
import json
from typing import Dict, List, Any

class QRadarConnector:
    """QRadar SIEM integration connector"""
    
    def __init__(self, host: str, token: str, verify_ssl: bool = True):
        self.host = host
        self.token = token
        self.base_url = f"https://{host}/api"
        self.session = self._create_session()
        
    def _create_session(self) -> requests.Session:
        session = requests.Session()
        session.headers.update({
            'SEC': self.token,
            'Content-Type': 'application/json',
            'Accept': 'application/json',
            'Version': '12.0'
        })
        return session
    
    def get_offense(self, offense_id: int) -> Dict[str, Any]:
        """Get QRadar offense details"""
        try:
            url = f"{self.base_url}/siem/offenses/{offense_id}"
            response = self.session.get(url)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error retrieving offense {offense_id}: {str(e)}")
            raise
    
    def close_offense(self, offense_id: int, closing_reason: str) -> Dict[str, Any]:
        """Close a QRadar offense"""
        try:
            url = f"{self.base_url}/siem/offenses/{offense_id}"
            data = {
                'status': 'CLOSED',
                'closing_reason_id': 1,
                'follow_up': closing_reason
            }
            response = self.session.post(url, json=data)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logger.error(f"Error closing offense {offense_id}: {str(e)}")
            raise
```

## Beispiel-Playbook

### Malware Response Playbook

```python
# Beispiel: Malware Detection Response Playbook

class MalwareResponsePlaybook(BasePlaybook):
    """Automated malware response playbook"""
    
    def execute(self) -> PlaybookStatus:
        try:
            self.logger.info(f"Starting malware response for container {self.container['id']}")
            
            # Phase 1: Triage
            if not self._phase_1_triage():
                return PlaybookStatus.FAILED
            
            # Phase 2: Containment
            if not self._phase_2_containment():
                return PlaybookStatus.FAILED
            
            # Phase 3: Recovery
            self._phase_3_recovery()
            
            return PlaybookStatus.SUCCESS
            
        except Exception as e:
            self.logger.error(f"Playbook execution failed: {str(e)}")
            return PlaybookStatus.FAILED
    
    def _phase_1_triage(self) -> bool:
        """Phase 1: Initial triage and enrichment"""
        try:
            # Get QRadar offense details
            offense_id = self.container.get('source_data_identifier')
            qradar = QRadarConnector(host='qradar.internal', token='api_token')
            offense_data = qradar.get_offense(offense_id)
            
            # Extract indicators
            self._extract_malware_indicators(offense_data)
            
            # Send notification
            self.send_notification(
                f"Malware incident detected: {offense_data.get('description', 'Unknown')}",
                'HIGH'
            )
            
            return True
        except Exception as e:
            self.logger.error(f"Triage failed: {str(e)}")
            return False
    
    def _phase_2_containment(self) -> bool:
        """Phase 2: Automated containment"""
        try:
            # Isolate infected hosts
            infected_hosts = self._get_infected_hosts()
            for host in infected_hosts:
                if self._isolate_host(host):
                    self.successful_actions.append(f"Isolated host: {host}")
                else:
                    self.failed_actions.append(f"Failed to isolate: {host}")
            
            return len(self.successful_actions) > len(self.failed_actions)
        except Exception as e:
            self.logger.error(f"Containment failed: {str(e)}")
            return False
```

## Testing Framework

### Unit Tests

```python
# tests/test_malware_playbook.py

import pytest
from unittest.mock import Mock, patch
from playbooks.malware_response import MalwareResponsePlaybook

class TestMalwareResponsePlaybook:
    
    def test_playbook_initialization(self):
        container = {'id': 12345, 'artifacts': [{'name': 'test'}]}
        config = PlaybookConfig(name="Test", version="1.0", author="Test")
        
        playbook = MalwareResponsePlaybook(container, config)
        
        assert playbook.container['id'] == 12345
        assert playbook.status == PlaybookStatus.NOT_STARTED
    
    @patch('playbooks.malware_response.QRadarConnector')
    def test_triage_phase_success(self, mock_qradar):
        # Setup mock
        mock_qradar.return_value.get_offense.return_value = {
            'id': 54321,
            'description': 'Test malware offense'
        }
        
        container = {'id': 12345, 'source_data_identifier': '54321', 'artifacts': [{}]}
        config = PlaybookConfig(name="Test", version="1.0", author="Test")
        playbook = MalwareResponsePlaybook(container, config)
        
        # Test triage phase
        result = playbook._phase_1_triage()
        
        assert result is True
        mock_qradar.return_value.get_offense.assert_called_once_with('54321')
```

## Deployment und Monitoring

### Metrics Collection

```python
# Playbook Performance Monitoring

class MetricsCollector:
    def __init__(self):
        self.active_playbooks = {}
    
    def start_tracking(self, playbook_name: str, container_id: str):
        metrics = {
            'playbook_name': playbook_name,
            'container_id': container_id,
            'start_time': datetime.now(),
            'status': 'running'
        }
        self.active_playbooks[container_id] = metrics
        return metrics
    
    def finish_tracking(self, container_id: str, status: str):
        if container_id in self.active_playbooks:
            metrics = self.active_playbooks[container_id]
            metrics['end_time'] = datetime.now()
            metrics['duration'] = (metrics['end_time'] - metrics['start_time']).total_seconds()
            metrics['status'] = status
            
            # Send to monitoring system
            self._send_metrics(metrics)
            del self.active_playbooks[container_id]
```

---

*Letzte Aktualisierung: 2024-01-01*
*Nächste Überprüfung: 2024-04-01*
*Technischer Lead: SOAR Engineering Team*