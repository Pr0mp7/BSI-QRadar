#!/usr/bin/env python3
"""
BSI Grundschutz Compliance Monitoring Script
Author: Compliance Team
Description: Automated compliance checking for BSI IT-Grundschutz requirements
Usage: python bsi-compliance-check.py [--config config.yaml]
"""

import argparse
import yaml
import json
import logging
import sys
from datetime import datetime, timedelta
from typing import Dict, List, Any

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class BSIComplianceChecker:
    """
    BSI IT-Grundschutz compliance checker for QRadar SIEM
    """
    
    def __init__(self, config_file: str = None):
        self.config = self.load_config(config_file)
        self.compliance_results = {}
        
    def load_config(self, config_file: str) -> Dict[str, Any]:
        """
        Load configuration from YAML file
        """
        if config_file:
            try:
                with open(config_file, 'r') as f:
                    return yaml.safe_load(f)
            except FileNotFoundError:
                logger.warning(f"Config file {config_file} not found, using defaults")
        
        # Default configuration
        return {
            'qradar': {
                'host': 'qradar.internal.domain',
                'api_token': 'your-api-token-here',
                'verify_ssl': True
            },
            'bsi_controls': {
                'SYS.1.1': {
                    'name': 'Allgemeiner Server',
                    'requirements': [
                        'secure_configuration',
                        'hardening_applied',
                        'monitoring_enabled'
                    ]
                },
                'NET.1.1': {
                    'name': 'Netzarchitektur und -design',
                    'requirements': [
                        'network_segmentation',
                        'access_control',
                        'traffic_monitoring'
                    ]
                },
                'ORP.4': {
                    'name': 'Identitäts- und Berechtigungsmanagement',
                    'requirements': [
                        'identity_management',
                        'access_logging',
                        'privilege_monitoring'
                    ]
                },
                'DER.1': {
                    'name': 'Detektion von sicherheitsrelevanten Ereignissen',
                    'requirements': [
                        'event_detection',
                        'incident_response',
                        'forensic_capabilities'
                    ]
                }
            }
        }
    
    def check_sys_1_1_compliance(self) -> Dict[str, Any]:
        """
        Check SYS.1.1 - Allgemeiner Server compliance
        """
        logger.info("Checking SYS.1.1 - Allgemeiner Server compliance")
        
        results = {
            'control': 'SYS.1.1',
            'name': 'Allgemeiner Server',
            'status': 'COMPLIANT',
            'findings': [],
            'score': 0
        }
        
        # Mock compliance checks - replace with actual QRadar API calls
        checks = [
            {
                'name': 'Server Hardening Configuration',
                'query': "SELECT COUNT(*) FROM events WHERE eventname MATCHES '.*Configuration.*Change.*' AND eventtime > NOW() - INTERVAL '24' HOUR",
                'threshold': 0,
                'description': 'No unauthorized configuration changes detected'
            },
            {
                'name': 'Security Monitoring Active',
                'query': "SELECT COUNT(*) FROM events WHERE category=1000 AND eventtime > NOW() - INTERVAL '1' HOUR",
                'threshold': 1,
                'description': 'Security monitoring events being received'
            },
            {
                'name': 'System Updates Applied',
                'query': "SELECT COUNT(*) FROM events WHERE eventname MATCHES '.*Update.*' AND eventtime > NOW() - INTERVAL '7' DAY",
                'threshold': 1,
                'description': 'System updates applied within last 7 days'
            }
        ]
        
        total_checks = len(checks)
        passed_checks = 0
        
        for check in checks:
            # Mock result - replace with actual QRadar query execution
            mock_result = 0  # Simulate compliant state
            
            if check['name'] == 'Security Monitoring Active':
                mock_result = 100  # Simulate active monitoring
            elif check['name'] == 'System Updates Applied':
                mock_result = 5  # Simulate recent updates
            
            if mock_result >= check['threshold']:
                passed_checks += 1
                results['findings'].append({
                    'check': check['name'],
                    'status': 'PASS',
                    'description': check['description'],
                    'value': mock_result
                })
            else:
                results['findings'].append({
                    'check': check['name'],
                    'status': 'FAIL',
                    'description': f"Failed: {check['description']}",
                    'value': mock_result,
                    'expected': check['threshold']
                })
        
        # Calculate compliance score
        results['score'] = (passed_checks / total_checks) * 100
        
        if results['score'] < 100:
            results['status'] = 'NON-COMPLIANT'
        
        return results
    
    def check_net_1_1_compliance(self) -> Dict[str, Any]:
        """
        Check NET.1.1 - Netzarchitektur und -design compliance
        """
        logger.info("Checking NET.1.1 - Netzarchitektur und -design compliance")
        
        results = {
            'control': 'NET.1.1',
            'name': 'Netzarchitektur und -design',
            'status': 'COMPLIANT',
            'findings': [],
            'score': 100  # Mock perfect compliance
        }
        
        # Mock network segmentation check
        results['findings'].append({
            'check': 'Network Segmentation',
            'status': 'PASS',
            'description': 'VLAN segmentation properly configured',
            'value': 'Configured'
        })
        
        return results
    
    def check_orp_4_compliance(self) -> Dict[str, Any]:
        """
        Check ORP.4 - Identitäts- und Berechtigungsmanagement compliance
        """
        logger.info("Checking ORP.4 - Identitäts- und Berechtigungsmanagement compliance")
        
        results = {
            'control': 'ORP.4',
            'name': 'Identitäts- und Berechtigungsmanagement',
            'status': 'COMPLIANT',
            'findings': [],
            'score': 95  # Mock high compliance with minor issues
        }
        
        # Mock identity management checks
        results['findings'].append({
            'check': 'Failed Authentication Monitoring',
            'status': 'PASS',
            'description': 'Failed authentication attempts properly logged',
            'value': 'Active'
        })
        
        return results
    
    def check_der_1_compliance(self) -> Dict[str, Any]:
        """
        Check DER.1 - Detektion von sicherheitsrelevanten Ereignissen compliance
        """
        logger.info("Checking DER.1 - Detektion von sicherheitsrelevanten Ereignissen compliance")
        
        results = {
            'control': 'DER.1',
            'name': 'Detektion von sicherheitsrelevanten Ereignissen',
            'status': 'COMPLIANT',
            'findings': [],
            'score': 100
        }
        
        # Mock detection capability checks
        results['findings'].append({
            'check': 'Use Case Coverage',
            'status': 'PASS',
            'description': 'All required use cases implemented and active',
            'value': '10/10 active'
        })
        
        return results
    
    def run_compliance_check(self) -> Dict[str, Any]:
        """
        Run complete BSI IT-Grundschutz compliance check
        """
        logger.info("Starting BSI IT-Grundschutz compliance check")
        
        # Run all compliance checks
        sys_1_1_results = self.check_sys_1_1_compliance()
        net_1_1_results = self.check_net_1_1_compliance()
        orp_4_results = self.check_orp_4_compliance()
        der_1_results = self.check_der_1_compliance()
        
        # Compile overall results
        all_results = [sys_1_1_results, net_1_1_results, orp_4_results, der_1_results]
        
        total_score = sum(result['score'] for result in all_results) / len(all_results)
        compliant_controls = sum(1 for result in all_results if result['status'] == 'COMPLIANT')
        
        overall_status = 'COMPLIANT' if compliant_controls == len(all_results) else 'NON-COMPLIANT'
        
        compliance_report = {
            'report_date': datetime.now().isoformat(),
            'overall_status': overall_status,
            'overall_score': round(total_score, 2),
            'compliant_controls': compliant_controls,
            'total_controls': len(all_results),
            'control_results': all_results,
            'recommendations': self.generate_recommendations(all_results)
        }
        
        return compliance_report
    
    def generate_recommendations(self, results: List[Dict[str, Any]]) -> List[str]:
        """
        Generate actionable recommendations based on compliance results
        """
        recommendations = []
        
        for result in results:
            if result['status'] == 'NON-COMPLIANT':
                recommendations.append(
                    f"Address compliance issues in {result['control']} - {result['name']}"
                )
                
                # Add specific recommendations based on failed checks
                for finding in result['findings']:
                    if finding['status'] == 'FAIL':
                        recommendations.append(
                            f"  - {finding['check']}: {finding['description']}"
                        )
        
        if not recommendations:
            recommendations.append("All BSI IT-Grundschutz controls are compliant - maintain current security posture")
        
        return recommendations
    
    def generate_report(self, results: Dict[str, Any], output_format: str = 'json') -> str:
        """
        Generate compliance report in specified format
        """
        if output_format.lower() == 'json':
            return json.dumps(results, indent=2, ensure_ascii=False)
        elif output_format.lower() == 'yaml':
            return yaml.dump(results, default_flow_style=False, allow_unicode=True)
        else:
            # Generate human-readable text report
            report_lines = [
                "BSI IT-Grundschutz Compliance Report",
                "====================================",
                f"Report Date: {results['report_date']}",
                f"Overall Status: {results['overall_status']}",
                f"Overall Score: {results['overall_score']}%",
                f"Compliant Controls: {results['compliant_controls']}/{results['total_controls']}",
                "",
                "Control Details:"
            ]
            
            for control in results['control_results']:
                report_lines.extend([
                    f"\n{control['control']} - {control['name']}",
                    f"Status: {control['status']} (Score: {control['score']}%)",
                    "Findings:"
                ])
                
                for finding in control['findings']:
                    status_symbol = "✓" if finding['status'] == 'PASS' else "✗"
                    report_lines.append(
                        f"  {status_symbol} {finding['check']}: {finding['description']}"
                    )
            
            if results['recommendations']:
                report_lines.extend([
                    "",
                    "Recommendations:"
                ])
                for rec in results['recommendations']:
                    report_lines.append(f"- {rec}")
            
            return "\n".join(report_lines)

def main():
    parser = argparse.ArgumentParser(description='BSI IT-Grundschutz Compliance Checker')
    parser.add_argument('--config', help='Configuration file path')
    parser.add_argument('--format', choices=['json', 'yaml', 'text'], default='text',
                       help='Output format (default: text)')
    parser.add_argument('--output', help='Output file path (default: stdout)')
    
    args = parser.parse_args()
    
    try:
        # Initialize compliance checker
        checker = BSIComplianceChecker(args.config)
        
        # Run compliance check
        results = checker.run_compliance_check()
        
        # Generate report
        report = checker.generate_report(results, args.format)
        
        # Output report
        if args.output:
            with open(args.output, 'w', encoding='utf-8') as f:
                f.write(report)
            logger.info(f"Compliance report written to {args.output}")
        else:
            print(report)
        
        # Exit with appropriate code
        exit_code = 0 if results['overall_status'] == 'COMPLIANT' else 1
        sys.exit(exit_code)
        
    except Exception as e:
        logger.error(f"Compliance check failed: {str(e)}")
        sys.exit(2)

if __name__ == '__main__':
    main()