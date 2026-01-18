"""
Security Scanner Tool
====================
Automated security scanning using Bandit and custom checks
"""

import subprocess
import json
import os
import sys
from pathlib import Path
from datetime import datetime
from typing import Dict, List

class SecurityScanner:
    """Comprehensive security scanner for Python code"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.results = {
            'scan_date': datetime.now().isoformat(),
            'bandit': {},
            'custom_checks': {},
            'summary': {}
        }
    
    def run_bandit_scan(self, target_path: str, output_file: str = None):
        """
        Run Bandit security scanner on target code
        
        Args:
            target_path: Path to code to scan
            output_file: Optional JSON output file path
        """
        print(f"[*] Running Bandit scan on {target_path}...")
        
        cmd = [
            'bandit',
            '-r',  # Recursive
            target_path,
            '-f', 'json',  # JSON format
            '-ll',  # Report only issues of medium severity or higher
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            # Bandit returns non-zero exit code when vulnerabilities are found
            output = json.loads(result.stdout) if result.stdout else {}
            
            self.results['bandit'] = {
                'target': target_path,
                'issues_found': len(output.get('results', [])),
                'output': output
            }
            
            # Save to file if specified
            if output_file:
                with open(output_file, 'w') as f:
                    json.dump(output, f, indent=2)
                print(f"[+] Bandit results saved to {output_file}")
            
            # Print summary
            metrics = output.get('metrics', {})
            total_issues = sum(
                m.get('SEVERITY.MEDIUM', 0) + m.get('SEVERITY.HIGH', 0)
                for m in metrics.values()
            )
            
            print(f"[+] Bandit scan complete: {len(output.get('results', []))} issues found")
            
            return output
            
        except subprocess.CalledProcessError as e:
            print(f"[-] Bandit scan failed: {e}")
            return None
        except json.JSONDecodeError as e:
            print(f"[-] Failed to parse Bandit output: {e}")
            return None
    
    def run_safety_check(self, requirements_file: str):
        """
        Run Safety check on dependencies
        
        Args:
            requirements_file: Path to requirements.txt
        """
        print(f"[*] Running Safety check on {requirements_file}...")
        
        cmd = [
            'safety',
            'check',
            '--file', requirements_file,
            '--json'
        ]
        
        try:
            result = subprocess.run(
                cmd,
                capture_output=True,
                text=True
            )
            
            output = json.loads(result.stdout) if result.stdout else []
            
            self.results['safety'] = {
                'vulnerable_packages': len(output),
                'details': output
            }
            
            print(f"[+] Safety check complete: {len(output)} vulnerable packages found")
            
            return output
            
        except Exception as e:
            print(f"[-] Safety check failed: {e}")
            return None
    
    def custom_security_checks(self, target_path: str):
        """
        Run custom security checks
        
        Args:
            target_path: Path to code to scan
        """
        print(f"[*] Running custom security checks...")
        
        issues = []
        
        for py_file in Path(target_path).rglob('*.py'):
            with open(py_file, 'r', encoding='utf-8') as f:
                content = f.read()
                line_num = 0
                
                for line in content.split('\n'):
                    line_num += 1
                    
                    # Check for hardcoded credentials
                    if any(keyword in line.lower() for keyword in [
                        'password = "', 'password="', "password = '", "password='",
                        'api_key = "', 'api_key="', 'secret = "', 'secret="',
                        'token = "', 'token="'
                    ]):
                        if not line.strip().startswith('#'):
                            issues.append({
                                'file': str(py_file.relative_to(self.project_root)),
                                'line': line_num,
                                'issue': 'Hardcoded credential',
                                'severity': 'HIGH',
                                'code': line.strip()
                            })
                    
                    # Check for SQL string concatenation
                    if 'execute(' in line and 'f"' in line or '.format(' in line:
                        if 'SELECT' in line or 'INSERT' in line or 'UPDATE' in line or 'DELETE' in line:
                            issues.append({
                                'file': str(py_file.relative_to(self.project_root)),
                                'line': line_num,
                                'issue': 'Possible SQL injection',
                                'severity': 'CRITICAL',
                                'code': line.strip()
                            })
                    
                    # Check for eval/exec usage
                    if 'eval(' in line or 'exec(' in line:
                        issues.append({
                            'file': str(py_file.relative_to(self.project_root)),
                            'line': line_num,
                            'issue': 'Dangerous function: eval/exec',
                            'severity': 'CRITICAL',
                            'code': line.strip()
                        })
                    
                    # Check for pickle usage
                    if 'pickle.loads(' in line:
                        issues.append({
                            'file': str(py_file.relative_to(self.project_root)),
                            'line': line_num,
                            'issue': 'Insecure deserialization',
                            'severity': 'HIGH',
                            'code': line.strip()
                        })
                    
                    # Check for shell=True
                    if 'shell=True' in line:
                        issues.append({
                            'file': str(py_file.relative_to(self.project_root)),
                            'line': line_num,
                            'issue': 'Command injection risk',
                            'severity': 'HIGH',
                            'code': line.strip()
                        })
                    
                    # Check for debug=True
                    if 'debug=True' in line or 'DEBUG = True' in line:
                        issues.append({
                            'file': str(py_file.relative_to(self.project_root)),
                            'line': line_num,
                            'issue': 'Debug mode enabled',
                            'severity': 'MEDIUM',
                            'code': line.strip()
                        })
        
        self.results['custom_checks'] = {
            'issues_found': len(issues),
            'issues': issues
        }
        
        print(f"[+] Custom checks complete: {len(issues)} issues found")
        
        # Print issues by severity
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_issues = [i for i in issues if i['severity'] == severity]
            if severity_issues:
                print(f"  {severity}: {len(severity_issues)} issues")
        
        return issues
    
    def generate_report(self, output_file: str = 'security_report.md'):
        """Generate markdown security report"""
        
        report = f"""# Security Scan Report

**Scan Date**: {self.results['scan_date']}

## Summary

"""
        
        # Bandit summary
        bandit_issues = self.results.get('bandit', {}).get('issues_found', 0)
        report += f"- **Bandit Issues**: {bandit_issues}\n"
        
        # Custom checks summary
        custom_issues = self.results.get('custom_checks', {}).get('issues_found', 0)
        report += f"- **Custom Check Issues**: {custom_issues}\n"
        
        # Safety summary
        vuln_packages = len(self.results.get('safety', {}).get('details', []))
        report += f"- **Vulnerable Dependencies**: {vuln_packages}\n\n"
        
        # Total
        total = bandit_issues + custom_issues
        report += f"**Total Issues Found**: {total}\n\n"
        
        # Severity breakdown
        report += "## Issues by Severity\n\n"
        
        custom_issues_list = self.results.get('custom_checks', {}).get('issues', [])
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
            severity_count = len([i for i in custom_issues_list if i['severity'] == severity])
            report += f"- **{severity}**: {severity_count}\n"
        
        report += "\n## Custom Security Check Details\n\n"
        
        for issue in custom_issues_list:
            report += f"### {issue['issue']} ({issue['severity']})\n\n"
            report += f"- **File**: `{issue['file']}`\n"
            report += f"- **Line**: {issue['line']}\n"
            report += f"- **Code**: `{issue['code']}`\n\n"
        
        # Save report
        output_path = self.project_root / output_file
        with open(output_path, 'w') as f:
            f.write(report)
        
        print(f"[+] Security report generated: {output_path}")
        
        return report
    
    def compare_scans(self, before_scan: Dict, after_scan: Dict):
        """Compare two security scans"""
        
        before_count = before_scan.get('bandit', {}).get('issues_found', 0)
        after_count = after_scan.get('bandit', {}).get('issues_found', 0)
        
        improvement = before_count - after_count
        improvement_pct = (improvement / before_count * 100) if before_count > 0 else 0
        
        print(f"\n[*] Scan Comparison:")
        print(f"  Before: {before_count} issues")
        print(f"  After:  {after_count} issues")
        print(f"  Improvement: {improvement} issues ({improvement_pct:.1f}%)")
        
        return {
            'before': before_count,
            'after': after_count,
            'improvement': improvement,
            'improvement_percentage': improvement_pct
        }

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Security Scanner for VulnHunter')
    parser.add_argument('target', help='Target directory to scan')
    parser.add_argument('--output', '-o', help='Output directory for results', default='analysis/security_scan_results')
    parser.add_argument('--report', '-r', help='Generate markdown report', action='store_true')
    parser.add_argument('--name', '-n', help='Scan name (e.g., original, refactored)', default='scan')
    
    args = parser.parse_args()
    
    # Get project root (assuming this script is in tools/)
    project_root = Path(__file__).parent.parent
    
    scanner = SecurityScanner(project_root)
    
    # Create output directory
    output_dir = project_root / args.output
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Run Bandit scan
    bandit_output = output_dir / f'bandit_{args.name}.json'
    scanner.run_bandit_scan(args.target, str(bandit_output))
    
    # Run custom checks
    scanner.custom_security_checks(args.target)
    
    # Check dependencies if requirements.txt exists
    requirements = project_root / args.target / 'requirements.txt'
    if requirements.exists():
        scanner.run_safety_check(str(requirements))
    
    # Generate report if requested
    if args.report:
        report_path = output_dir / f'security_report_{args.name}.md'
        scanner.generate_report(str(report_path))
    
    # Save full results as JSON
    results_file = output_dir / f'full_results_{args.name}.json'
    with open(results_file, 'w') as f:
        json.dump(scanner.results, f, indent=2)
    
    print(f"\n[+] Scan complete! Results saved to {output_dir}")

if __name__ == '__main__':
    main()
