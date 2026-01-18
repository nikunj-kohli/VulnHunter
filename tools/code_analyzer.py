"""
Code Analyzer Tool
==================
Analyzes code quality metrics and complexity
"""

import os
import json
from pathlib import Path
from datetime import datetime
import subprocess

class CodeAnalyzer:
    """Analyze code quality and complexity"""
    
    def __init__(self, project_root: str):
        self.project_root = Path(project_root)
        self.results = {
            'analysis_date': datetime.now().isoformat(),
            'metrics': {}
        }
    
    def analyze_complexity(self, target_path: str):
        """
        Analyze cyclomatic complexity using radon
        
        Args:
            target_path: Path to analyze
        """
        print(f"[*] Analyzing complexity for {target_path}...")
        
        cmd = ['radon', 'cc', target_path, '-a', '-j']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.stdout:
                complexity_data = json.loads(result.stdout)
                
                # Calculate average complexity
                all_complexities = []
                for file_data in complexity_data.values():
                    for item in file_data:
                        if 'complexity' in item:
                            all_complexities.append(item['complexity'])
                
                avg_complexity = sum(all_complexities) / len(all_complexities) if all_complexities else 0
                
                self.results['metrics']['cyclomatic_complexity'] = {
                    'average': avg_complexity,
                    'max': max(all_complexities) if all_complexities else 0,
                    'min': min(all_complexities) if all_complexities else 0,
                    'details': complexity_data
                }
                
                print(f"[+] Average cyclomatic complexity: {avg_complexity:.2f}")
                
                return complexity_data
            
        except Exception as e:
            print(f"[-] Complexity analysis failed: {e}")
            return None
    
    def analyze_maintainability(self, target_path: str):
        """
        Analyze maintainability index using radon
        
        Args:
            target_path: Path to analyze
        """
        print(f"[*] Analyzing maintainability for {target_path}...")
        
        cmd = ['radon', 'mi', target_path, '-j']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.stdout:
                mi_data = json.loads(result.stdout)
                
                # Calculate average maintainability
                mi_scores = [v['mi'] for v in mi_data.values() if 'mi' in v]
                avg_mi = sum(mi_scores) / len(mi_scores) if mi_scores else 0
                
                self.results['metrics']['maintainability_index'] = {
                    'average': avg_mi,
                    'details': mi_data
                }
                
                # Maintainability Index ranges:
                # 0-9: Low - Difficult to maintain
                # 10-19: Moderate
                # 20-100: High - Easy to maintain
                
                if avg_mi >= 20:
                    rating = "High (Easy to maintain)"
                elif avg_mi >= 10:
                    rating = "Moderate"
                else:
                    rating = "Low (Difficult to maintain)"
                
                print(f"[+] Average maintainability index: {avg_mi:.2f} ({rating})")
                
                return mi_data
            
        except Exception as e:
            print(f"[-] Maintainability analysis failed: {e}")
            return None
    
    def analyze_raw_metrics(self, target_path: str):
        """
        Analyze raw metrics (LOC, LLOC, comments, etc.)
        
        Args:
            target_path: Path to analyze
        """
        print(f"[*] Analyzing raw metrics for {target_path}...")
        
        cmd = ['radon', 'raw', target_path, '-j']
        
        try:
            result = subprocess.run(cmd, capture_output=True, text=True)
            
            if result.stdout:
                raw_data = json.loads(result.stdout)
                
                # Aggregate totals
                total_loc = sum(v['loc'] for v in raw_data.values() if 'loc' in v)
                total_lloc = sum(v['lloc'] for v in raw_data.values() if 'lloc' in v)
                total_comments = sum(v['comments'] for v in raw_data.values() if 'comments' in v)
                
                self.results['metrics']['raw'] = {
                    'total_lines': total_loc,
                    'logical_lines': total_lloc,
                    'comments': total_comments,
                    'comment_ratio': (total_comments / total_loc * 100) if total_loc > 0 else 0,
                    'details': raw_data
                }
                
                print(f"[+] Lines of code: {total_loc}")
                print(f"[+] Logical lines: {total_lloc}")
                print(f"[+] Comments: {total_comments}")
                print(f"[+] Comment ratio: {self.results['metrics']['raw']['comment_ratio']:.1f}%")
                
                return raw_data
            
        except Exception as e:
            print(f"[-] Raw metrics analysis failed: {e}")
            return None
    
    def count_files(self, target_path: str):
        """Count Python files"""
        
        py_files = list(Path(target_path).rglob('*.py'))
        
        self.results['file_count'] = len(py_files)
        
        print(f"[+] Python files: {len(py_files)}")
        
        return len(py_files)
    
    def generate_report(self, output_file: str):
        """Generate analysis report"""
        
        report = f"""# Code Analysis Report

**Analysis Date**: {self.results['analysis_date']}

## Summary

- **Python Files**: {self.results.get('file_count', 'N/A')}
- **Total Lines of Code**: {self.results['metrics'].get('raw', {}).get('total_lines', 'N/A')}
- **Logical Lines**: {self.results['metrics'].get('raw', {}).get('logical_lines', 'N/A')}
- **Comments**: {self.results['metrics'].get('raw', {}).get('comments', 'N/A')}

## Code Quality Metrics

### Cyclomatic Complexity

- **Average**: {self.results['metrics'].get('cyclomatic_complexity', {}).get('average', 'N/A'):.2f}
- **Maximum**: {self.results['metrics'].get('cyclomatic_complexity', {}).get('max', 'N/A')}
- **Minimum**: {self.results['metrics'].get('cyclomatic_complexity', {}).get('min', 'N/A')}

**Interpretation**:
- 1-10: Simple, easy to test
- 11-20: Moderate complexity
- 21-50: Complex, difficult to test
- >50: Very complex, high risk

### Maintainability Index

- **Average**: {self.results['metrics'].get('maintainability_index', {}).get('average', 'N/A'):.2f}

**Interpretation**:
- 20-100: High (Easy to maintain)
- 10-19: Moderate
- 0-9: Low (Difficult to maintain)

### Comments

- **Comment Ratio**: {self.results['metrics'].get('raw', {}).get('comment_ratio', 'N/A'):.1f}%

Recommended: 20-30% for good documentation

"""
        
        with open(output_file, 'w') as f:
            f.write(report)
        
        print(f"[+] Analysis report saved to {output_file}")
    
    def compare_analyses(self, before_results: dict, after_results: dict):
        """Compare two code analyses"""
        
        print("\n[*] Code Quality Comparison:")
        
        before_complexity = before_results['metrics'].get('cyclomatic_complexity', {}).get('average', 0)
        after_complexity = after_results['metrics'].get('cyclomatic_complexity', {}).get('average', 0)
        
        before_mi = before_results['metrics'].get('maintainability_index', {}).get('average', 0)
        after_mi = after_results['metrics'].get('maintainability_index', {}).get('average', 0)
        
        print(f"  Complexity:")
        print(f"    Before: {before_complexity:.2f}")
        print(f"    After: {after_complexity:.2f}")
        print(f"    Change: {after_complexity - before_complexity:+.2f}")
        
        print(f"\n  Maintainability:")
        print(f"    Before: {before_mi:.2f}")
        print(f"    After: {after_mi:.2f}")
        print(f"    Change: {after_mi - before_mi:+.2f}")
        
        return {
            'complexity_before': before_complexity,
            'complexity_after': after_complexity,
            'maintainability_before': before_mi,
            'maintainability_after': after_mi
        }

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Code Analyzer for VulnHunter')
    parser.add_argument('target', help='Target directory to analyze')
    parser.add_argument('--output', '-o', default='analysis/code_metrics', help='Output directory')
    parser.add_argument('--name', '-n', default='analysis', help='Analysis name')
    
    args = parser.parse_args()
    
    project_root = Path(__file__).parent.parent
    analyzer = CodeAnalyzer(project_root)
    
    # Run all analyses
    analyzer.count_files(args.target)
    analyzer.analyze_raw_metrics(args.target)
    analyzer.analyze_complexity(args.target)
    analyzer.analyze_maintainability(args.target)
    
    # Create output directory
    output_dir = project_root / args.output
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save results
    json_output = output_dir / f'{args.name}.json'
    with open(json_output, 'w') as f:
        json.dump(analyzer.results, f, indent=2)
    
    # Generate report
    report_output = output_dir / f'{args.name}_report.md'
    analyzer.generate_report(str(report_output))
    
    print(f"\n[+] Code analysis complete!")

if __name__ == '__main__':
    main()
