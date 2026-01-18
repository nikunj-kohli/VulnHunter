"""
Performance Testing Tool
========================
Load testing and performance benchmarking
"""

import time
import statistics
import subprocess
import json
from pathlib import Path
from datetime import datetime
from typing import List, Dict
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed

class PerformanceTester:
    """Performance and load testing tool"""
    
    def __init__(self, base_url: str = 'http://localhost:5000'):
        self.base_url = base_url
        self.results = {
            'test_date': datetime.now().isoformat(),
            'base_url': base_url,
            'tests': []
        }
    
    def response_time_test(self, endpoint: str, num_requests: int = 100):
        """
        Test response time for an endpoint
        
        Args:
            endpoint: API endpoint to test
            num_requests: Number of requests to make
        """
        print(f"[*] Testing response time for {endpoint} ({num_requests} requests)...")
        
        url = f"{self.base_url}{endpoint}"
        response_times = []
        errors = 0
        
        for i in range(num_requests):
            try:
                start = time.time()
                response = requests.get(url, timeout=10)
                end = time.time()
                
                response_time = (end - start) * 1000  # Convert to milliseconds
                response_times.append(response_time)
                
                if response.status_code != 200:
                    errors += 1
                    
            except Exception as e:
                errors += 1
                print(f"[!] Request {i+1} failed: {e}")
        
        if response_times:
            result = {
                'endpoint': endpoint,
                'num_requests': num_requests,
                'successful_requests': len(response_times),
                'failed_requests': errors,
                'min_time': min(response_times),
                'max_time': max(response_times),
                'avg_time': statistics.mean(response_times),
                'median_time': statistics.median(response_times),
                'std_dev': statistics.stdev(response_times) if len(response_times) > 1 else 0
            }
            
            self.results['tests'].append(result)
            
            print(f"[+] Results:")
            print(f"    Min: {result['min_time']:.2f}ms")
            print(f"    Max: {result['max_time']:.2f}ms")
            print(f"    Avg: {result['avg_time']:.2f}ms")
            print(f"    Median: {result['median_time']:.2f}ms")
            print(f"    Errors: {errors}")
            
            return result
        
        return None
    
    def concurrent_load_test(self, endpoint: str, num_concurrent: int = 10, num_requests: int = 100):
        """
        Test concurrent load
        
        Args:
            endpoint: API endpoint to test
            num_concurrent: Number of concurrent users
            num_requests: Total number of requests
        """
        print(f"[*] Load testing {endpoint} with {num_concurrent} concurrent users...")
        
        url = f"{self.base_url}{endpoint}"
        response_times = []
        errors = 0
        
        def make_request():
            try:
                start = time.time()
                response = requests.get(url, timeout=10)
                end = time.time()
                return (end - start) * 1000, response.status_code
            except Exception as e:
                return None, None
        
        start_time = time.time()
        
        with ThreadPoolExecutor(max_workers=num_concurrent) as executor:
            futures = [executor.submit(make_request) for _ in range(num_requests)]
            
            for future in as_completed(futures):
                response_time, status_code = future.result()
                if response_time:
                    response_times.append(response_time)
                    if status_code != 200:
                        errors += 1
                else:
                    errors += 1
        
        end_time = time.time()
        total_time = end_time - start_time
        
        if response_times:
            result = {
                'endpoint': endpoint,
                'test_type': 'concurrent_load',
                'concurrent_users': num_concurrent,
                'total_requests': num_requests,
                'successful_requests': len(response_times),
                'failed_requests': errors,
                'total_time': total_time,
                'requests_per_second': num_requests / total_time,
                'min_time': min(response_times),
                'max_time': max(response_times),
                'avg_time': statistics.mean(response_times),
                'median_time': statistics.median(response_times)
            }
            
            self.results['tests'].append(result)
            
            print(f"[+] Load test results:")
            print(f"    Total time: {total_time:.2f}s")
            print(f"    Requests/sec: {result['requests_per_second']:.2f}")
            print(f"    Avg response: {result['avg_time']:.2f}ms")
            print(f"    Errors: {errors}")
            
            return result
        
        return None
    
    def memory_usage_test(self, endpoint: str, num_requests: int = 100):
        """
        Monitor memory usage during requests
        
        Note: This is a basic implementation. For production, use tools like memory_profiler
        """
        print(f"[*] Memory usage test for {endpoint}...")
        
        import psutil
        import os
        
        process = psutil.Process(os.getpid())
        
        memory_before = process.memory_info().rss / 1024 / 1024  # MB
        
        url = f"{self.base_url}{endpoint}"
        for _ in range(num_requests):
            try:
                requests.get(url, timeout=10)
            except:
                pass
        
        memory_after = process.memory_info().rss / 1024 / 1024  # MB
        memory_diff = memory_after - memory_before
        
        result = {
            'endpoint': endpoint,
            'test_type': 'memory_usage',
            'memory_before_mb': memory_before,
            'memory_after_mb': memory_after,
            'memory_increase_mb': memory_diff
        }
        
        print(f"[+] Memory usage:")
        print(f"    Before: {memory_before:.2f} MB")
        print(f"    After: {memory_after:.2f} MB")
        print(f"    Increase: {memory_diff:.2f} MB")
        
        return result
    
    def generate_report(self, output_file: str):
        """Generate performance report"""
        
        report = f"""# Performance Test Report

**Test Date**: {self.results['test_date']}
**Target**: {self.results['base_url']}

## Summary

"""
        
        for test in self.results['tests']:
            report += f"### {test['endpoint']}\n\n"
            
            if test.get('test_type') == 'concurrent_load':
                report += f"- **Test Type**: Concurrent Load Test\n"
                report += f"- **Concurrent Users**: {test['concurrent_users']}\n"
                report += f"- **Total Requests**: {test['total_requests']}\n"
                report += f"- **Successful**: {test['successful_requests']}\n"
                report += f"- **Failed**: {test['failed_requests']}\n"
                report += f"- **Requests/sec**: {test['requests_per_second']:.2f}\n"
                report += f"- **Average Response**: {test['avg_time']:.2f}ms\n"
            else:
                report += f"- **Requests**: {test.get('num_requests', 'N/A')}\n"
                report += f"- **Min Response**: {test.get('min_time', 'N/A'):.2f}ms\n"
                report += f"- **Max Response**: {test.get('max_time', 'N/A'):.2f}ms\n"
                report += f"- **Avg Response**: {test.get('avg_time', 'N/A'):.2f}ms\n"
            
            report += "\n"
        
        with open(output_file, 'w') as f:
            f.write(report)
        
        print(f"[+] Performance report saved to {output_file}")
    
    def compare_performance(self, before_results: Dict, after_results: Dict):
        """Compare performance between two versions"""
        
        print("\n[*] Performance Comparison:")
        
        # Compare response times
        before_avg = statistics.mean([t['avg_time'] for t in before_results['tests'] if 'avg_time' in t])
        after_avg = statistics.mean([t['avg_time'] for t in after_results['tests'] if 'avg_time' in t])
        
        improvement = ((before_avg - after_avg) / before_avg) * 100
        
        print(f"  Before avg: {before_avg:.2f}ms")
        print(f"  After avg: {after_avg:.2f}ms")
        print(f"  Improvement: {improvement:.1f}%")
        
        return {
            'before_avg': before_avg,
            'after_avg': after_avg,
            'improvement_percentage': improvement
        }

def main():
    """Main function"""
    import argparse
    
    parser = argparse.ArgumentParser(description='Performance Tester for VulnHunter')
    parser.add_argument('--url', default='http://localhost:5000', help='Base URL to test')
    parser.add_argument('--output', '-o', default='analysis/performance_benchmarks', help='Output directory')
    parser.add_argument('--name', '-n', default='test', help='Test name')
    parser.add_argument('--concurrent', '-c', type=int, default=10, help='Number of concurrent users')
    parser.add_argument('--requests', '-r', type=int, default=100, help='Number of requests')
    
    args = parser.parse_args()
    
    tester = PerformanceTester(args.url)
    
    # Common endpoints to test
    endpoints = ['/', '/search?q=test', '/api/users', '/messages']
    
    print(f"[*] Starting performance tests on {args.url}\n")
    
    for endpoint in endpoints:
        try:
            # Response time test
            tester.response_time_test(endpoint, num_requests=args.requests)
            print()
            
            # Concurrent load test
            tester.concurrent_load_test(endpoint, num_concurrent=args.concurrent, num_requests=args.requests)
            print()
        except Exception as e:
            print(f"[!] Failed to test {endpoint}: {e}\n")
    
    # Create output directory
    output_dir = Path(args.output)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    # Save results
    json_output = output_dir / f'{args.name}_performance.json'
    with open(json_output, 'w') as f:
        json.dump(tester.results, f, indent=2)
    
    # Generate report
    report_output = output_dir / f'{args.name}_performance_report.md'
    tester.generate_report(str(report_output))
    
    print(f"\n[+] Performance testing complete!")

if __name__ == '__main__':
    main()
