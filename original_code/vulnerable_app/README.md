# Vulnerable Flask Application

## ⚠️ WARNING: EDUCATIONAL USE ONLY

This is a **deliberately vulnerable** Flask application created for security education and testing purposes. **DO NOT deploy this in any production environment.**

## Purpose

This application demonstrates 30+ common web application security vulnerabilities including:

- SQL Injection
- Cross-Site Scripting (XSS)
- Command Injection
- Insecure Deserialization
- Path Traversal
- Broken Authentication
- Sensitive Data Exposure
- And many more...

## Installation

```bash
cd original_code/vulnerable_app
pip install -r requirements.txt
```

## Running the Application

```bash
python app.py
```

The application will start on `http://localhost:5000`

## Default Credentials

- Username: `admin` / Password: `admin123`
- Username: `user1` / Password: `password`
- Username: `test` / Password: `test`

## Vulnerability Catalog

### 1. SQL Injection (High)
- **Location**: `/search` endpoint
- **Exploit**: `?q=' OR '1'='1`

### 2. Cross-Site Scripting - XSS (High)
- **Location**: `/search`, `/messages`, profile pages
- **Exploit**: `?q=<script>alert('XSS')</script>`

### 3. Command Injection (Critical)
- **Location**: `/execute` endpoint
- **Exploit**: `?cmd=whoami`

### 4. Insecure Deserialization (Critical)
- **Location**: `/deserialize` endpoint
- **Exploit**: Malicious pickle payload

### 5. Path Traversal (High)
- **Location**: `/download` endpoint
- **Exploit**: `?file=../../etc/passwd`

### 6. Hardcoded Credentials (High)
- **Location**: Source code
- **Issue**: Admin password and API keys in code

### 7. Information Disclosure (Medium)
- **Location**: `/debug` endpoint
- **Issue**: Exposes configuration and environment

### 8. Broken Access Control (High)
- **Location**: `/admin`, `/profile/<id>` endpoints
- **Issue**: No authentication required

### 9. Insecure File Upload (High)
- **Location**: `/upload` endpoint
- **Issue**: No file type validation

### 10. Missing CSRF Protection (Medium)
- **Location**: All POST endpoints
- **Issue**: No CSRF tokens

## Testing Exploits

See the `../../tools/vulnerability_injector.py` script for automated exploit testing.

## Educational Use

This application is designed to help developers:
1. Understand common security vulnerabilities
2. Learn how to identify security issues
3. Practice secure coding techniques
4. Test security scanning tools

## Legal Notice

This code is provided for educational purposes only. Misuse of this code for unauthorized testing or malicious purposes is illegal and unethical. Always obtain proper authorization before testing security vulnerabilities.
