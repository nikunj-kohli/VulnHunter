# 🔍 VulnHunter: AI-Powered Security Refactoring Analysis

> **⚠️ Educational Project Warning**: This repository contains **deliberately vulnerable code** for security education and AI capability testing. **DO NOT deploy any code from this repository in production environments.**

## 📖 Overview

VulnHunter is a comprehensive security research project that evaluates the capabilities and limitations of various AI models (Claude, ChatGPT, Gemini, GitHub Copilot) in identifying and fixing security vulnerabilities in Python Flask applications.

### Key Features

- **30+ Intentional Vulnerabilities**: Including SQL injection, XSS, command injection, and more
- **Multi-AI Comparison**: Side-by-side analysis of security fixes from different AI models
- **Automated Testing**: Comprehensive security test suite using pytest
- **Performance Benchmarking**: Before/after performance analysis
- **Security Scanning**: Integration with Bandit, Safety, and custom scanners
- **Interactive Demo**: Docker-based vulnerable/secure app comparison

## 🎯 Project Goals

1. **Evaluate AI Security Capabilities**: Test how well AI models identify and fix vulnerabilities
2. **Document AI Limitations**: Identify what AIs miss or incorrectly fix
3. **Educational Resource**: Teach security best practices through examples
4. **Methodology Development**: Create a framework for AI-assisted security refactoring

## 📁 Project Structure

```
VulnHunter/
├── original_code/              # Deliberately vulnerable applications
│   ├── vulnerable_app/         # Main Flask app with 30+ vulnerabilities
│   └── other_examples/         # Specific vulnerability demonstrations
├── ai_refactored/              # AI-generated secure versions
│   ├── claude_refactored/      # Claude's analysis and fixes
│   ├── chatgpt_refactored/     # ChatGPT's analysis and fixes
│   ├── gemini_refactored/      # Gemini's analysis and fixes
│   └── copilot_refactored/     # Copilot's analysis and fixes
├── final_refactored/           # Production-ready secure version
├── tests/                      # Comprehensive security test suite
├── tools/                      # Analysis and scanning tools
├── scripts/                    # Automation scripts
├── analysis/                   # Security scan results and reports
└── docs/                       # Documentation

```

## 🚀 Quick Start

### Prerequisites

- Python 3.8+
- pip
- virtualenv (recommended)
- Docker (optional, for containerized demos)

### Installation

```bash
# Clone the repository
git clone https://github.com/yourusername/VulnHunter.git
cd VulnHunter

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

### Running the Vulnerable Application

```bash
cd original_code/vulnerable_app
python app.py
```

The application will be available at `http://localhost:5000`

**Default credentials:**
- Username: `admin` / Password: `admin123`
- Username: `user1` / Password: `password`

### Running Security Tests

```bash
# Run all security tests
pytest tests/test_security.py -v

# Run specific test category
pytest tests/test_security.py::TestSQLInjection -v

# Generate coverage report
pytest tests/ --cov=original_code --cov-report=html
```

### Running Security Scans

```bash
# Scan vulnerable application
python tools/security_scanner.py original_code/vulnerable_app --name vulnerable --report

# Scan refactored version
python tools/security_scanner.py final_refactored --name secure --report

# Compare results
python tools/security_scanner.py --compare analysis/security_scan_results/
```

## 🐛 Vulnerability Catalog

The vulnerable application includes **30+ security vulnerabilities** across multiple categories:

### Critical Vulnerabilities

1. **SQL Injection** (OWASP A03)
   - Location: `/search`, `/login`, `/profile`
   - Exploit: `?q=' OR '1'='1`

2. **Command Injection** (OWASP A03)
   - Location: `/execute`
   - Exploit: `?cmd=whoami; cat /etc/passwd`

3. **Insecure Deserialization** (OWASP A08)
   - Location: `/deserialize`
   - Exploit: Malicious pickle payload

### High Severity

4. **Cross-Site Scripting (XSS)** (OWASP A03)
   - Locations: `/search`, `/messages`, `/profile`
   - Exploit: `?q=<script>alert('XSS')</script>`

5. **Path Traversal** (OWASP A01)
   - Location: `/download`
   - Exploit: `?file=../../etc/passwd`

6. **Hardcoded Credentials** (OWASP A07)
   - Location: Source code
   - Issue: API keys and passwords in code

7. **Insecure File Upload** (OWASP A04)
   - Location: `/upload`
   - Issue: No file type validation

8. **Broken Access Control** (OWASP A01)
   - Locations: `/admin`, `/profile/<id>`
   - Issue: No authentication required

### Medium Severity

9. **Missing CSRF Protection** (OWASP A01)
10. **Information Disclosure** (OWASP A05)
11. **Weak Session Management** (OWASP A07)
12. **Debug Mode Enabled** (OWASP A05)
13. **Missing Security Headers** (OWASP A05)
14. **Sensitive Data Exposure** (OWASP A02)
15. **No Rate Limiting** (OWASP A04)

[See full list in docs/vulnerability_types.md]

## 🤖 AI Analysis Results

### Performance Summary

| AI Model | Vulnerabilities Found | Fix Accuracy | Code Quality | Overall Score |
|----------|----------------------|--------------|--------------|---------------|
| Claude 3.5 | TBD | TBD | TBD | TBD/100 |
| ChatGPT-4 | TBD | TBD | TBD | TBD/100 |
| Gemini Pro | TBD | TBD | TBD | TBD/100 |
| Copilot | TBD | TBD | TBD | TBD/100 |

*Results will be updated after running AI experiments*

### Key Findings

#### What AIs Do Well
- Identifying common vulnerabilities (SQL injection, XSS)
- Suggesting parameterized queries
- Adding input validation
- Improving code structure

#### What AIs Miss
- Business logic vulnerabilities
- Complex authentication bypasses
- Subtle timing attacks
- Configuration issues

#### AI Limitations
- May introduce new bugs
- Sometimes over-complicate fixes
- Can miss context-specific issues
- Inconsistent across runs

[Detailed analysis in ai_refactored/*/AI_ANALYSIS.md]

## 📊 Security Metrics

### Before Refactoring
```
Bandit Issues: XX
Safety Vulnerabilities: XX
Cyclomatic Complexity: XX
Maintainability Index: XX
```

### After Refactoring
```
Bandit Issues: XX
Safety Vulnerabilities: XX
Cyclomatic Complexity: XX
Maintainability Index: XX
Improvement: XX%
```

## 🔬 Testing & Analysis Tools

### Security Scanner
```bash
python tools/security_scanner.py <target_path> --report
```

### Performance Tester
```bash
python tools/performance_tester.py --url http://localhost:5000 --requests 100
```

### Code Analyzer
```bash
python tools/code_analyzer.py <target_path> --name analysis
```

### Vulnerability Injector
```bash
python tools/vulnerability_injector.py --url http://localhost:5000 --all
```

## 🐳 Docker Deployment

```bash
# Build and run vulnerable app
docker-compose up vulnerable_app

# Build and run secure app
docker-compose up secure_app

# Run both for comparison
docker-compose up
```

Access:
- Vulnerable app: http://localhost:8080
- Secure app: http://localhost:8081
- 
## 🎓 Educational Use

This project is designed for:
- **Security Students**: Learn about common vulnerabilities
- **Developers**: Understand secure coding practices
- **Researchers**: Study AI capabilities in security
- **CTF Practice**: Hands-on exploitation experience

### Learning Path

1. **Study the vulnerable code**: Understand each vulnerability
2. **Try exploits**: Use the vulnerability injector
3. **Review AI fixes**: See how different AIs approach security
4. **Implement fixes**: Practice secure coding
5. **Run tests**: Verify your fixes work

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Add tests for new vulnerabilities
4. Submit a pull request


## ⚖️ Legal & Ethical Use

### Educational Purpose Only

This code is provided **solely for educational purposes**. You must:

✅ **DO:**
- Use in controlled test environments
- Learn about security vulnerabilities
- Practice secure coding
- Test security tools

❌ **DON'T:**
- Deploy in production
- Use on systems you don't own
- Attack real websites
- Share exploits maliciously

### Disclaimer

The authors are not responsible for misuse of this code. Always obtain proper authorization before testing security vulnerabilities.


**Note**: The MIT license does NOT grant permission to use this code for malicious purposes. This project is for educational use only.

## 🙏 Acknowledgments

- OWASP for vulnerability classifications
- Python security community
- AI model providers (Anthropic, OpenAI, Google)
- Security researchers and educators



---

**⭐ If you find this project useful, please give it a star!**

**🐛 Found a vulnerability we missed? Open an issue!**

**💡 Have ideas for improvement? We'd love to hear them!**

---

*Last Updated: January 2026*
