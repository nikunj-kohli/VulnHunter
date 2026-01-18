# How to Use VulnHunter

This guide explains how to use the VulnHunter project for learning about security vulnerabilities and testing AI capabilities.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Running the Vulnerable App](#running-the-vulnerable-app)
3. [Testing Vulnerabilities](#testing-vulnerabilities)
4. [AI Analysis](#ai-analysis)
5. [Security Scanning](#security-scanning)
6. [Performance Testing](#performance-testing)
7. [Docker Usage](#docker-usage)

---

## Quick Start

### Setup

```bash
# Clone the repository
git clone https://github.com/yourusername/VulnHunter.git
cd VulnHunter

# Create virtual environment
python -m venv venv

# Activate (Linux/Mac)
source venv/bin/activate

# Activate (Windows)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
```

---

## Running the Vulnerable App

### Local Development

```bash
cd original_code/vulnerable_app
python app.py
```

Visit: http://localhost:5000

### Default Credentials

- **Admin**: username=`admin`, password=`admin123`
- **User**: username=`user1`, password=`password`
- **Test**: username=`test`, password=`test`

### Available Endpoints

| Endpoint | Description | Vulnerabilities |
|----------|-------------|-----------------|
| `/` | Home page | XSS in search form |
| `/search?q=` | User search | SQL Injection, XSS |
| `/login` | Login form | SQL Injection, No CSRF |
| `/admin` | Admin panel | No authentication |
| `/messages` | Message board | XSS, No auth |
| `/upload` | File upload | Path traversal, No validation |
| `/execute?cmd=` | Command executor | Command injection |
| `/download?file=` | File download | Path traversal |
| `/debug` | Debug info | Information disclosure |
| `/api/users` | User API | Data exposure, No auth |

---

## Testing Vulnerabilities

### Manual Testing

#### 1. SQL Injection

```bash
# Basic OR bypass
http://localhost:5000/search?q=' OR '1'='1

# Authentication bypass
POST /login
username: admin' --
password: anything

# UNION attack
http://localhost:5000/search?q=' UNION SELECT 1,2,3--
```

#### 2. Cross-Site Scripting (XSS)

```bash
# Reflected XSS
http://localhost:5000/search?q=<script>alert('XSS')</script>

# Stored XSS
POST /post_message
message: <script>document.cookie</script>

# Various payloads
<img src=x onerror=alert(1)>
<svg onload=alert(1)>
```

#### 3. Command Injection

```bash
# Basic command
http://localhost:5000/execute?cmd=whoami

# Command chaining (Linux)
http://localhost:5000/execute?cmd=echo test; cat /etc/passwd

# Command chaining (Windows)
http://localhost:5000/execute?cmd=echo test & dir
```

#### 4. Path Traversal

```bash
# Unix
http://localhost:5000/download?file=../../etc/passwd

# Windows
http://localhost:5000/download?file=..\..\windows\system32\config\sam

# Encoded
http://localhost:5000/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### Automated Testing

#### Using Vulnerability Injector

```bash
# Test all vulnerabilities
python tools/vulnerability_injector.py --url http://localhost:5000 --all

# Test specific categories
python tools/vulnerability_injector.py --url http://localhost:5000 --sqli
python tools/vulnerability_injector.py --url http://localhost:5000 --xss
python tools/vulnerability_injector.py --url http://localhost:5000 --cmd
```

#### Using Pytest

```bash
# Run all security tests
pytest tests/test_security.py -v

# Run specific test class
pytest tests/test_security.py::TestSQLInjection -v

# Generate coverage report
pytest tests/ --cov=original_code --cov-report=html
```

---

## AI Analysis

### Preparing Code for AI

1. **Select Code to Analyze**
   ```bash
   # View the vulnerable app code
   cat original_code/vulnerable_app/app.py
   ```

2. **Choose a Prompt Template**
   ```bash
   # View available prompts
   cat ai_refactored/PROMPT_TEMPLATES.md
   ```

3. **Submit to AI**
   - Copy the code
   - Use the chosen prompt
   - Save the response

### Documenting AI Results

1. **Create Analysis File**
   ```bash
   # For Claude
   nano ai_refactored/claude_refactored/AI_ANALYSIS.md
   ```

2. **Document Findings**
   - List vulnerabilities found
   - Save refactored code
   - Note strengths and weaknesses
   - Test the AI's fixes

3. **Test AI Fixes**
   ```bash
   # Save AI-generated code
   # Run security tests against it
   pytest tests/ -v
   
   # Run security scan
   python tools/security_scanner.py ai_refactored/claude_refactored/ --report
   ```

### Comparing AI Outputs

```bash
# Use comparison tools
python tools/report_generator.py --compare \
    ai_refactored/claude_refactored/ \
    ai_refactored/chatgpt_refactored/ \
    ai_refactored/gemini_refactored/
```

---

## Security Scanning

### Bandit Scan

```bash
# Scan vulnerable app
bandit -r original_code/vulnerable_app/ -f json -o bandit_results.json

# Scan with different confidence levels
bandit -r original_code/vulnerable_app/ -ll  # Low confidence
```

### Safety Check

```bash
# Check dependencies
safety check --file requirements.txt

# Check with detailed output
safety check --file requirements.txt --full-report
```

### Custom Security Scanner

```bash
# Scan and generate report
python tools/security_scanner.py original_code/vulnerable_app/ --report --name vulnerable

# Scan refactored code
python tools/security_scanner.py final_refactored/ --report --name secure
```

### Complete Security Scan

```bash
# Linux/Mac
./scripts/run_security_scan.sh original_code/vulnerable_app vulnerable

# Windows
scripts\run_security_scan.bat original_code\vulnerable_app vulnerable
```

---

## Performance Testing

### Basic Performance Test

```bash
python tools/performance_tester.py \
    --url http://localhost:5000 \
    --requests 100 \
    --concurrent 10
```

### Complete Performance Test

```bash
# Linux/Mac
./scripts/run_performance_test.sh http://localhost:5000 vulnerable_app 10 100

# Windows  
scripts\run_performance_test.bat http://localhost:5000 vulnerable_app
```

### Load Testing with Locust

```bash
# Install locust
pip install locust

# Run load test (if locustfile exists)
locust -f tests/locustfile.py --host=http://localhost:5000
```

---

## Docker Usage

### Starting the Vulnerable App

```bash
# Build and run
docker-compose up vulnerable_app

# Run in detached mode
docker-compose up -d vulnerable_app

# View logs
docker-compose logs -f vulnerable_app
```

Access: http://localhost:8080

### Running Security Scanner

```bash
docker-compose --profile tools up security_scanner
```

### Running Performance Tests

```bash
docker-compose --profile tools up performance_tester
```

### Full Environment

```bash
# Start all services
docker-compose --profile tools --profile docs up

# Access points:
# - Vulnerable app: http://localhost:8080
# - Secure app: http://localhost:8081
# - Documentation: http://localhost:8082
```

### Cleanup

```bash
# Stop all containers
docker-compose down

# Remove volumes
docker-compose down -v

# Remove images
docker-compose down --rmi all
```

---

## Code Analysis

### Complexity Analysis

```bash
# Analyze code complexity
python tools/code_analyzer.py original_code/vulnerable_app/ --name vulnerable

# Compare versions
python tools/code_analyzer.py final_refactored/ --name secure
```

### Code Quality Metrics

```bash
# Cyclomatic complexity
radon cc original_code/vulnerable_app/ -a

# Maintainability index
radon mi original_code/vulnerable_app/

# Raw metrics (LOC, comments)
radon raw original_code/vulnerable_app/
```

---

## Workflow Examples

### Example 1: Complete Security Assessment

```bash
# 1. Start the application
cd original_code/vulnerable_app
python app.py &
cd ../..

# 2. Run vulnerability tests
python tools/vulnerability_injector.py --url http://localhost:5000 --all

# 3. Run security scan
./scripts/run_security_scan.sh original_code/vulnerable_app/ vulnerable

# 4. Run automated tests
pytest tests/test_security.py -v

# 5. Review results
cat analysis/security_scan_results/security_report_vulnerable.md
```

### Example 2: AI Refactoring Workflow

```bash
# 1. Copy vulnerable code
cat original_code/vulnerable_app/app.py

# 2. Submit to AI with prompt (manual step)
# Use prompts from ai_refactored/PROMPT_TEMPLATES.md

# 3. Save AI response
nano ai_refactored/claude_refactored/app.py

# 4. Test AI fixes
pytest tests/test_security.py -v

# 5. Scan AI-refactored code
python tools/security_scanner.py ai_refactored/claude_refactored/ --report

# 6. Document findings
nano ai_refactored/claude_refactored/AI_ANALYSIS.md
```

### Example 3: Performance Comparison

```bash
# 1. Test vulnerable app
python tools/performance_tester.py --url http://localhost:5000 --name vulnerable

# 2. Start secure app (if available)
cd final_refactored
python run.py &
cd ..

# 3. Test secure app
python tools/performance_tester.py --url http://localhost:5001 --name secure

# 4. Compare results
python tools/report_generator.py --compare-performance \
    analysis/performance_benchmarks/vulnerable_performance.json \
    analysis/performance_benchmarks/secure_performance.json
```

---

## Tips & Best Practices

### Security Testing

1. **Always test in isolated environment**
2. **Don't test on production systems**
3. **Get proper authorization**
4. **Document all findings**
5. **Use version control**

### AI Analysis

1. **Use consistent prompts**
2. **Test multiple times**
3. **Compare different AI models**
4. **Verify all AI suggestions**
5. **Document unexpected behaviors**

### Performance Testing

1. **Start with low load**
2. **Monitor system resources**
3. **Test different scenarios**
4. **Compare apples to apples**
5. **Consider network factors**

---

## Troubleshooting

### Application won't start

```bash
# Check if port is in use
netstat -an | grep 5000  # Linux/Mac
netstat -an | findstr 5000  # Windows

# Kill process on port
kill -9 $(lsof -t -i:5000)  # Linux/Mac
# Windows: Use Task Manager
```

### Tests failing

```bash
# Verify application is running
curl http://localhost:5000

# Check Python version
python --version  # Should be 3.8+

# Reinstall dependencies
pip install -r requirements.txt --force-reinstall
```

### Docker issues

```bash
# Rebuild containers
docker-compose build --no-cache

# Check container logs
docker-compose logs vulnerable_app

# Remove all containers and restart
docker-compose down -v
docker-compose up
```

---

## Additional Resources

- **Documentation**: See `docs/` directory
- **Examples**: See `original_code/other_examples/`
- **Tests**: See `tests/` directory
- **Tools**: See `tools/` directory

---

*Last Updated: January 2026*
