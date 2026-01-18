# AI Prompt Templates for Security Refactoring

This document contains standardized prompts for testing various AI models on security code refactoring tasks.

## 1. Basic Security Audit Prompt

```
Please analyze the following Flask application for security vulnerabilities and provide a comprehensive security audit.

Instructions:
1. Identify all security vulnerabilities
2. Categorize each vulnerability by severity (Critical, High, Medium, Low)
3. Provide OWASP classification where applicable
4. Explain the potential impact of each vulnerability
5. Suggest specific fixes for each issue

[PASTE CODE HERE]
```

## 2. Comprehensive Refactoring Prompt

```
Act as a senior security engineer and Python developer. I have a Flask application with known security vulnerabilities that needs to be completely refactored.

Requirements:
1. Identify ALL security vulnerabilities (aim for at least 15+)
2. Provide a fully refactored version of the code
3. Implement security best practices:
   - Input validation and sanitization
   - Parameterized queries (prevent SQL injection)
   - Output encoding (prevent XSS)
   - CSRF protection
   - Secure session management
   - Proper authentication and authorization
   - Secure password hashing
   - Environment variable usage for secrets
   - Security headers
   - Rate limiting
4. Add detailed comments explaining each fix
5. Maintain the same functionality while making it secure
6. Follow PEP 8 style guidelines

Original Code:
[PASTE CODE HERE]

Please provide:
1. List of vulnerabilities found
2. Complete refactored code
3. Explanation of each security improvement
```

## 3. Comparative Analysis Prompt

```
I have an original vulnerable code and an AI-refactored version. Please perform a comparative security analysis.

Task:
1. Compare the security posture of both versions
2. Verify that all vulnerabilities were addressed
3. Identify any NEW issues introduced in the refactored version
4. Check for false positives in the AI's fixes
5. Identify any missed vulnerabilities
6. Rate the overall improvement (percentage)

Original Code:
[PASTE ORIGINAL]

Refactored Code:
[PASTE REFACTORED]

Provide:
1. Vulnerability comparison matrix
2. List of properly fixed issues
3. List of missed vulnerabilities
4. List of newly introduced issues
5. Overall assessment
```

## 4. OWASP Top 10 Focused Prompt

```
Analyze this Flask application specifically for OWASP Top 10 vulnerabilities:

1. A01:2021 – Broken Access Control
2. A02:2021 – Cryptographic Failures
3. A03:2021 – Injection
4. A04:2021 – Insecure Design
5. A05:2021 – Security Misconfiguration
6. A06:2021 – Vulnerable and Outdated Components
7. A07:2021 – Identification and Authentication Failures
8. A08:2021 – Software and Data Integrity Failures
9. A09:2021 – Security Logging and Monitoring Failures
10. A10:2021 – Server-Side Request Forgery (SSRF)

For each category, identify if vulnerabilities exist and provide fixes.

Code:
[PASTE CODE HERE]
```

## 5. Incremental Fix Prompt

```
Please fix ONLY the following specific vulnerability in this code:

Vulnerability: [SQL Injection / XSS / CSRF / etc.]
Location: [Function/route name]

Requirements:
- Fix only this specific issue
- Preserve all other code unchanged
- Provide minimal, focused fix
- Explain the fix

Code:
[PASTE CODE SECTION]
```

## 6. Performance + Security Prompt

```
Refactor this Flask application to be both SECURE and PERFORMANT.

Security Requirements:
- Fix all security vulnerabilities
- Implement defense-in-depth
- Add security monitoring

Performance Requirements:
- Optimize database queries
- Add caching where appropriate
- Implement connection pooling
- Minimize redundant operations

Code:
[PASTE CODE HERE]
```

## 7. Testing Focus Prompt

```
For this vulnerable Flask application:

1. Identify all security vulnerabilities
2. For each vulnerability, provide:
   - A specific test case that exploits it
   - The expected vulnerable behavior
   - A pytest test function to verify the fix

3. Provide a complete test suite (pytest) that:
   - Tests for each vulnerability
   - Verifies the fix works
   - Uses proper assertions

Code:
[PASTE CODE HERE]
```

## 8. Documentation Prompt

```
Create comprehensive security documentation for this Flask application:

1. List all vulnerabilities with:
   - Vulnerability name
   - OWASP category
   - CWE ID
   - Severity (Critical/High/Medium/Low)
   - Description
   - Exploitation example
   - Impact assessment
   - Remediation steps

2. Create a security audit report in markdown format

Code:
[PASTE CODE HERE]
```

## 9. Production-Ready Refactoring Prompt

```
Transform this vulnerable Flask application into a production-ready secure application.

Requirements:
1. Fix ALL security vulnerabilities
2. Implement proper application structure:
   - Blueprints for routing
   - Models for database
   - Configuration management
   - Environment-based settings
3. Add comprehensive error handling
4. Implement logging and monitoring
5. Add security middleware
6. Include requirements.txt with secure dependencies
7. Create Dockerfile for secure deployment
8. Add configuration for security headers

Provide complete file structure with all necessary files.

Code:
[PASTE CODE HERE]
```

## 10. AI Limitations Testing Prompt

```
This is a deliberately vulnerable application for testing AI security analysis capabilities.

Challenge:
1. Find ALL vulnerabilities (there are 30+)
2. Categorize them correctly
3. Don't create false positives
4. Don't miss subtle vulnerabilities
5. Consider both obvious and obscure issues

Be thorough and think critically about:
- Logic flaws
- Race conditions
- Business logic vulnerabilities
- Configuration issues
- Dependency vulnerabilities

Code:
[PASTE CODE HERE]
```

---

## Usage Instructions

### For Claude:
1. Use prompts 1, 2, and 4 for comprehensive analysis
2. Claude excels at detailed explanations
3. Ask for code comments in refactored output

### For ChatGPT:
1. Use prompts 2, 6, and 9 for best results
2. GPT-4 is good at structured responses
3. Request specific format for vulnerability lists

### For Gemini:
1. Use prompts 1, 3, and 7 
2. Gemini is good at comparative analysis
3. Request both fixes and test cases

### For GitHub Copilot:
1. Use prompt 5 for inline fixes
2. Works best with focused, single-issue prompts
3. Use in IDE for contextual suggestions

---

## Evaluation Criteria

When comparing AI outputs, evaluate:

### Completeness (30 points)
- Number of vulnerabilities found
- Coverage of vulnerability categories
- Identification of subtle issues

### Correctness (30 points)
- Accuracy of fixes
- No new vulnerabilities introduced
- Proper security practices used

### Code Quality (20 points)
- Clean, maintainable code
- Proper structure and organization
- Following Python best practices

### Explanation Quality (20 points)
- Clear vulnerability descriptions
- Detailed fix explanations
- Educational value

---

## Notes for Analysis

- Save AI responses with timestamps
- Document which prompt version was used
- Note any follow-up questions needed
- Record unexpected behaviors
- Compare consistency across multiple runs
