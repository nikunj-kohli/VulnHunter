"""
Pytest Configuration
====================
Shared fixtures and configuration for test suite
"""

import pytest
import sys
import os

# Add project root to path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

def pytest_configure(config):
    """Configure pytest with custom markers"""
    config.addinivalue_line(
        "markers", "security: mark test as a security test"
    )
    config.addinivalue_line(
        "markers", "vulnerable: mark test as testing vulnerable code"
    )
    config.addinivalue_line(
        "markers", "secure: mark test as testing secure code"
    )
    config.addinivalue_line(
        "markers", "slow: mark test as slow running"
    )

@pytest.fixture(scope="session")
def test_database():
    """Create a test database"""
    import sqlite3
    import tempfile
    
    # Create temporary database
    db_fd, db_path = tempfile.mkstemp(suffix='.db')
    
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    
    # Create test tables
    c.execute('''CREATE TABLE users
                 (id INTEGER PRIMARY KEY, username TEXT, password TEXT, email TEXT, role TEXT)''')
    
    c.execute('''CREATE TABLE messages
                 (id INTEGER PRIMARY KEY, user_id INTEGER, message TEXT, created_at TIMESTAMP)''')
    
    # Insert test data
    c.execute("INSERT INTO users VALUES (1, 'admin', 'admin123', 'admin@test.com', 'admin')")
    c.execute("INSERT INTO users VALUES (2, 'user1', 'password', 'user1@test.com', 'user')")
    
    conn.commit()
    conn.close()
    
    yield db_path
    
    # Cleanup
    os.close(db_fd)
    os.unlink(db_path)

@pytest.fixture
def mock_user():
    """Mock user for testing"""
    return {
        'id': 1,
        'username': 'testuser',
        'password': 'testpass123',
        'email': 'test@example.com',
        'role': 'user'
    }

@pytest.fixture
def xss_payloads():
    """Common XSS payloads for testing"""
    return [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "javascript:alert(1)",
        "<iframe src=javascript:alert(1)>",
        "<body onload=alert(1)>",
        "'-alert(1)-'",
        "\"><script>alert(1)</script>",
        "<script>alert(String.fromCharCode(88,83,83))</script>",
        "<img src=\"x\" onerror=\"alert(1)\">",
    ]

@pytest.fixture
def sqli_payloads():
    """Common SQL injection payloads for testing"""
    return [
        "' OR '1'='1",
        "' OR 1=1--",
        "admin' --",
        "' UNION SELECT NULL--",
        "1' ORDER BY 1--",
        "' OR '1'='1' /*",
        "'; DROP TABLE users--",
        "1' AND 1=2 UNION SELECT NULL, NULL--",
        "admin'/*",
        "' WAITFOR DELAY '00:00:05'--",
    ]

@pytest.fixture
def command_injection_payloads():
    """Common command injection payloads"""
    return [
        "; ls",
        "| dir",
        "&& whoami",
        "`whoami`",
        "$(whoami)",
        "; cat /etc/passwd",
        "| type C:\\Windows\\System32\\drivers\\etc\\hosts",
        "&& ping -c 4 127.0.0.1",
    ]

@pytest.fixture
def path_traversal_payloads():
    """Common path traversal payloads"""
    return [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "....//....//....//etc/passwd",
        "..%2F..%2F..%2Fetc%2Fpasswd",
        "../../../../../../etc/hosts",
        "..\\..\\..\\..\\..\\..\\windows\\win.ini",
    ]

@pytest.fixture(autouse=True)
def reset_database():
    """Reset database before each test"""
    # This would reset the test database
    # Implement based on your database setup
    pass

# Pytest hooks for custom behavior
def pytest_collection_modifyitems(config, items):
    """Modify test collection"""
    for item in items:
        # Add marker based on test name
        if "vulnerable" in item.nodeid:
            item.add_marker(pytest.mark.vulnerable)
        if "secure" in item.nodeid:
            item.add_marker(pytest.mark.secure)
        if "security" in item.nodeid:
            item.add_marker(pytest.mark.security)

def pytest_report_header(config):
    """Add custom header to pytest report"""
    return [
        "VulnHunter Security Test Suite",
        "Testing vulnerable and secure Flask applications",
        "=" * 60
    ]
