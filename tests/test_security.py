"""
Security Test Suite for VulnHunter Project
==========================================
Comprehensive security tests for vulnerable and refactored applications.
"""

import pytest
import sys
import os

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

@pytest.fixture
def vulnerable_app():
    """Fixture for the vulnerable Flask application"""
    from original_code.vulnerable_app.app import app as vuln_app
    vuln_app.config['TESTING'] = True
    return vuln_app.test_client()

@pytest.fixture
def secure_app():
    """Fixture for the refactored secure Flask application"""
    # Will be implemented after creating secure version
    pass

class TestSQLInjection:
    """Tests for SQL Injection vulnerabilities"""
    
    def test_sqli_in_search_vulnerable(self, vulnerable_app):
        """Verify SQL injection exists in vulnerable app"""
        # Basic SQL injection attempt
        response = vulnerable_app.get("/search?q=' OR '1'='1")
        assert response.status_code == 200
        # In vulnerable app, this should return data or cause error
        assert b'user' in response.data.lower() or b'error' in response.data.lower()
    
    def test_sqli_union_attack_vulnerable(self, vulnerable_app):
        """Test UNION-based SQL injection"""
        response = vulnerable_app.get("/search?q=' UNION SELECT 1,2,3--")
        assert response.status_code == 200
        # Should either succeed or show SQL error
        
    def test_sqli_authentication_bypass_vulnerable(self, vulnerable_app):
        """Test SQL injection in login (authentication bypass)"""
        response = vulnerable_app.post("/login", data={
            'username': "admin' --",
            'password': "anything"
        })
        # In vulnerable app, might allow login bypass
        assert b'Welcome' in response.data or b'success' in response.data.lower()
    
    def test_sqli_blind_attack_vulnerable(self, vulnerable_app):
        """Test blind SQL injection"""
        # Time-based blind SQLi (won't actually test timing)
        response = vulnerable_app.get("/profile/1 AND 1=1")
        assert response.status_code in [200, 404, 500]
    
    # Tests for secure app (should prevent SQL injection)
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_sqli_prevention_secure(self, secure_app):
        """Verify SQL injection is prevented in secure app"""
        response = secure_app.get("/search?q=' OR '1'='1")
        assert response.status_code == 200
        # Should return empty results or properly escaped
        assert b'<script>' not in response.data

class TestXSS:
    """Tests for Cross-Site Scripting vulnerabilities"""
    
    def test_reflected_xss_vulnerable(self, vulnerable_app):
        """Test reflected XSS in search"""
        xss_payload = "<script>alert('XSS')</script>"
        response = vulnerable_app.get(f"/search?q={xss_payload}")
        assert response.status_code == 200
        # In vulnerable app, script should be present unescaped
        assert b'<script>' in response.data
    
    def test_stored_xss_vulnerable(self, vulnerable_app):
        """Test stored XSS in messages"""
        # First, attempt to post a message with XSS
        xss_payload = "<script>document.cookie</script>"
        response = vulnerable_app.post("/post_message", data={
            'message': xss_payload
        })
        
        # Then retrieve messages
        response = vulnerable_app.get("/messages")
        # In vulnerable app, script should be present
        assert b'<script>' in response.data
    
    def test_xss_in_attributes_vulnerable(self, vulnerable_app):
        """Test XSS through HTML attributes"""
        payload = '" onload="alert(1)'
        response = vulnerable_app.get(f"/search?q={payload}")
        assert response.status_code == 200
    
    def test_xss_various_payloads_vulnerable(self, vulnerable_app):
        """Test various XSS payloads"""
        payloads = [
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "javascript:alert(1)",
            "<iframe src=javascript:alert(1)>",
            "<body onload=alert(1)>"
        ]
        
        for payload in payloads:
            response = vulnerable_app.get(f"/search?q={payload}")
            # Should contain unescaped payload in vulnerable app
            assert response.status_code == 200
    
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_xss_prevention_secure(self, secure_app):
        """Verify XSS is prevented in secure app"""
        xss_payload = "<script>alert('XSS')</script>"
        response = secure_app.get(f"/search?q={xss_payload}")
        # Should be escaped: &lt;script&gt; instead of <script>
        assert b'<script>' not in response.data
        assert b'&lt;script&gt;' in response.data or b'alert' not in response.data

class TestCommandInjection:
    """Tests for Command Injection vulnerabilities"""
    
    def test_command_injection_vulnerable(self, vulnerable_app):
        """Test command injection in execute endpoint"""
        # Basic command
        response = vulnerable_app.get("/execute?cmd=echo test")
        assert response.status_code == 200
        assert b'test' in response.data or b'Output' in response.data
    
    def test_command_injection_chaining_vulnerable(self, vulnerable_app):
        """Test command chaining"""
        # Command chaining with semicolon
        response = vulnerable_app.get("/execute?cmd=echo hello; echo world")
        assert response.status_code == 200
    
    def test_command_injection_pipe_vulnerable(self, vulnerable_app):
        """Test command injection with pipes"""
        response = vulnerable_app.get("/execute?cmd=echo test | findstr test")
        assert response.status_code == 200
    
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_command_injection_prevention_secure(self, secure_app):
        """Verify command injection is prevented"""
        response = secure_app.get("/execute?cmd=echo test; rm -rf /")
        # Should either block entirely or sanitize
        assert response.status_code in [400, 403, 404]

class TestPathTraversal:
    """Tests for Path Traversal vulnerabilities"""
    
    def test_path_traversal_download_vulnerable(self, vulnerable_app):
        """Test path traversal in download"""
        # Attempt to read arbitrary file
        response = vulnerable_app.get("/download?file=../../etc/passwd")
        # May succeed or fail depending on OS, but should attempt
        assert response.status_code in [200, 404, 500]
    
    def test_path_traversal_windows_vulnerable(self, vulnerable_app):
        """Test Windows-style path traversal"""
        response = vulnerable_app.get("/download?file=..\\..\\windows\\system32\\config\\sam")
        assert response.status_code in [200, 404, 500]
    
    def test_path_traversal_encoded_vulnerable(self, vulnerable_app):
        """Test encoded path traversal"""
        # URL encoded: ../
        response = vulnerable_app.get("/download?file=%2e%2e%2f%2e%2e%2fetc%2fpasswd")
        assert response.status_code in [200, 404, 500]
    
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_path_traversal_prevention_secure(self, secure_app):
        """Verify path traversal is prevented"""
        response = secure_app.get("/download?file=../../etc/passwd")
        assert response.status_code in [400, 403, 404]

class TestAuthentication:
    """Tests for authentication and authorization issues"""
    
    def test_broken_access_control_vulnerable(self, vulnerable_app):
        """Test broken access control - admin without auth"""
        response = vulnerable_app.get("/admin")
        # Vulnerable app allows access without authentication
        assert response.status_code == 200
        assert b'Admin' in response.data
    
    def test_idor_vulnerable(self, vulnerable_app):
        """Test Insecure Direct Object Reference"""
        # Access other user's profile without authorization
        response = vulnerable_app.get("/profile/1")
        assert response.status_code == 200
        # Should show user data including password
        assert b'password' in response.data.lower()
    
    def test_weak_authentication_vulnerable(self, vulnerable_app):
        """Test weak authentication"""
        # Attempt login with weak credentials
        response = vulnerable_app.post("/login", data={
            'username': 'admin',
            'password': 'admin123'
        })
        assert b'Welcome' in response.data or b'success' in response.data.lower()
    
    def test_auto_login_bypass_vulnerable(self, vulnerable_app):
        """Test authentication bypass via auto-login"""
        response = vulnerable_app.get("/auto_login/admin")
        # Vulnerable app allows direct access
        assert response.status_code == 200
    
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_authentication_required_secure(self, secure_app):
        """Verify authentication is required in secure app"""
        response = secure_app.get("/admin")
        assert response.status_code in [401, 403]

class TestCSRF:
    """Tests for CSRF protection"""
    
    def test_csrf_missing_vulnerable(self, vulnerable_app):
        """Test that CSRF protection is missing"""
        # POST request without CSRF token should succeed in vulnerable app
        response = vulnerable_app.post("/login", data={
            'username': 'test',
            'password': 'test'
        })
        # Should allow request without CSRF token
        assert response.status_code == 200
    
    def test_csrf_message_post_vulnerable(self, vulnerable_app):
        """Test CSRF on message posting"""
        response = vulnerable_app.post("/post_message", data={
            'message': 'Test message'
        })
        # Should succeed without CSRF token
        assert response.status_code in [200, 302]
    
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_csrf_protection_secure(self, secure_app):
        """Verify CSRF protection is implemented"""
        response = secure_app.post("/login", data={
            'username': 'test',
            'password': 'test'
        })
        # Should require CSRF token
        assert response.status_code == 400 or b'csrf' in response.data.lower()

class TestInformationDisclosure:
    """Tests for information disclosure vulnerabilities"""
    
    def test_debug_info_disclosure_vulnerable(self, vulnerable_app):
        """Test debug endpoint exposes sensitive info"""
        response = vulnerable_app.get("/debug")
        assert response.status_code == 200
        # Should expose configuration
        assert b'secret' in response.data.lower() or b'config' in response.data.lower()
    
    def test_error_disclosure_vulnerable(self, vulnerable_app):
        """Test error messages expose info"""
        # Trigger an error
        response = vulnerable_app.get("/profile/999999")
        # May show error details
        assert response.status_code in [200, 404, 500]
    
    def test_api_data_exposure_vulnerable(self, vulnerable_app):
        """Test API exposes sensitive data"""
        response = vulnerable_app.get("/api/users?format=full")
        assert response.status_code == 200
        # Should expose passwords
        assert b'password' in response.data.lower()
    
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_information_disclosure_prevention_secure(self, secure_app):
        """Verify sensitive info is not disclosed"""
        response = secure_app.get("/debug")
        assert response.status_code in [403, 404]

class TestFileUpload:
    """Tests for file upload vulnerabilities"""
    
    def test_unrestricted_file_upload_vulnerable(self, vulnerable_app):
        """Test unrestricted file upload"""
        from io import BytesIO
        
        data = {
            'file': (BytesIO(b'test content'), 'test.txt')
        }
        response = vulnerable_app.post("/upload", data=data, content_type='multipart/form-data')
        assert response.status_code == 200
    
    @pytest.mark.skip(reason="Requires actual file")
    def test_malicious_file_upload_vulnerable(self, vulnerable_app):
        """Test uploading executable file"""
        from io import BytesIO
        
        # Attempt to upload .php file (could be executed if server processes it)
        data = {
            'file': (BytesIO(b'<?php echo "test"; ?>'), 'shell.php')
        }
        response = vulnerable_app.post("/upload/no_check", data=data, content_type='multipart/form-data')
        # Vulnerable app should accept it
        assert response.status_code == 200
    
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_file_upload_validation_secure(self, secure_app):
        """Verify file upload validation in secure app"""
        from io import BytesIO
        
        data = {
            'file': (BytesIO(b'<?php echo "test"; ?>'), 'shell.php')
        }
        response = secure_app.post("/upload", data=data, content_type='multipart/form-data')
        # Should reject dangerous files
        assert response.status_code in [400, 403]

class TestSecurityHeaders:
    """Tests for security headers"""
    
    def test_missing_security_headers_vulnerable(self, vulnerable_app):
        """Test that security headers are missing"""
        response = vulnerable_app.get("/")
        headers = response.headers
        
        # These headers should be missing in vulnerable app
        assert 'X-Content-Type-Options' not in headers
        assert 'X-Frame-Options' not in headers
        assert 'X-XSS-Protection' not in headers
        assert 'Content-Security-Policy' not in headers
        assert 'Strict-Transport-Security' not in headers
    
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_security_headers_present_secure(self, secure_app):
        """Verify security headers are present in secure app"""
        response = secure_app.get("/")
        headers = response.headers
        
        # These headers should be present
        assert 'X-Content-Type-Options' in headers
        assert headers['X-Content-Type-Options'] == 'nosniff'
        assert 'X-Frame-Options' in headers
        assert 'Content-Security-Policy' in headers

class TestSessionManagement:
    """Tests for session management issues"""
    
    def test_session_fixation_vulnerable(self, vulnerable_app):
        """Test session fixation vulnerability"""
        # Login and check session
        response = vulnerable_app.post("/login", data={
            'username': 'admin',
            'password': 'admin123'
        })
        # Session should be created
        assert response.status_code == 200
    
    def test_predictable_session_vulnerable(self, vulnerable_app):
        """Test predictable session IDs"""
        response = vulnerable_app.get("/session_check?session_id=admin_1234567890")
        # May validate predictable session
        assert response.status_code in [200, 401]
    
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_session_security_secure(self, secure_app):
        """Verify secure session management"""
        response = secure_app.post("/login", data={
            'username': 'test',
            'password': 'test123'
        })
        # Session should be secure, httponly, samesite
        assert 'Set-Cookie' in response.headers

class TestInputValidation:
    """Tests for input validation"""
    
    def test_no_input_validation_vulnerable(self, vulnerable_app):
        """Test lack of input validation"""
        # Send extremely long input
        long_input = "A" * 100000
        response = vulnerable_app.get(f"/search?q={long_input}")
        # May process without validation
        assert response.status_code in [200, 500]
    
    def test_special_chars_vulnerable(self, vulnerable_app):
        """Test handling of special characters"""
        special_chars = "'; DROP TABLE users; --"
        response = vulnerable_app.get(f"/search?q={special_chars}")
        assert response.status_code in [200, 500]
    
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_input_validation_secure(self, secure_app):
        """Verify input validation in secure app"""
        long_input = "A" * 100000
        response = secure_app.get(f"/search?q={long_input}")
        # Should limit or reject
        assert response.status_code in [400, 413]

# Performance and Load Tests
class TestPerformance:
    """Basic performance tests"""
    
    def test_response_time_vulnerable(self, vulnerable_app):
        """Measure response time of vulnerable app"""
        import time
        
        start = time.time()
        response = vulnerable_app.get("/")
        end = time.time()
        
        response_time = end - start
        assert response.status_code == 200
        # Just record, don't assert specific time
        print(f"Vulnerable app response time: {response_time:.3f}s")
    
    @pytest.mark.skip(reason="Secure app not yet implemented")
    def test_response_time_secure(self, secure_app):
        """Measure response time of secure app"""
        import time
        
        start = time.time()
        response = secure_app.get("/")
        end = time.time()
        
        response_time = end - start
        assert response.status_code == 200
        print(f"Secure app response time: {response_time:.3f}s")

if __name__ == '__main__':
    pytest.main([__file__, '-v', '--tb=short'])
