"""
Insecure Authentication Examples - Vulnerable Code
===================================================
This demonstrates various authentication vulnerabilities.
"""

from flask import Flask, request, session, redirect, url_for
import hashlib
import jwt
import base64
from datetime import datetime, timedelta

app = Flask(__name__)

# VULNERABILITY: Hardcoded secret key
app.config['SECRET_KEY'] = 'my-secret-key-123'
JWT_SECRET = 'jwt-secret-key'

# Simulated user database
users_db = {
    'admin': {
        'password': 'admin',  # VULNERABLE: Plaintext password
        'role': 'admin',
        'api_key': 'admin-key-123'
    },
    'user1': {
        'password': hashlib.md5('password'.encode()).hexdigest(),  # VULNERABLE: MD5 hash
        'role': 'user',
        'api_key': 'user-key-456'
    },
    'test': {
        'password': base64.b64encode('test123'.encode()).decode(),  # VULNERABLE: Base64 encoding
        'role': 'user',
        'api_key': 'test-key-789'
    }
}

# Session storage (should use database)
active_sessions = {}

@app.route('/login/basic', methods=['POST'])
def basic_login():
    """
    VULNERABLE: Multiple authentication issues
    - Plaintext password comparison
    - No rate limiting
    - Information disclosure
    """
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    
    # VULNERABLE: No input validation
    if not username or not password:
        return {'error': 'Missing credentials'}, 400
    
    # VULNERABLE: User enumeration - different responses for invalid user vs invalid password
    if username not in users_db:
        return {'error': f'User {username} does not exist'}, 401
    
    user = users_db[username]
    
    # VULNERABLE: Plaintext password comparison
    if user['password'] == password:
        # VULNERABLE: Predictable session ID
        session_id = f"{username}_{datetime.now().timestamp()}"
        active_sessions[session_id] = username
        
        # VULNERABLE: Session ID in response body
        return {
            'status': 'success',
            'session_id': session_id,
            'role': user['role'],
            'api_key': user['api_key']  # VULNERABLE: Exposing API key
        }
    else:
        return {'error': 'Invalid password'}, 401

@app.route('/login/md5', methods=['POST'])
def md5_login():
    """
    VULNERABLE: Using weak MD5 hashing
    """
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    
    if username in users_db:
        # VULNERABLE: MD5 is cryptographically broken
        password_hash = hashlib.md5(password.encode()).hexdigest()
        
        if users_db[username]['password'] == password_hash:
            session['user'] = username
            return {'status': 'success', 'hash_used': 'md5'}
    
    return {'error': 'Invalid credentials'}, 401

@app.route('/login/jwt', methods=['POST'])
def jwt_login():
    """
    VULNERABLE: Insecure JWT implementation
    """
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    
    if username in users_db and users_db[username]['password'] == password:
        # VULNERABLE: Weak JWT secret
        # VULNERABLE: No expiration time
        # VULNERABLE: Sensitive data in JWT
        token = jwt.encode(
            {
                'username': username,
                'role': users_db[username]['role'],
                'api_key': users_db[username]['api_key'],
                'password': password  # VULNERABLE: Password in token!
            },
            JWT_SECRET,
            algorithm='HS256'
        )
        
        return {'token': token}
    
    return {'error': 'Invalid credentials'}, 401

@app.route('/api/auth', methods=['GET'])
def api_auth():
    """
    VULNERABLE: Insecure API key authentication
    """
    api_key = request.headers.get('X-API-Key', '')
    
    # VULNERABLE: API key in header (should use OAuth/JWT)
    # VULNERABLE: No rate limiting
    for username, data in users_db.items():
        if data['api_key'] == api_key:
            return {
                'authenticated': True,
                'username': username,
                'role': data['role']
            }
    
    return {'authenticated': False}, 401

@app.route('/reset_password', methods=['POST'])
def reset_password():
    """
    VULNERABLE: Insecure password reset
    """
    email = request.json.get('email', '')
    
    # VULNERABLE: No verification token
    # VULNERABLE: Password reset via GET request
    reset_link = f"http://example.com/reset?email={email}"
    
    # VULNERABLE: Information disclosure
    return {
        'message': f'Password reset link sent to {email}',
        'reset_link': reset_link  # VULNERABLE: Exposing reset link
    }

@app.route('/reset', methods=['GET', 'POST'])
def reset():
    """
    VULNERABLE: Password reset without token validation
    """
    email = request.args.get('email', '')
    
    if request.method == 'POST':
        new_password = request.form.get('password', '')
        
        # VULNERABLE: No verification, anyone can reset any password
        # Just need to know the email
        return f"<h1>Password reset for {email}</h1>"
    
    return f'''
    <form method="POST">
        <h1>Reset Password for {email}</h1>
        <input type="password" name="password" placeholder="New password">
        <button type="submit">Reset</button>
    </form>
    '''

@app.route('/change_password', methods=['POST'])
def change_password():
    """
    VULNERABLE: Password change without authentication
    """
    username = request.json.get('username', '')
    old_password = request.json.get('old_password', '')
    new_password = request.json.get('new_password', '')
    
    # VULNERABLE: No session validation
    # VULNERABLE: No password strength requirements
    if username in users_db:
        users_db[username]['password'] = new_password  # VULNERABLE: Storing plaintext
        return {'status': 'success', 'message': 'Password changed'}
    
    return {'error': 'User not found'}, 404

@app.route('/session_check')
def session_check():
    """
    VULNERABLE: Insecure session management
    """
    session_id = request.args.get('session_id', '')
    
    # VULNERABLE: Session ID in URL parameter
    # VULNERABLE: No session expiration
    if session_id in active_sessions:
        username = active_sessions[session_id]
        return {
            'valid': True,
            'username': username,
            'session_id': session_id,  # VULNERABLE: Exposing session ID
            'user_data': users_db[username]  # VULNERABLE: Exposing all user data
        }
    
    return {'valid': False}, 401

@app.route('/auto_login/<username>')
def auto_login(username):
    """
    VULNERABLE: Authentication bypass
    """
    # VULNERABLE: No authentication required
    if username in users_db:
        session['user'] = username
        session['role'] = users_db[username]['role']
        return {'status': 'success', 'message': f'Logged in as {username}'}
    
    return {'error': 'User not found'}, 404

@app.route('/remember_me', methods=['POST'])
def remember_me():
    """
    VULNERABLE: Insecure "remember me" functionality
    """
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    
    if username in users_db and users_db[username]['password'] == password:
        # VULNERABLE: Storing credentials in cookie
        response = app.make_response({'status': 'success'})
        response.set_cookie('remember_user', username)
        response.set_cookie('remember_pass', password)  # VULNERABLE: Password in cookie!
        return response
    
    return {'error': 'Invalid credentials'}, 401

# Example Exploits:
"""
1. User Enumeration:
   POST /login/basic
   {"username": "admin", "password": "wrong"}
   Response indicates if user exists

2. Session Prediction:
   Session IDs are predictable: username_timestamp

3. JWT Token Manipulation:
   Decode JWT, modify role to "admin", re-encode

4. Password Reset Bypass:
   GET /reset?email=admin@example.com
   No token validation required

5. API Key Exposure:
   Login exposes API key in response

6. Session Fixation:
   /session_check?session_id=admin_123456789

7. Authentication Bypass:
   /auto_login/admin (direct access)

8. Cookie Theft:
   Credentials stored in cookies
"""

if __name__ == '__main__':
    app.run(debug=True, port=5003)
