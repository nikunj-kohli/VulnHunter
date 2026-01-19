"""
DELIBERATELY VULNERABLE FLASK APPLICATION
==========================================
⚠️ WARNING: This application contains 30+ security vulnerabilities.
DO NOT deploy in production. For educational purposes only.

Vulnerabilities included:
1. SQL Injection
2. Cross-Site Scripting (XSS)
3. Hardcoded Credentials
4. Command Injection
5. Insecure Deserialization
6. Path Traversal
7. Information Disclosure
8. Missing CSRF Protection
9. Weak Authentication
10. Insecure Session Management
11. Missing Security Headers
12. Debug Mode Enabled
13. Insecure File Upload
14. No Input Validation
15. Missing Rate Limiting
16. Sensitive Data Exposure
17. Broken Access Control
18. Security Misconfiguration
19. Authentication Bypass
20. Predictable Sessions
"""

from flask import Flask, request, render_template_string, session, redirect, send_file
import sqlite3
import pickle
import os
import subprocess
import hashlib
import base64
from datetime import datetime

app = Flask(__name__)

# VULNERABILITY 1: Hardcoded Secret Key
app.config['SECRET_KEY'] = 'supersecretkey123'

# VULNERABILITY 2: Debug Mode Enabled in Production
app.config['DEBUG'] = True

# VULNERABILITY 3: Hardcoded Database Credentials
DATABASE = 'users.db'
ADMIN_PASSWORD = 'admin123'  # Hardcoded admin password
API_KEY = '1234567890abcdef'  # Hardcoded API key

# VULNERABILITY 4: Insecure File Upload Path
UPLOAD_FOLDER = '/tmp/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}

def init_db():
    """Initialize database with sample data"""
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS users
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  username TEXT NOT NULL,
                  password TEXT NOT NULL,
                  email TEXT,
                  role TEXT DEFAULT 'user')''')
    
    c.execute('''CREATE TABLE IF NOT EXISTS messages
                 (id INTEGER PRIMARY KEY AUTOINCREMENT,
                  user_id INTEGER,
                  message TEXT,
                  created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP)''')
    
    # Insert sample users with weak passwords
    c.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (1, 'admin', 'admin123', 'admin@example.com', 'admin')")
    c.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (2, 'user1', 'password', 'user1@example.com', 'user')")
    c.execute("INSERT OR IGNORE INTO users (id, username, password, email, role) VALUES (3, 'test', 'test', 'test@example.com', 'user')")
    
    conn.commit()
    conn.close()

@app.route('/')
def index():
    """Home page with search form"""
    # VULNERABILITY 5: XSS in template
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>VulnApp - Deliberately Vulnerable Application</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 40px; }
            .warning { background: #ff0000; color: white; padding: 10px; }
            .container { max-width: 800px; margin: 0 auto; }
            input[type="text"], input[type="password"] { padding: 8px; margin: 5px; width: 200px; }
            button { padding: 10px 20px; margin: 5px; cursor: pointer; }
        </style>
    </head>
    <body>
        <div class="warning">
            ⚠️ WARNING: This is a deliberately vulnerable application for educational purposes only!
        </div>
        <div class="container">
            <h1>Welcome to VulnApp</h1>
            
            <h2>User Search</h2>
            <form action="/search" method="GET">
                <input type="text" name="q" placeholder="Search users...">
                <button type="submit">Search</button>
            </form>
            
            <h2>Login</h2>
            <form action="/login" method="POST">
                <input type="text" name="username" placeholder="Username"><br>
                <input type="password" name="password" placeholder="Password"><br>
                <button type="submit">Login</button>
            </form>
            
            <h2>Quick Links</h2>
            <ul>
                <li><a href="/messages">View Messages</a></li>
                <li><a href="/upload">Upload File</a></li>
                <li><a href="/api/users">API - List Users</a></li>
                <li><a href="/admin">Admin Panel</a></li>
                <li><a href="/debug">Debug Info</a></li>
                <li><a href="/execute">Execute Command</a></li>
            </ul>
        </div>
    </body>
    </html>
    '''

@app.route('/search')
def search():
    """
    VULNERABILITY 6: SQL Injection
    User input is directly concatenated into SQL query
    """
    query = request.args.get('q', '')
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # VULNERABLE: SQL Injection - no parameterization
    sql = f"SELECT id, username, email FROM users WHERE username LIKE '%{query}%' OR email LIKE '%{query}%'"
    
    try:
        c.execute(sql)
        results = c.fetchall()
    except Exception as e:
        # VULNERABILITY 7: Information Disclosure in Error Messages
        return f"<h1>Database Error</h1><pre>{str(e)}</pre><p>Query: {sql}</p>"
    finally:
        conn.close()
    
    # VULNERABILITY 8: XSS - Unescaped user input in output
    html = f"<h1>Search Results for: {query}</h1>"
    html += "<table border='1'><tr><th>ID</th><th>Username</th><th>Email</th></tr>"
    
    for row in results:
        html += f"<tr><td>{row[0]}</td><td>{row[1]}</td><td>{row[2]}</td></tr>"
    
    html += "</table><br><a href='/'>Back</a>"
    
    return html

@app.route('/login', methods=['POST'])
def login():
    """
    VULNERABILITY 9: Weak Authentication
    VULNERABILITY 10: Missing CSRF Protection
    """
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # VULNERABLE: SQL Injection in login
    c.execute(f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'")
    user = c.fetchone()
    conn.close()
    
    if user:
        # VULNERABILITY 11: Insecure Session Management
        session['user_id'] = user[0]
        session['username'] = user[1]
        session['role'] = user[4]
        
        # VULNERABILITY 12: XSS in redirect message
        return f"<h1>Welcome {username}!</h1><p>Login successful!</p><a href='/'>Home</a>"
    else:
        return "<h1>Login Failed</h1><p>Invalid credentials</p><a href='/'>Back</a>"

@app.route('/messages')
def messages():
    """
    VULNERABILITY 13: Broken Access Control
    Anyone can view all messages without authentication
    """
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    c.execute("SELECT u.username, m.message, m.created_at FROM messages m JOIN users u ON m.user_id = u.id ORDER BY m.created_at DESC")
    results = c.fetchall()
    conn.close()
    
    html = "<h1>All Messages</h1><ul>"
    for row in results:
        # VULNERABILITY 14: XSS in messages
        html += f"<li><strong>{row[0]}</strong>: {row[1]} <em>({row[2]})</em></li>"
    
    html += "</ul>"
    
    # Message posting form
    html += '''
    <h2>Post a Message</h2>
    <form action="/post_message" method="POST">
        <textarea name="message" rows="4" cols="50"></textarea><br>
        <button type="submit">Post</button>
    </form>
    <a href="/">Back</a>
    '''
    
    return html

@app.route('/post_message', methods=['POST'])
def post_message():
    """
    VULNERABILITY 15: Missing Authentication Check
    VULNERABILITY 16: No Input Validation
    """
    message = request.form.get('message', '')
    user_id = session.get('user_id', 1)  # Default to user 1 if not logged in
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # VULNERABLE: No input validation or sanitization
    c.execute(f"INSERT INTO messages (user_id, message) VALUES ({user_id}, '{message}')")
    conn.commit()
    conn.close()
    
    return redirect('/messages')

@app.route('/upload', methods=['GET', 'POST'])
def upload():
    """
    VULNERABILITY 17: Insecure File Upload
    VULNERABILITY 18: Path Traversal
    """
    if request.method == 'POST':
        if 'file' not in request.files:
            return "<h1>No file uploaded</h1><a href='/upload'>Back</a>"
        
        file = request.files['file']
        filename = request.form.get('filename', file.filename)
        
        # VULNERABLE: No file type validation
        # VULNERABLE: User-controlled filename without sanitization
        filepath = os.path.join(UPLOAD_FOLDER, filename)
        
        os.makedirs(UPLOAD_FOLDER, exist_ok=True)
        file.save(filepath)
        
        return f"<h1>File uploaded!</h1><p>Saved as: {filepath}</p><a href='/upload'>Upload another</a>"
    
    return '''
    <h1>File Upload</h1>
    <form method="POST" enctype="multipart/form-data">
        <input type="file" name="file"><br>
        <input type="text" name="filename" placeholder="Custom filename (optional)"><br>
        <button type="submit">Upload</button>
    </form>
    <a href="/">Back</a>
    '''

@app.route('/download')
def download():
    """
    VULNERABILITY 19: Path Traversal
    Arbitrary file read vulnerability
    """
    filename = request.args.get('file', '')
    
    # VULNERABLE: No path validation - allows directory traversal
    try:
        return send_file(filename)
    except Exception as e:
        return f"<h1>Error</h1><pre>{str(e)}</pre>"

@app.route('/execute')
def execute():
    """
    VULNERABILITY 20: Command Injection
    Remote code execution vulnerability
    """
    command = request.args.get('cmd', 'echo "No command provided"')
    
    # VULNERABLE: Unsanitized command execution
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return f"<h1>Command Output</h1><pre>{result}</pre><a href='/'>Back</a>"
    except Exception as e:
        return f"<h1>Execution Error</h1><pre>{str(e)}</pre>"

@app.route('/admin')
def admin():
    """
    VULNERABILITY 21: Broken Access Control
    No authentication required for admin panel
    """
    # VULNERABLE: No authentication check
    return '''
    <h1>Admin Panel</h1>
    <h2>⚠️ Sensitive Administrative Functions</h2>
    <ul>
        <li><a href="/api/users?format=full">View All User Data (including passwords)</a></li>
        <li><a href="/debug">View System Debug Info</a></li>
        <li><a href="/execute?cmd=whoami">Execute System Commands</a></li>
        <li><a href="/deserialize">Deserialize Data</a></li>
    </ul>
    <a href="/">Back</a>
    '''

@app.route('/api/users')
def api_users():
    """
    VULNERABILITY 22: Sensitive Data Exposure
    VULNERABILITY 23: Missing API Authentication
    """
    format_type = request.args.get('format', 'basic')
    
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    if format_type == 'full':
        # VULNERABLE: Exposing passwords in API response
        c.execute("SELECT * FROM users")
    else:
        c.execute("SELECT id, username, email FROM users")
    
    results = c.fetchall()
    conn.close()
    
    # VULNERABLE: No API rate limiting
    # VULNERABLE: Exposing sensitive data structure
    html = "<h1>API - Users List</h1><pre>"
    for row in results:
        html += str(row) + "\n"
    html += "</pre><a href='/'>Back</a>"
    
    return html

@app.route('/debug')
def debug():
    """
    VULNERABILITY 24: Information Disclosure
    Exposing sensitive configuration and environment variables
    """
    # VULNERABLE: Exposing all configuration
    debug_info = {
        'app_config': dict(app.config),
        'environment': dict(os.environ),
        'secret_key': app.config['SECRET_KEY'],
        'database': DATABASE,
        'admin_password': ADMIN_PASSWORD,
        'api_key': API_KEY,
        'python_version': os.sys.version,
        'current_user': session.get('username', 'Not logged in'),
        'session_data': dict(session)
    }
    
    html = "<h1>Debug Information</h1><pre>"
    for key, value in debug_info.items():
        html += f"{key}:\n{value}\n\n"
    html += "</pre><a href='/'>Back</a>"
    
    return html

@app.route('/deserialize', methods=['GET', 'POST'])
def deserialize():
    """
    VULNERABILITY 25: Insecure Deserialization
    Remote code execution through pickle
    """
    if request.method == 'POST':
        data = request.form.get('data', '')
        
        try:
            # VULNERABLE: Deserializing untrusted data
            decoded = base64.b64decode(data)
            obj = pickle.loads(decoded)
            return f"<h1>Deserialized Object</h1><pre>{obj}</pre><a href='/deserialize'>Back</a>"
        except Exception as e:
            return f"<h1>Deserialization Error</h1><pre>{str(e)}</pre>"
    
    return '''
    <h1>Deserialize Data</h1>
    <form method="POST">
        <textarea name="data" rows="10" cols="50" placeholder="Base64 encoded pickle data"></textarea><br>
        <button type="submit">Deserialize</button>
    </form>
    <a href="/">Back</a>
    '''

@app.route('/profile/<user_id>')
def profile(user_id):
    """
    VULNERABILITY 26: Insecure Direct Object Reference (IDOR)
    Users can access any profile without authorization
    """
    conn = sqlite3.connect(DATABASE)
    c = conn.cursor()
    
    # VULNERABLE: No authorization check
    c.execute(f"SELECT username, email, password, role FROM users WHERE id = {user_id}")
    user = c.fetchone()
    conn.close()
    
    if user:
        # VULNERABILITY 27: Exposing passwords in profile view
        return f'''
        <h1>User Profile</h1>
        <p><strong>Username:</strong> {user[0]}</p>
        <p><strong>Email:</strong> {user[1]}</p>
        <p><strong>Password:</strong> {user[2]}</p>
        <p><strong>Role:</strong> {user[3]}</p>
        <a href="/">Back</a>
        '''
    
    return "<h1>User not found</h1><a href='/'>Back</a>"

@app.route('/auto_login/<username>')
def auto_login(username):
    """
    VULNERABILITY 30: Authentication Bypass via Auto-Login
    Allows direct login without credentials
    """
    # VULNERABLE: Auto-login without authentication
    session['user'] = username
    session['role'] = 'admin' if username == 'admin' else 'user'
    return f'''
    <h1>Auto Login</h1>
    <p>You are now logged in as {username}</p>
    <a href="/">Back</a>
    '''

@app.route('/session_check')
def session_check():
    """
    VULNERABILITY 31: Predictable Session Validation
    Accepts predictable session IDs
    """
    session_id = request.args.get('session_id', '')
    # VULNERABLE: Accepts any predictable session ID pattern
    if session_id and 'admin' in session_id:
        session['user'] = 'admin'
        session['role'] = 'admin'
        return '<h1>Session Valid</h1><p>Admin session activated</p><a href="/">Back</a>'
    return '<h1>Invalid Session</h1><a href="/">Back</a>', 401

@app.errorhandler(404)
def page_not_found(e):
    """
    VULNERABILITY 28: Information Disclosure in Error Pages
    """
    # VULNERABLE: Exposing internal paths and request details
    return f'''
    <h1>404 - Page Not Found</h1>
    <p>The requested URL was not found: {request.url}</p>
    <p>Method: {request.method}</p>
    <p>Headers: {dict(request.headers)}</p>
    <p>Error: {str(e)}</p>
    <a href="/">Back</a>
    ''', 404

@app.errorhandler(500)
def internal_error(e):
    """
    VULNERABILITY 29: Stack Trace Exposure
    """
    import traceback
    # VULNERABLE: Exposing full stack trace
    return f'''
    <h1>500 - Internal Server Error</h1>
    <pre>{traceback.format_exc()}</pre>
    <a href="/">Back</a>
    ''', 500

if __name__ == '__main__':
    # Initialize database
    init_db()
    
    # VULNERABILITY 30: Running on all interfaces (0.0.0.0)
    # VULNERABILITY 31: No HTTPS enforcement
    # VULNERABILITY 32: No security headers
    app.run(host='0.0.0.0', port=5000, debug=True, use_reloader=False)
