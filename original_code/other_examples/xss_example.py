"""
Cross-Site Scripting (XSS) Examples - Vulnerable Code
=====================================================
This demonstrates various XSS vulnerabilities.
"""

from flask import Flask, request, render_template_string, make_response

app = Flask(__name__)

# Simulated user data store
comments = []
user_profiles = {}

@app.route('/comment', methods=['GET', 'POST'])
def comment_section():
    """
    VULNERABLE: Stored XSS
    User input stored and displayed without sanitization
    """
    if request.method == 'POST':
        username = request.form.get('username', 'Anonymous')
        comment = request.form.get('comment', '')
        
        # VULNERABLE: Storing unsanitized user input
        comments.append({'username': username, 'comment': comment})
    
    # VULNERABLE: Rendering unsanitized data
    html = '''
    <h1>Comment Section</h1>
    <form method="POST">
        <input type="text" name="username" placeholder="Your name"><br>
        <textarea name="comment" placeholder="Your comment"></textarea><br>
        <button type="submit">Post Comment</button>
    </form>
    <hr>
    <h2>Comments:</h2>
    '''
    
    for c in comments:
        # VULNERABLE: Direct HTML rendering without escaping
        html += f"<div><strong>{c['username']}:</strong> {c['comment']}</div>"
    
    return html

@app.route('/search')
def search():
    """
    VULNERABLE: Reflected XSS
    User input directly reflected in response
    """
    query = request.args.get('q', '')
    
    # VULNERABLE: Unescaped user input in HTML
    html = f'''
    <h1>Search Results for: {query}</h1>
    <p>You searched for: {query}</p>
    <form method="GET">
        <input type="text" name="q" value="{query}">
        <button type="submit">Search</button>
    </form>
    '''
    
    return html

@app.route('/profile/<username>')
def profile(username):
    """
    VULNERABLE: DOM-based XSS
    User input in JavaScript context
    """
    bio = user_profiles.get(username, 'No bio available')
    
    html = f'''
    <html>
    <head>
        <script>
            var username = "{username}";
            var bio = "{bio}";
            document.addEventListener('DOMContentLoaded', function() {{
                document.getElementById('username').innerHTML = username;
                document.getElementById('bio').innerHTML = bio;
            }});
        </script>
    </head>
    <body>
        <h1 id="username"></h1>
        <p id="bio"></p>
    </body>
    </html>
    '''
    
    return html

@app.route('/update_profile', methods=['POST'])
def update_profile():
    """
    VULNERABLE: Stored XSS in user profile
    """
    username = request.form.get('username', '')
    bio = request.form.get('bio', '')
    
    # VULNERABLE: Storing unsanitized HTML/JavaScript
    user_profiles[username] = bio
    
    return f"<h1>Profile Updated!</h1><p>Bio: {bio}</p>"

@app.route('/render_template')
def render_template():
    """
    VULNERABLE: XSS through template injection
    """
    template = request.args.get('template', '<h1>Hello</h1>')
    
    # VULNERABLE: Rendering user-controlled template
    return render_template_string(template)

@app.route('/json_xss')
def json_xss():
    """
    VULNERABLE: XSS in JSON response
    """
    callback = request.args.get('callback', 'handleData')
    data = request.args.get('data', 'test')
    
    # VULNERABLE: JSONP callback not sanitized
    response = make_response(f"{callback}({{'data': '{data}'}})")
    response.headers['Content-Type'] = 'application/javascript'
    
    return response

@app.route('/innerHTML')
def inner_html():
    """
    VULNERABLE: innerHTML with user data
    """
    content = request.args.get('content', 'Default content')
    
    html = f'''
    <html>
    <head>
        <script>
            function loadContent() {{
                document.getElementById('content').innerHTML = "{content}";
            }}
        </script>
    </head>
    <body onload="loadContent()">
        <div id="content"></div>
    </body>
    </html>
    '''
    
    return html

@app.route('/svg_xss')
def svg_xss():
    """
    VULNERABLE: XSS through SVG
    """
    color = request.args.get('color', 'red')
    
    svg = f'''
    <svg xmlns="http://www.w3.org/2000/svg">
        <text fill="{color}" x="10" y="20">Hello</text>
    </svg>
    '''
    
    return svg

# Example Exploits:
"""
1. Stored XSS in comments:
   POST /comment
   comment=<script>alert('XSS')</script>

2. Reflected XSS:
   /search?q=<script>alert(document.cookie)</script>

3. XSS in attribute:
   /search?q=" onload="alert('XSS')

4. JavaScript context XSS:
   /profile/<script>alert('XSS')</script>

5. Template injection:
   /render_template?template={{7*7}}

6. SVG XSS:
   /svg_xss?color=red" onload="alert('XSS')

7. JSONP callback injection:
   /json_xss?callback=alert(document.cookie);//

8. Event handler XSS:
   /search?q=" onfocus="alert('XSS')" autofocus="
"""

if __name__ == '__main__':
    app.run(debug=True, port=5002)
