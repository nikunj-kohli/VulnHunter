"""
SQL Injection Example - Vulnerable Code
========================================
This demonstrates various SQL injection vulnerabilities.
"""

import sqlite3
from flask import Flask, request

app = Flask(__name__)

# Initialize a simple database
def init_database():
    conn = sqlite3.connect('products.db')
    c = conn.cursor()
    c.execute('''CREATE TABLE IF NOT EXISTS products
                 (id INTEGER PRIMARY KEY, name TEXT, price REAL, category TEXT)''')
    c.execute("INSERT OR IGNORE INTO products VALUES (1, 'Laptop', 999.99, 'Electronics')")
    c.execute("INSERT OR IGNORE INTO products VALUES (2, 'Book', 19.99, 'Books')")
    c.execute("INSERT OR IGNORE INTO products VALUES (3, 'Phone', 599.99, 'Electronics')")
    c.execute("INSERT OR IGNORE INTO products VALUES (4, 'Secret Admin Data', 0, 'CONFIDENTIAL')")
    conn.commit()
    conn.close()

@app.route('/product/search')
def product_search():
    """
    VULNERABLE: Classic SQL Injection
    User input directly concatenated into query
    """
    search_term = request.args.get('name', '')
    
    conn = sqlite3.connect('products.db')
    c = conn.cursor()
    
    # VULNERABLE: String concatenation in SQL query
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    
    c.execute(query)
    results = c.fetchall()
    conn.close()
    
    return {'query': query, 'results': results}

@app.route('/product/<product_id>')
def get_product(product_id):
    """
    VULNERABLE: SQL Injection in URL parameter
    """
    conn = sqlite3.connect('products.db')
    c = conn.cursor()
    
    # VULNERABLE: No input validation or sanitization
    query = f"SELECT * FROM products WHERE id = {product_id}"
    
    c.execute(query)
    result = c.fetchone()
    conn.close()
    
    return {'query': query, 'product': result}

@app.route('/products/filter')
def filter_products():
    """
    VULNERABLE: SQL Injection in ORDER BY clause
    """
    sort_by = request.args.get('sort', 'name')
    order = request.args.get('order', 'ASC')
    
    conn = sqlite3.connect('products.db')
    c = conn.cursor()
    
    # VULNERABLE: User-controlled ORDER BY
    query = f"SELECT * FROM products ORDER BY {sort_by} {order}"
    
    c.execute(query)
    results = c.fetchall()
    conn.close()
    
    return {'query': query, 'results': results}

@app.route('/login', methods=['POST'])
def login():
    """
    VULNERABLE: SQL Injection in authentication
    Allows authentication bypass
    """
    username = request.json.get('username', '')
    password = request.json.get('password', '')
    
    conn = sqlite3.connect('users.db')
    c = conn.cursor()
    
    # VULNERABLE: Authentication bypass through SQL injection
    query = f"SELECT * FROM users WHERE username = '{username}' AND password = '{password}'"
    
    c.execute(query)
    user = c.fetchone()
    conn.close()
    
    if user:
        return {'status': 'success', 'message': 'Logged in', 'query': query}
    else:
        return {'status': 'failed', 'message': 'Invalid credentials', 'query': query}

# Example Exploits:
"""
1. Basic SQL Injection:
   /product/search?name='; DROP TABLE products; --

2. Union-based SQL Injection:
   /product/search?name=' UNION SELECT 1,2,3,4 --

3. Authentication Bypass:
   POST /login
   {"username": "admin' --", "password": "anything"}

4. Boolean-based Blind SQL Injection:
   /product/1 OR 1=1 --

5. Time-based Blind SQL Injection:
   /product/1; SELECT CASE WHEN (1=1) THEN pg_sleep(5) ELSE pg_sleep(0) END --
"""

if __name__ == '__main__':
    init_database()
    app.run(debug=True, port=5001)
