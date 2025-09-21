"""
Security Vulnerabilities Test File
WARNING: This file contains intentional security vulnerabilities for testing purposes only.
DO NOT use this code in production environments.
"""

import os
import subprocess
import pickle
import sqlite3
import hashlib
import random
import re
import yaml
import xml.etree.ElementTree as ET
from flask import Flask, request, render_template_string, redirect
import requests
import jwt

app = Flask(__name__)

# ============================================================================
# 1. SQL INJECTION VULNERABILITIES
# ============================================================================

def vulnerable_sql_injection(user_id):
    """CWE-89: SQL Injection"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)
    
    # VULNERABLE: String formatting
    query2 = "SELECT * FROM users WHERE name = '%s'" % user_id
    cursor.execute(query2)
    
    # VULNERABLE: f-string formatting
    username = request.args.get('username')
    query3 = f"SELECT * FROM accounts WHERE username = '{username}'"
    cursor.execute(query3)
    
    return cursor.fetchall()

def vulnerable_sql_injection_order_by(sort_column):
    """CWE-89: SQL Injection in ORDER BY"""
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Unvalidated column name in ORDER BY
    query = f"SELECT * FROM products ORDER BY {sort_column}"
    cursor.execute(query)
    
    return cursor.fetchall()

# ============================================================================
# 2. COMMAND INJECTION VULNERABILITIES
# ============================================================================

def vulnerable_command_injection(filename):
    """CWE-78: OS Command Injection"""
    # VULNERABLE: Direct command execution
    os.system(f"cat {filename}")
    
    # VULNERABLE: Shell=True with user input
    subprocess.call(f"echo {filename}", shell=True)
    
    # VULNERABLE: Using os.popen
    result = os.popen(f"ls -la {filename}").read()
    
    # VULNERABLE: subprocess.run with shell=True
    subprocess.run(["sh", "-c", f"grep pattern {filename}"])
    
    return result

def vulnerable_eval_injection(user_input):
    """CWE-95: Eval Injection"""
    # VULNERABLE: Direct eval of user input
    result = eval(user_input)
    
    # VULNERABLE: exec with user input
    exec(f"value = {user_input}")
    
    return result

# ============================================================================
# 3. PATH TRAVERSAL VULNERABILITIES
# ============================================================================

def vulnerable_path_traversal(file_path):
    """CWE-22: Path Traversal"""
    # VULNERABLE: No path validation
    with open(f"/var/www/uploads/{file_path}", 'r') as f:
        content = f.read()
    
    # VULNERABLE: Insufficient validation
    if not file_path.startswith('/etc'):
        with open(file_path, 'r') as f:
            data = f.read()
    
    return content

@app.route('/download')
def vulnerable_file_download():
    """CWE-22: Path Traversal in file download"""
    # VULNERABLE: Direct file access from user input
    filename = request.args.get('file')
    with open(f"./uploads/{filename}", 'rb') as f:
        return f.read()

# ============================================================================
# 4. CROSS-SITE SCRIPTING (XSS) VULNERABILITIES
# ============================================================================

@app.route('/xss')
def vulnerable_xss():
    """CWE-79: Cross-site Scripting"""
    # VULNERABLE: Direct HTML rendering without escaping
    name = request.args.get('name', '')
    return f"<h1>Welcome {name}</h1>"

@app.route('/template_xss')
def vulnerable_template_injection():
    """CWE-79: Server-Side Template Injection"""
    # VULNERABLE: Direct template rendering from user input
    template = request.args.get('template', '')
    return render_template_string(template)

# ============================================================================
# 5. INSECURE DESERIALIZATION
# ============================================================================

def vulnerable_pickle_deserialization(data):
    """CWE-502: Deserialization of Untrusted Data"""
    # VULNERABLE: Pickle deserialization of untrusted data
    obj = pickle.loads(data)
    return obj

def vulnerable_yaml_deserialization(yaml_string):
    """CWE-502: YAML Deserialization"""
    # VULNERABLE: Using yaml.load with Loader=yaml.Loader
    data = yaml.load(yaml_string, Loader=yaml.Loader)
    return data

# ============================================================================
# 6. SENSITIVE DATA EXPOSURE
# ============================================================================

def vulnerable_hardcoded_credentials():
    """CWE-798: Use of Hard-coded Credentials"""
    # VULNERABLE: Hardcoded passwords
    admin_password = "admin123"
    api_key = "sk-1234567890abcdef"
    database_password = "P@ssw0rd123"
    
    # VULNERABLE: Hardcoded database connection
    connection_string = "postgresql://admin:password123@localhost:5432/mydb"
    
    # VULNERABLE: Hardcoded AWS credentials
    aws_access_key = "AKIAIOSFODNN7EXAMPLE"
    aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
    
    return api_key

def vulnerable_weak_encryption(password):
    """CWE-327: Use of Broken Crypto"""
    # VULNERABLE: MD5 for password hashing
    hashed = hashlib.md5(password.encode()).hexdigest()
    
    # VULNERABLE: SHA1 for password hashing
    hashed2 = hashlib.sha1(password.encode()).hexdigest()
    
    return hashed

# ============================================================================
# 7. INSECURE RANDOM NUMBER GENERATION
# ============================================================================

def vulnerable_weak_random():
    """CWE-330: Use of Insufficiently Random Values"""
    # VULNERABLE: Using random for security purposes
    token = random.randint(1000, 9999)
    
    # VULNERABLE: Predictable random seed
    random.seed(12345)
    session_id = random.randint(0, 1000000)
    
    return token

# ============================================================================
# 8. SSRF (SERVER-SIDE REQUEST FORGERY)
# ============================================================================

@app.route('/fetch')
def vulnerable_ssrf():
    """CWE-918: Server-Side Request Forgery"""
    # VULNERABLE: Unvalidated URL from user input
    url = request.args.get('url')
    response = requests.get(url)
    
    # VULNERABLE: Partial validation insufficient
    if url.startswith('http'):
        data = requests.get(url).text
    
    return response.text

# ============================================================================
# 9. XXE (XML EXTERNAL ENTITY)
# ============================================================================

def vulnerable_xxe(xml_string):
    """CWE-611: XML External Entity Reference"""
    # VULNERABLE: XML parsing with external entities enabled
    root = ET.fromstring(xml_string)
    
    # VULNERABLE: Using lxml with resolve_entities=True
    from lxml import etree
    parser = etree.XMLParser(resolve_entities=True)
    doc = etree.fromstring(xml_string, parser)
    
    return root

# ============================================================================
# 10. RACE CONDITIONS
# ============================================================================

balance = 1000

def vulnerable_race_condition(amount):
    """CWE-362: Race Condition"""
    global balance
    
    # VULNERABLE: Check-then-act without locking
    if balance >= amount:
        # Time-of-check to time-of-use vulnerability
        balance -= amount
        return True
    return False

# ============================================================================
# 11. OPEN REDIRECT
# ============================================================================

@app.route('/redirect')
def vulnerable_open_redirect():
    """CWE-601: Open Redirect"""
    # VULNERABLE: Unvalidated redirect
    target = request.args.get('url')
    return redirect(target)

# ============================================================================
# 12. INSUFFICIENT AUTHORIZATION
# ============================================================================

@app.route('/admin')
def vulnerable_missing_auth():
    """CWE-862: Missing Authorization"""
    # VULNERABLE: No authentication check
    user_id = request.args.get('user_id')
    # Directly accessing admin functions without auth
    return f"Admin panel for user {user_id}"

def vulnerable_broken_access_control(user_id, document_id):
    """CWE-639: Insecure Direct Object Reference"""
    # VULNERABLE: No authorization check for document access
    conn = sqlite3.connect('database.db')
    cursor = conn.cursor()
    
    # User can access any document by changing document_id
    query = f"SELECT * FROM documents WHERE id = {document_id}"
    cursor.execute(query)
    
    return cursor.fetchall()

# ============================================================================
# 13. JWT VULNERABILITIES
# ============================================================================

def vulnerable_jwt_none_algorithm(token):
    """CWE-347: Improper Verification of Cryptographic Signature"""
    # VULNERABLE: Accepting 'none' algorithm
    decoded = jwt.decode(token, options={"verify_signature": False})
    return decoded

def vulnerable_jwt_weak_secret(token):
    """CWE-347: Weak JWT Secret"""
    # VULNERABLE: Weak/predictable secret
    secret = "secret"
    decoded = jwt.decode(token, secret, algorithms=["HS256"])
    return decoded

# ============================================================================
# 14. LDAP INJECTION
# ============================================================================

def vulnerable_ldap_injection(username):
    """CWE-90: LDAP Injection"""
    # VULNERABLE: Unescaped LDAP query
    import ldap
    
    conn = ldap.initialize('ldap://localhost')
    # Direct concatenation in LDAP filter
    filter_string = f"(&(uid={username})(objectClass=person))"
    result = conn.search_s('dc=example,dc=com', ldap.SCOPE_SUBTREE, filter_string)
    
    return result

# ============================================================================
# 15. REGULAR EXPRESSION DOS (ReDoS)
# ============================================================================

def vulnerable_redos(user_input):
    """CWE-1333: Inefficient Regular Expression Complexity"""
    # VULNERABLE: Catastrophic backtracking regex
    pattern = r'^(a+)+$'
    
    # This can cause exponential time complexity
    if re.match(pattern, user_input):
        return "Match found"
    
    # Another vulnerable pattern
    email_pattern = r'^([a-zA-Z0-9])+@([a-zA-Z0-9])+\.([a-zA-Z]{2,4})+$'
    re.match(email_pattern, user_input)
    
    return "No match"

# ============================================================================
# 16. BUFFER OVERFLOW (Python context)
# ============================================================================

def vulnerable_format_string(user_input):
    """CWE-134: Format String Vulnerability"""
    # VULNERABLE: User controlled format string
    log_message = user_input % {"password": "secret123"}
    
    # VULNERABLE: Using user input in string formatting
    output = f"User said: {user_input}".format(data="sensitive")
    
    return output

# ============================================================================
# 17. INSECURE FILE OPERATIONS
# ============================================================================

def vulnerable_file_upload(file_content, filename):
    """CWE-434: Unrestricted Upload of Dangerous File"""
    # VULNERABLE: No file type validation
    with open(f"uploads/{filename}", 'wb') as f:
        f.write(file_content)
    
    # VULNERABLE: Executing uploaded files
    if filename.endswith('.py'):
        exec(open(f"uploads/{filename}").read())
    
    return "File uploaded"

def vulnerable_temp_file():
    """CWE-377: Insecure Temporary File"""
    # VULNERABLE: Predictable temp file name
    temp_file = "/tmp/tempfile.txt"
    
    # VULNERABLE: World-readable temp file
    with open(temp_file, 'w') as f:
        f.write("sensitive data")
    os.chmod(temp_file, 0o777)
    
    return temp_file

# ============================================================================
# 18. TIMING ATTACKS
# ============================================================================

def vulnerable_timing_attack(input_password):
    """CWE-208: Observable Timing Discrepancy"""
    actual_password = "SuperSecretPassword123"
    
    # VULNERABLE: Character-by-character comparison
    for i in range(len(input_password)):
        if i >= len(actual_password):
            return False
        if input_password[i] != actual_password[i]:
            return False
    
    return len(input_password) == len(actual_password)

# ============================================================================
# 19. UNSAFE REFLECTION
# ============================================================================

def vulnerable_unsafe_reflection(class_name, method_name):
    """CWE-470: Unsafe Reflection"""
    # VULNERABLE: Dynamic class/method invocation from user input
    module = __import__('os')
    func = getattr(module, method_name)
    result = func()
    
    # VULNERABLE: Creating class from user input
    klass = globals()[class_name]
    instance = klass()
    
    return result

# ============================================================================
# 20. INFORMATION DISCLOSURE
# ============================================================================

@app.errorhandler(Exception)
def vulnerable_error_handler(e):
    """CWE-209: Information Exposure Through Error Messages"""
    # VULNERABLE: Exposing stack trace to user
    import traceback
    return f"<pre>{traceback.format_exc()}</pre>", 500

def vulnerable_debug_info():
    """CWE-215: Information Exposure Through Debug Information"""
    # VULNERABLE: Debug mode in production
    app.debug = True
    
    # VULNERABLE: Verbose logging
    import logging
    logging.basicConfig(level=logging.DEBUG)
    
    # VULNERABLE: Exposing system information
    return {
        "python_version": os.sys.version,
        "platform": os.sys.platform,
        "env_vars": dict(os.environ),
        "current_dir": os.getcwd()
    }

if __name__ == "__main__":
    # VULNERABLE: Debug mode enabled
    app.run(debug=True, host='0.0.0.0')
