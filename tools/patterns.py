"""Shared security detection patterns — single source of truth across all tools."""

# (pattern, severity, description)
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("ghp_", "CRITICAL", "GitHub Personal Access Token prefix"),
    ("ghs_", "CRITICAL", "GitHub App installation token prefix"),
    ("gho_", "CRITICAL", "GitHub OAuth token prefix"),
    ("AKIA", "CRITICAL", "AWS Access Key ID prefix"),
    ("AWS_SECRET", "HIGH", "AWS Secret Key environment variable name"),
    ("sk-", "HIGH", "OpenAI/Stripe-style API key prefix"),
    ("-----BEGIN RSA PRIVATE KEY", "CRITICAL", "RSA private key"),
    ("-----BEGIN EC PRIVATE KEY", "CRITICAL", "EC private key"),
    ("-----BEGIN OPENSSH PRIVATE KEY", "CRITICAL", "OpenSSH private key"),
    ("TOKEN=", "HIGH", "Token assignment in log/config line"),
    ("password=", "HIGH", "Password in log/config output"),
    ("secret=", "HIGH", "Secret value in log/config output"),
    ("API_KEY", "CRITICAL", "Hardcoded API key variable"),
    ("SECRET_KEY", "CRITICAL", "Hardcoded secret key variable"),
    ("DATABASE_URL", "HIGH", "Database connection string (may contain credentials)"),
    ("PRIVATE KEY", "CRITICAL", "Private key material"),
]

# (pattern, cwe, severity, vuln_type, remediation)
INJECTION_PATTERNS: list[tuple[str, str, str, str, str]] = [
    ("f'SELECT", "CWE-89", "CRITICAL", "SQL Injection (f-string)", "Use parameterized queries: cursor.execute('SELECT ... WHERE id=%s', (user_id,))"),
    ('f"SELECT', "CWE-89", "CRITICAL", "SQL Injection (f-string)", "Use parameterized queries: cursor.execute('SELECT ... WHERE id=%s', (user_id,))"),
    ('execute("SELECT', "CWE-89", "HIGH", "Possible SQL string concatenation", "Use parameterized queries instead of string building"),
    ("shell=True", "CWE-78", "CRITICAL", "Command Injection via shell=True", "Remove shell=True; pass args as list: subprocess.run(['cmd', arg])"),
    ("os.system(", "CWE-78", "HIGH", "Command Injection via os.system", "Use subprocess.run with args list instead"),
    ("eval(", "CWE-95", "HIGH", "Code Injection via eval()", "Never eval() user-controlled input"),
    ("exec(", "CWE-95", "HIGH", "Code Injection via exec()", "Never exec() user-controlled input"),
    ("innerHTML", "CWE-79", "HIGH", "XSS via innerHTML", "Use textContent or DOMPurify for user content"),
    ("dangerouslySetInnerHTML", "CWE-79", "HIGH", "React XSS via dangerouslySetInnerHTML", "Sanitize HTML with DOMPurify before rendering"),
    ("requests.get(user_input", "CWE-918", "HIGH", "SSRF via unvalidated URL", "Validate and allowlist URLs before outbound requests"),
    ("pickle.loads(", "CWE-502", "CRITICAL", "Insecure Deserialization (pickle)", "Never unpickle untrusted data; use JSON instead"),
    ("yaml.load(", "CWE-502", "HIGH", "Unsafe YAML deserialization", "Use yaml.safe_load() instead of yaml.load()"),
    ("__import__(", "CWE-95", "HIGH", "Dynamic import (code injection risk)", "Avoid dynamic imports from user-controlled strings"),
]
