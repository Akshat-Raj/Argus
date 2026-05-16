"""
Supply chain attack detection.

Detects:
  1. Typosquatting      — package names suspiciously close to popular ones
  2. Malicious scripts  — postinstall/preinstall with data-exfiltration patterns
  3. Malicious init     — network calls / subprocess in package __init__.py
  4. Secret exfiltration — env/credential reads combined with outbound network calls
"""

import ast
import difflib
import json
import os
import re
from pathlib import Path

# Representative popular npm packages for typosquat comparison
_POPULAR_NPM: list[str] = [
    "axios", "react", "lodash", "express", "moment", "chalk", "commander",
    "request", "async", "bluebird", "underscore", "webpack", "typescript",
    "eslint", "prettier", "jest", "mocha", "react-dom", "react-router",
    "redux", "vue", "angular", "next", "nuxt", "socket.io", "cors",
    "body-parser", "dotenv", "uuid", "semver", "inquirer", "yargs",
    "minimist", "glob", "rimraf", "cross-env", "nodemon", "pm2", "helmet",
    "passport", "jsonwebtoken", "bcrypt", "sequelize", "mongoose", "prisma",
    "typeorm", "knex", "node-fetch", "cross-fetch", "got", "superagent",
]

# Representative popular PyPI packages
_POPULAR_PYPI: list[str] = [
    "requests", "numpy", "pandas", "scipy", "matplotlib", "pillow",
    "flask", "django", "fastapi", "sqlalchemy", "celery", "redis",
    "boto3", "pydantic", "pytest", "black", "mypy", "flake8",
    "cryptography", "paramiko", "litellm", "openai", "anthropic",
    "langchain", "transformers", "torch", "tensorflow", "keras",
    "scikit-learn", "xgboost", "click", "typer", "rich", "httpx",
    "aiohttp", "uvicorn", "gunicorn", "alembic", "pymongo",
    "psycopg2", "asyncpg", "colorama", "tqdm", "arrow", "pendulum",
]

# Install script patterns indicating malicious intent
_SCRIPT_PATTERNS: list[tuple[str, str, str]] = [
    (r"curl\s+https?://", "CRITICAL", "curl to external URL in install script"),
    (r"wget\s+https?://", "CRITICAL", "wget from external URL in install script"),
    (r"https?://(?!localhost|127\.0\.0\.1)", "CRITICAL", "outbound HTTP call in install script"),
    (r"process\.env", "HIGH", "environment variable read in install script"),
    (r"Buffer\.from.*\.toString\(['\"]base64", "CRITICAL", "base64-encoding env data in install script"),
    (r"require\(['\"]https?['\"]\)", "HIGH", "http(s) module used in install script"),
    (r"child_process", "CRITICAL", "child_process use in install script"),
    (r"\.ssh|\.aws|\.gnupg|credentials", "CRITICAL", "credential path accessed in install script"),
    (r"base64", "HIGH", "base64 encoding in install script (data obfuscation)"),
    (r'eval\(|exec\(', "CRITICAL", "eval/exec in install script"),
]

# Patterns indicating malicious __init__.py
_INIT_PATTERNS: list[tuple[str, str, str]] = [
    (r"urllib\.request\.urlopen", "CRITICAL", "outbound HTTP call fires on package import"),
    (r"requests\.(get|post|put|delete)\s*\(", "CRITICAL", "outbound HTTP call fires on package import"),
    (r"httpx\.(get|post)\s*\(", "CRITICAL", "outbound HTTP call fires on package import"),
    (r"http\.client\.(HTTPConnection|HTTPSConnection)", "CRITICAL", "raw HTTP socket on package import"),
    (r"socket\.connect\s*\(", "HIGH", "raw socket connection on package import"),
    (r"subprocess\.(run|call|Popen|check_output)\s*\(", "CRITICAL", "subprocess execution on package import"),
    (r"os\.system\s*\(", "CRITICAL", "os.system call on package import"),
    (r"os\.environ", "HIGH", "environment variable access on package import"),
    (r"base64\.(b64encode|encodebytes)\s*\(", "HIGH", "base64 encoding on package import (data exfil pattern)"),
    (r"eval\s*\(|exec\s*\(", "CRITICAL", "eval/exec fires on package import"),
    (r"__import__\s*\(", "HIGH", "dynamic import on package import"),
]

_SECRET_ENV_NAMES = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "GITHUB_TOKEN",
    "GITLAB_TOKEN",
    "NPM_TOKEN",
    "PYPI_TOKEN",
    "TWINE_PASSWORD",
    "DATABASE_URL",
    "KUBECONFIG",
    "SSH_AUTH_SOCK",
}

_CREDENTIAL_PATH_PATTERNS = (
    ".ssh/id_rsa",
    ".ssh/id_ed25519",
    ".aws/credentials",
    ".docker/config.json",
    "kube/config",
)

_PYTHON_SKIP_DIRS = {
    ".git",
    ".hg",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    "__pycache__",
    "node_modules",
}


# Packages that look like extensions of a popular name but are legitimate companions
# (e.g. "webpack-cli" extends "webpack" — not a typosquat)
_LEGITIMATE_PREFIXES = {
    "webpack": {"webpack-cli", "webpack-dev-server", "webpack-merge", "webpack-node-externals"},
    "react": {"react-dom", "react-router", "react-router-dom", "react-redux", "react-query"},
    "eslint": {"eslint-config-airbnb", "eslint-plugin-react", "eslint-config-prettier"},
    "babel": {"babel-loader", "babel-jest", "babel-preset-env"},
}


def _is_legitimate_companion(name: str, popular: str) -> bool:
    """Return True if `name` is a well-known companion/plugin of `popular`."""
    companions = _LEGITIMATE_PREFIXES.get(popular, set())
    if name in companions:
        return True
    # Also skip if name is just popular + '-something' and the prefix matches exactly
    norm_pop = popular.lower().replace("-", "").replace("_", "")
    norm_name = name.lower().replace("-", "").replace("_", "")
    # Only flag if they are nearly identical (transposition / single char swap)
    # not if name is clearly an extension (much longer)
    if norm_name.startswith(norm_pop) and len(norm_name) > len(norm_pop) + 3:
        return True
    return False


def _typosquat_hits(name: str, popular: list[str], threshold: float = 0.82) -> list[dict]:
    name_lower = name.lower()
    norm = name_lower.replace("-", "").replace("_", "")

    hits = []
    for pop in popular:
        pop_norm = pop.lower().replace("-", "").replace("_", "")
        if norm == pop_norm:
            continue  # exact match → this IS the package
        if _is_legitimate_companion(name_lower, pop):
            continue
        ratio = difflib.SequenceMatcher(None, norm, pop_norm).ratio()
        edit_distance = _bounded_levenshtein(norm, pop_norm, 2)
        if ratio >= threshold or edit_distance <= 1 or _has_adjacent_transposition(norm, pop_norm):
            hits.append({"popular_package": pop, "similarity": round(ratio, 3)})
    return sorted(hits, key=lambda x: x["similarity"], reverse=True)


def _bounded_levenshtein(a: str, b: str, max_distance: int) -> int:
    if abs(len(a) - len(b)) > max_distance:
        return max_distance + 1
    previous = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        current = [i]
        row_min = i
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            value = min(previous[j] + 1, current[j - 1] + 1, previous[j - 1] + cost)
            current.append(value)
            row_min = min(row_min, value)
        if row_min > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def _has_adjacent_transposition(a: str, b: str) -> bool:
    if len(a) != len(b) or a == b:
        return False
    diffs = [i for i, (ca, cb) in enumerate(zip(a, b)) if ca != cb]
    return (
        len(diffs) == 2
        and diffs[1] == diffs[0] + 1
        and a[diffs[0]] == b[diffs[1]]
        and a[diffs[1]] == b[diffs[0]]
    )


def _scan_script(script_name: str, body: str, pkg_name: str) -> list[dict]:
    found = []
    for pattern, severity, description in _SCRIPT_PATTERNS:
        if re.search(pattern, body, re.IGNORECASE):
            found.append({
                "type": "MALICIOUS_INSTALL_SCRIPT",
                "severity": severity,
                "ecosystem": "npm",
                "package": pkg_name,
                "script": script_name,
                "script_body": body[:400],
                "detail": f"Script '{script_name}': {description}",
                "attack_vector": (
                    "Install scripts run with full user privileges during `npm install`. "
                    "A postinstall hook can silently exfiltrate API keys, AWS credentials, "
                    "and SSH keys before the developer sees any output — identical to the "
                    "2018 event-stream / flatmap-stream attack and the 2024 axios-style attacks."
                ),
                "remediation": (
                    f"Remove the '{script_name}' script from package.json. "
                    "If a dependency ships this script, remove the dependency immediately "
                    "and rotate all credentials accessible at install time."
                ),
            })
            break  # one finding per script block
    return found


def _parse_req_line(line: str) -> tuple[str, str | None]:
    line = line.split("#", 1)[0].strip()
    if not line or line.startswith("-"):
        return "", None
    match = re.match(r"^\s*([A-Za-z0-9_.-]+)(?:\[[^\]]+\])?\s*(?:==|===)\s*([^,;\s]+)", line)
    if match:
        return match.group(1), match.group(2)
    pkg_name = re.split(r"[=<>!~\[ ;]", line)[0].strip()
    return pkg_name, None


def _imports_module(tree: ast.AST, module_name: str) -> bool:
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            if any(alias.name == module_name or alias.name.startswith(f"{module_name}.") for alias in node.names):
                return True
        if isinstance(node, ast.ImportFrom):
            if node.module == module_name or (node.module and node.module.startswith(f"{module_name}.")):
                return True
    return False


def _called_name(node: ast.AST) -> str:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        base = _called_name(node.value)
        return f"{base}.{node.attr}" if base else node.attr
    return ""


def _literal_strings(node: ast.AST) -> list[str]:
    return [n.value for n in ast.walk(node) if isinstance(n, ast.Constant) and isinstance(n.value, str)]


def _suspicious_trigger_name(name: str) -> bool:
    lowered = name.lower()
    return any(token in lowered for token in ("secret", "harvest", "collect", "exfil", "beacon", "telemetry", "credential"))


def _scan_python_for_exfil(project_path: str, py_file: Path) -> list[dict]:
    try:
        content = py_file.read_text(encoding="utf-8", errors="replace")
        tree = ast.parse(content, filename=str(py_file))
    except (OSError, SyntaxError):
        return []

    env_reads: set[str] = set()
    credential_paths: set[str] = set()
    network_calls: list[tuple[str, int, str]] = []
    shell_exec: list[tuple[str, int]] = []
    shell_urls: list[str] = []
    top_level_triggers: set[str] = set()
    function_defs: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}

    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            function_defs[node.name] = node
        if isinstance(node, ast.Call):
            call_name = _called_name(node.func)
            strings = _literal_strings(node)
            for value in strings:
                if value in _SECRET_ENV_NAMES:
                    env_reads.add(value)
                if any(path in value for path in _CREDENTIAL_PATH_PATTERNS):
                    credential_paths.add(value)
            if call_name in {"os.getenv", "os.environ.get", "os.environ.__getitem__"}:
                env_reads.update(value for value in strings if value)
            if call_name in {
                "requests.post",
                "requests.get",
                "httpx.post",
                "httpx.get",
                "urllib.request.urlopen",
                "urllib3.PoolManager.request",
            }:
                endpoint = next((value for value in strings if value.startswith(("http://", "https://"))), "")
                network_calls.append((call_name, getattr(node, "lineno", 0), endpoint))
            if call_name in {"subprocess.run", "subprocess.call", "subprocess.Popen", "subprocess.check_output", "os.system"}:
                shell_exec.append((call_name, getattr(node, "lineno", 0)))
                for value in strings:
                    shell_urls.extend(re.findall(r"https?://[^\s'\"|)]+", value))

    for node in tree.body:
        if isinstance(node, ast.Call):
            name = _called_name(node.func)
            if name:
                top_level_triggers.add(name)
        elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
            name = _called_name(node.value.func)
            if name:
                top_level_triggers.add(name)
        elif isinstance(node, (ast.Import, ast.ImportFrom)) and py_file.name == "__init__.py":
            for secret_module in ("secrets", "security_fix", "_security"):
                if _imports_module(ast.Module(body=[node], type_ignores=[]), secret_module):
                    top_level_triggers.add(f"import {secret_module}")

    called_payloads = [
        name for name in top_level_triggers
        if name in function_defs
        and any(
            isinstance(child, ast.Call)
            and _called_name(child.func) in {"requests.post", "requests.get", "httpx.post", "httpx.get", "urllib.request.urlopen"}
            for child in ast.walk(function_defs[name])
        )
    ]

    findings: list[dict] = []
    if network_calls and (env_reads or credential_paths):
        rel = str(py_file.relative_to(project_path))
        first_call = network_calls[0]
        triggers = sorted(called_payloads or top_level_triggers)
        findings.append({
            "type": "SECRET_EXFILTRATION_PATTERN",
            "severity": "CRITICAL",
            "ecosystem": "pypi",
            "package": py_file.parent.name,
            "file": rel,
            "line": first_call[1],
            "detail": (
                "Python module reads secrets or credential files and performs outbound network calls. "
                f"Secrets: {sorted(env_reads)[:8]}; credential paths: {sorted(credential_paths)[:4]}."
            ),
            "attack_vector": (
                "Compromised package payload: a new security-looking module harvests environment "
                "variables, SSH/cloud/Kubernetes credentials, and posts them to an attacker endpoint. "
                "If imported by package __init__.py or executed at top level, this runs during normal app startup or CI."
            ),
            "evidence": {
                "network_call": first_call[0],
                "endpoint": first_call[2],
                "top_level_triggers": triggers,
                "shell_execution": [name for name, _ in shell_exec],
            },
            "remediation": (
                "Remove the compromised package version, pin to the last known-good release, audit lockfiles, "
                "purge package caches, and rotate all exposed API keys, cloud keys, deploy keys, and CI tokens."
            ),
        })
    elif shell_exec and shell_urls:
        rel = str(py_file.relative_to(project_path))
        findings.append({
            "type": "REMOTE_CODE_EXECUTION_FETCH",
            "severity": "CRITICAL",
            "ecosystem": "pypi",
            "package": py_file.parent.name,
            "file": rel,
            "line": shell_exec[0][1],
            "detail": "Python module executes a shell command that fetches a remote URL.",
            "attack_vector": "Install-time or import-time bootstrapper downloads attacker-controlled code and executes it.",
            "evidence": {
                "endpoint": shell_urls[0],
                "shell_execution": [name for name, _ in shell_exec],
            },
            "remediation": "Block the package, inspect CI logs, rotate publishing tokens, and rebuild from trusted lockfiles.",
        })
    return findings


def check_supply_chain_risks(project_path: str) -> str:
    """Scan a project directory for supply chain attack indicators.

    Checks three attack surfaces:
      1. Typosquatted dependency names (requirements.txt + package.json)
      2. Malicious install scripts (postinstall / preinstall / prepare in package.json)
      3. Outbound network / subprocess calls in installed package __init__.py files
         (looks inside .venv, venv, env, and a vendor/ directory if present)

    Returns a JSON report with severity counts and actionable remediation steps.
    Analogous real-world attacks covered: litellm-ai typosquat (Mar 2024),
    axios / axois typosquat campaigns, event-stream/flatmap-stream (2018).
    """
    project_path = os.path.abspath(project_path)
    if not os.path.isdir(project_path):
        return json.dumps({"status": "error", "error": f"'{project_path}' is not a directory."})

    findings: list[dict] = []

    # ── 1. package.json — typosquatting + malicious scripts ──────────────────
    pkg_json = os.path.join(project_path, "package.json")
    if os.path.exists(pkg_json):
        try:
            with open(pkg_json, encoding="utf-8") as f:
                pkg_data = json.load(f)

            all_deps = {
                **pkg_data.get("dependencies", {}),
                **pkg_data.get("devDependencies", {}),
            }
            for dep in all_deps:
                for hit in _typosquat_hits(dep, _POPULAR_NPM):
                    findings.append({
                        "type": "TYPOSQUATTING",
                        "severity": "CRITICAL",
                        "ecosystem": "npm",
                        "package": dep,
                        "detail": (
                            f"'{dep}' is {hit['similarity']*100:.0f}% similar to popular package "
                            f"'{hit['popular_package']}' — likely typosquat"
                        ),
                        "attack_vector": (
                            "Typosquatting: attacker publishes a package with a name one keystroke "
                            "away from a popular package. Developer types the wrong name and installs "
                            "malware. Mirrors the 2024 'axois' campaign targeting axios users."
                        ),
                        "remediation": (
                            f"Remove '{dep}' from package.json. "
                            f"Install the legitimate package: npm install {hit['popular_package']}"
                        ),
                    })

            for script_name in ("preinstall", "install", "postinstall", "prepare"):
                body = pkg_data.get("scripts", {}).get(script_name, "")
                if body:
                    findings.extend(_scan_script(script_name, body, pkg_data.get("name", "project")))

        except (json.JSONDecodeError, OSError) as e:
            findings.append({"type": "PARSE_ERROR", "severity": "LOW",
                              "detail": f"Could not parse package.json: {e}"})

    # ── 2. requirements.txt — typosquatting ──────────────────────────────────
    req_txt = os.path.join(project_path, "requirements.txt")
    if os.path.exists(req_txt):
        try:
            with open(req_txt, encoding="utf-8") as f:
                for raw_line in f:
                    pkg_name, _version = _parse_req_line(raw_line)
                    if not pkg_name:
                        continue
                    for hit in _typosquat_hits(pkg_name, _POPULAR_PYPI):
                        findings.append({
                            "type": "TYPOSQUATTING",
                            "severity": "CRITICAL",
                            "ecosystem": "pypi",
                            "package": pkg_name,
                            "detail": (
                                f"'{pkg_name}' is {hit['similarity']*100:.0f}% similar to popular "
                                f"package '{hit['popular_package']}' — likely typosquat"
                            ),
                            "attack_vector": (
                                "Typosquatting on PyPI: matches the March 2024 litellm-ai attack "
                                "where BeeHive-AI published 'litellm-ai' targeting developers who "
                                "mistyped 'litellm'. The package ran _beacon() on import to exfiltrate "
                                "OPENAI_API_KEY, ANTHROPIC_API_KEY, AWS credentials, and GITHUB_TOKEN."
                            ),
                            "remediation": (
                                f"Remove '{pkg_name}' from requirements.txt. "
                                f"Install the legitimate package: pip install {hit['popular_package']}. "
                                "Immediately rotate any API keys or credentials present in your environment."
                            ),
                        })
        except OSError as e:
            findings.append({"type": "PARSE_ERROR", "severity": "LOW",
                              "detail": f"Could not read requirements.txt: {e}"})

    # ── 3. Python package files — malicious import-time / exfil code ─────────
    scan_roots: list[Path] = []
    for candidate in (".venv", "venv", "env", "vendor"):
        p = Path(project_path) / candidate
        if p.is_dir():
            scan_roots.append(p)

    for root in scan_roots:
        for init_file in root.rglob("__init__.py"):
            try:
                content = init_file.read_text(encoding="utf-8", errors="replace")
            except OSError:
                continue

            # Skip obviously large standard-library stubs
            if len(content) > 50_000:
                continue

            matched_patterns = set()
            for pattern, severity, description in _INIT_PATTERNS:
                if pattern in matched_patterns:
                    continue
                if re.search(pattern, content):
                    pkg_name_guess = init_file.parent.name
                    matched_patterns.add(pattern)
                    findings.append({
                        "type": "MALICIOUS_INIT_CODE",
                        "severity": severity,
                        "ecosystem": "pypi",
                        "package": pkg_name_guess,
                        "file": str(init_file.relative_to(project_path)),
                        "detail": f"Package __init__.py: {description}",
                        "attack_vector": (
                            "Import-time execution: the attacker ships a facade package that mirrors "
                            "a popular library's public API while running malicious code at import. "
                            "The victim's application works normally, masking the compromise. "
                            "Pattern matches the litellm-ai and similar PyPI typosquat campaigns."
                        ),
                        "remediation": (
                            f"Immediately remove the package: pip uninstall {pkg_name_guess}. "
                            f"Inspect the full file at {init_file} for exfiltrated secrets. "
                            "Rotate ALL credentials (API keys, AWS keys, tokens) that were in "
                            "environment variables at any time this package was installed."
                        ),
                    })
                    break  # one finding per file

            try:
                init_tree = ast.parse(content, filename=str(init_file))
            except SyntaxError:
                init_tree = None

            imported_suspicious_names: set[str] = set()
            top_level_calls: set[str] = set()
            if init_tree is not None:
                for node in init_tree.body:
                    if isinstance(node, ast.ImportFrom) and node.level > 0:
                        imported_suspicious_names.update(
                            alias.asname or alias.name
                            for alias in node.names
                            if _suspicious_trigger_name(alias.asname or alias.name)
                        )
                    elif isinstance(node, ast.Expr) and isinstance(node.value, ast.Call):
                        call_name = _called_name(node.value.func)
                        if call_name:
                            top_level_calls.add(call_name)

            triggered = sorted(name for name in imported_suspicious_names if name in top_level_calls)
            if triggered:
                pkg_name_guess = init_file.parent.name
                findings.append({
                    "type": "IMPORT_TIME_EXFIL_TRIGGER",
                    "severity": "CRITICAL",
                    "ecosystem": "pypi",
                    "package": pkg_name_guess,
                    "file": str(init_file.relative_to(project_path)),
                    "detail": (
                        "Package __init__.py imports a suspiciously named helper and invokes it at import time: "
                        f"{', '.join(triggered)}."
                    ),
                    "attack_vector": (
                        "Import-time execution: compromised package exposes a normal public API while "
                        "triggering a hidden helper during `import package`."
                    ),
                    "remediation": (
                        f"Remove or pin away from the suspicious {pkg_name_guess} release, inspect the imported helper module, "
                        "and rotate credentials available to the process or CI runner if the helper performs secret access."
                    ),
                })

    for root in scan_roots or [Path(project_path)]:
        for py_file in root.rglob("*.py"):
            if any(part in _PYTHON_SKIP_DIRS for part in py_file.parts):
                continue
            if len(py_file.parts) > 0 and py_file.name.endswith("_test.py"):
                continue
            try:
                if py_file.stat().st_size > 80_000:
                    continue
            except OSError:
                continue
            findings.extend(_scan_python_for_exfil(project_path, py_file))

    # ── Deduplicate and summarise ─────────────────────────────────────────────
    seen: set[tuple] = set()
    unique: list[dict] = []
    for f in findings:
        key = (f.get("type"), f.get("package"), f.get("detail", "")[:100])
        if key not in seen:
            seen.add(key)
            unique.append(f)

    by_severity = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for f in unique:
        sev = f.get("severity", "LOW")
        by_severity[sev] = by_severity.get(sev, 0) + 1

    return json.dumps({
        "status": "success",
        "project_path": project_path,
        "total_findings": len(unique),
        "critical": by_severity["CRITICAL"],
        "high": by_severity["HIGH"],
        "attack_surface_summary": {
            "dependency_manifest": "requirements.txt and package.json checked for typosquatting and suspicious dependency names",
            "install_hooks": "npm lifecycle scripts checked for curl/wget/http/env/credential exfil patterns",
            "python_packages": "vendored/site-package Python files checked for import-time network, subprocess, and secret harvesting",
        },
        "findings": unique,
    }, indent=2)
