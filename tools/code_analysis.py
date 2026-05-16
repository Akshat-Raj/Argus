"""
Code analysis tools for SAST security review.

Real integrations (in priority order):
  - Semgrep   : open-source SAST (https://semgrep.dev) — preferred for injection detection
  - Gitleaks  : secret scanning (https://gitleaks.io) — preferred for secret detection
  - GitHub API: PR diffs and commit diffs require GITHUB_TOKEN
  - Regex     : last-resort fallback using shared patterns (no external tools needed)
"""

import json
import logging
import os
import shutil
import subprocess
import tempfile
import time

import httpx

from tools.patterns import INJECTION_PATTERNS, SECRET_PATTERNS

logger = logging.getLogger(__name__)

_GH_BASE = "https://api.github.com"
_GH_API_VERSION = "2022-11-28"
_PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def _gh_token() -> str | None:
    for key in ("GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_TOKEN", "GITHUB_PAT"):
        val = os.environ.get(key, "").strip()
        if val:
            return val
    return None


def _gh_headers(accept: str = "application/vnd.github+json") -> dict:
    headers = {"Accept": accept, "X-GitHub-Api-Version": _GH_API_VERSION}
    token = _gh_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _gh_get(path: str, accept: str = "application/vnd.github+json", **params) -> httpx.Response:
    url = f"{_GH_BASE}{path}"
    for attempt in range(3):
        r = httpx.get(url, headers=_gh_headers(accept), params=params or None, timeout=30)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", 2 ** (attempt + 1)))
            logger.warning("GitHub rate limited — waiting %ds", wait)
            time.sleep(min(wait, 60))
            continue
        return r
    return r


# ---------------------------------------------------------------------------
# Semgrep integration
# ---------------------------------------------------------------------------

def _semgrep_binary() -> str | None:
    candidates = [
        os.environ.get("SEMGREP_BIN"),
        "/opt/homebrew/bin/semgrep",
        "/usr/local/bin/semgrep",
        shutil.which("semgrep"),
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen:
            continue
        seen.add(candidate)
        if os.path.exists(candidate) and os.access(candidate, os.X_OK):
            return candidate
    return None


def _semgrep_env() -> dict[str, str]:
    cache_home = os.path.join(_PROJECT_ROOT, ".cache")
    config_home = os.path.join(_PROJECT_ROOT, ".config")
    semgrep_cache = os.path.join(cache_home, "semgrep")
    semgrep_config = os.path.join(config_home, ".semgrep")
    os.makedirs(semgrep_cache, exist_ok=True)
    os.makedirs(semgrep_config, exist_ok=True)

    env = {
        **os.environ,
        "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION": "python",
        "XDG_CACHE_HOME": cache_home,
        "XDG_CONFIG_HOME": config_home,
        "SEMGREP_LOG_FILE": os.path.join(semgrep_cache, "semgrep.log"),
        "SEMGREP_SETTINGS_FILE": os.path.join(semgrep_config, "settings.yml"),
        "SEMGREP_VERSION_CACHE_PATH": os.path.join(cache_home, "semgrep_version"),
    }
    cert_file = "/opt/homebrew/etc/ca-certificates/cert.pem"
    if os.path.exists(cert_file):
        env.setdefault("SSL_CERT_FILE", cert_file)
        env.setdefault("REQUESTS_CA_BUNDLE", cert_file)
    return env


def _run_semgrep(code: str, language: str, filename: str) -> list[dict] | None:
    """Run semgrep on a code snippet. Returns findings or None if unavailable."""
    semgrep_bin = _semgrep_binary()
    if not semgrep_bin:
        return None
    ext_map = {
        "python": ".py", "javascript": ".js", "typescript": ".ts",
        "java": ".java", "go": ".go", "ruby": ".rb", "php": ".php",
        "c": ".c", "cpp": ".cpp", "rust": ".rs",
    }
    ext = ext_map.get(language.lower(), ".txt")
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=ext, delete=False, encoding="utf-8") as f:
            f.write(code)
            tmp_path = f.name

        result = subprocess.run(
            [
                semgrep_bin, "--config", "p/security-audit",
                "--config", "p/secrets",
                "--json", "--quiet", tmp_path,
            ],
            capture_output=True,
            text=True,
            timeout=60,
            env=_semgrep_env(),
        )
        os.unlink(tmp_path)

        if not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        findings = []
        for r in data.get("results", []):
            meta = r.get("extra", {}).get("metadata", {})
            findings.append({
                "line": r.get("start", {}).get("line"),
                "cwe": meta.get("cwe", [None])[0] if isinstance(meta.get("cwe"), list) else meta.get("cwe"),
                "severity": r.get("extra", {}).get("severity", "WARNING").upper().replace("WARNING", "MEDIUM").replace("ERROR", "HIGH"),
                "vulnerability": r.get("check_id", ""),
                "snippet": r.get("extra", {}).get("lines", "")[:120],
                "remediation": r.get("extra", {}).get("message", ""),
                "source": "semgrep",
            })
        return findings
    except subprocess.TimeoutExpired:
        logger.warning("Semgrep timed out")
        return None
    except json.JSONDecodeError as e:
        logger.error("Semgrep JSON parse error: %s", e)
        return None
    except Exception as e:
        logger.error("Semgrep error: %s", e)
        return None
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# Gitleaks integration
# ---------------------------------------------------------------------------

def _run_gitleaks(code: str, filename: str) -> list[dict] | None:
    """Run gitleaks on a code snippet. Returns findings or None if unavailable."""
    if not shutil.which("gitleaks"):
        return None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=os.path.splitext(filename)[-1] or ".txt", delete=False, encoding="utf-8") as f:
            f.write(code)
            tmp_path = f.name

        result = subprocess.run(
            ["gitleaks", "detect", "--source", tmp_path, "--report-format", "json", "--report-path", "-", "--no-git"],
            capture_output=True,
            text=True,
            timeout=30,
        )
        os.unlink(tmp_path)

        if not result.stdout.strip() or result.stdout.strip() == "null":
            return []
        data = json.loads(result.stdout)
        if not isinstance(data, list):
            data = [data] if data else []
        findings = []
        for leak in data:
            findings.append({
                "line": leak.get("StartLine"),
                "severity": "CRITICAL",
                "type": leak.get("Description", "Secret detected"),
                "matched_pattern": leak.get("RuleID", ""),
                "snippet": (leak.get("Secret") or leak.get("Match") or "")[:80],
                "source": "gitleaks",
            })
        return findings
    except subprocess.TimeoutExpired:
        logger.warning("Gitleaks timed out")
        return None
    except json.JSONDecodeError:
        return []
    except Exception as e:
        logger.error("Gitleaks error: %s", e)
        return None
    finally:
        try:
            if os.path.exists(tmp_path):
                os.unlink(tmp_path)
        except Exception:
            pass


# ---------------------------------------------------------------------------
# GitHub API tools
# ---------------------------------------------------------------------------

def get_pull_request_diff(repo: str, pr_number: int) -> str:
    """Retrieve the unified diff for a GitHub pull request.
    Returns diff text plus metadata (files changed, additions, deletions).
    Requires GITHUB_TOKEN.
    """
    if not _gh_token():
        return json.dumps({
            "status": "unconfigured",
            "error": "Set GITHUB_TOKEN to fetch PR diffs for code analysis.",
        })

    try:
        r_diff = _gh_get(f"/repos/{repo}/pulls/{pr_number}", accept="application/vnd.github.diff")
        r_meta = _gh_get(f"/repos/{repo}/pulls/{pr_number}")

        if r_diff.status_code == 404:
            return json.dumps({"status": "error", "error": f"PR #{pr_number} not found in {repo}."})
        r_diff.raise_for_status()

        meta = r_meta.json() if r_meta.status_code == 200 else {}
        diff_text = r_diff.text
        truncated = len(diff_text) > 30000
        return json.dumps({
            "status": "success",
            "repo": repo,
            "pr": pr_number,
            "title": meta.get("title", ""),
            "state": meta.get("state", ""),
            "files_changed": meta.get("changed_files", 0),
            "additions": meta.get("additions", 0),
            "deletions": meta.get("deletions", 0),
            "truncated": truncated,
            "diff": diff_text[:30000],
        })
    except httpx.HTTPStatusError as e:
        logger.error("GitHub API error fetching PR diff %s#%d: %s", repo, pr_number, e)
        return json.dumps({"status": "error", "error": f"GitHub API HTTP {e.response.status_code}: {e.response.text[:300]}"})
    except Exception as e:
        logger.exception("Unexpected error fetching PR diff for %s#%d", repo, pr_number)
        return json.dumps({"status": "error", "error": str(e)})


def list_recent_commits(repo: str, branch: str = "main", limit: int = 10) -> str:
    """List recent commits on a branch with author and message info.
    Requires GITHUB_TOKEN.
    """
    if not _gh_token():
        return json.dumps({
            "status": "unconfigured",
            "error": "Set GITHUB_TOKEN to list commits.",
            "commits": [],
        })

    try:
        r = _gh_get(f"/repos/{repo}/commits", sha=branch, per_page=min(limit, 100))
        if r.status_code == 404:
            return json.dumps({"status": "error", "error": f"Repo '{repo}' or branch '{branch}' not found.", "commits": []})
        r.raise_for_status()
        commits = [
            {
                "sha": c["sha"],
                "author_email": c.get("commit", {}).get("author", {}).get("email", ""),
                "author_name": c.get("commit", {}).get("author", {}).get("name", ""),
                "message": c.get("commit", {}).get("message", "").split("\n")[0][:120],
                "timestamp": c.get("commit", {}).get("author", {}).get("date", ""),
                "url": c.get("html_url", ""),
            }
            for c in r.json()[:limit]
        ]
        return json.dumps({"status": "success", "repo": repo, "branch": branch, "commits": commits})
    except httpx.HTTPStatusError as e:
        logger.error("GitHub API error listing commits for %s@%s: %s", repo, branch, e)
        return json.dumps({"status": "error", "error": f"GitHub API HTTP {e.response.status_code}", "commits": []})
    except Exception as e:
        logger.exception("Unexpected error listing commits for %s@%s", repo, branch)
        return json.dumps({"status": "error", "error": str(e), "commits": []})


def get_commit_diff(repo: str, commit_sha: str) -> str:
    """Retrieve the unified diff introduced by a specific commit.
    Requires GITHUB_TOKEN.
    """
    if not _gh_token():
        return json.dumps({
            "status": "unconfigured",
            "error": "Set GITHUB_TOKEN to fetch commit diffs.",
        })

    try:
        r = _gh_get(f"/repos/{repo}/commits/{commit_sha}", accept="application/vnd.github.diff")
        if r.status_code == 404:
            return json.dumps({"status": "error", "error": f"Commit '{commit_sha}' not found in {repo}."})
        r.raise_for_status()
        diff_text = r.text
        truncated = len(diff_text) > 30000
        return json.dumps({
            "status": "success",
            "repo": repo,
            "sha": commit_sha,
            "truncated": truncated,
            "diff": diff_text[:30000],
        })
    except httpx.HTTPStatusError as e:
        logger.error("GitHub API error fetching commit diff %s@%s: %s", repo, commit_sha, e)
        return json.dumps({"status": "error", "error": f"GitHub API HTTP {e.response.status_code}"})
    except Exception as e:
        logger.exception("Unexpected error fetching commit diff %s@%s", repo, commit_sha)
        return json.dumps({"status": "error", "error": str(e)})


# ---------------------------------------------------------------------------
# SAST tools — prefer real scanners, fall back to regex
# ---------------------------------------------------------------------------

def scan_code_for_secrets(code_snippet: str, filename: str) -> str:
    """Scan a code snippet for hardcoded secrets.
    Uses Gitleaks (preferred) → regex pattern matching (fallback).
    No credentials required.
    """
    # 1. Gitleaks
    gitleaks_findings = _run_gitleaks(code_snippet, filename)
    if gitleaks_findings is not None:
        if not gitleaks_findings:
            gitleaks_findings = [{"severity": "INFO", "finding": "No secrets detected by gitleaks"}]
        return json.dumps({
            "status": "success",
            "file": filename,
            "analyzer": "gitleaks",
            "findings": gitleaks_findings,
        })

    # 2. Regex fallback
    findings = []
    for i, line in enumerate(code_snippet.splitlines(), 1):
        for pattern, severity, label in SECRET_PATTERNS:
            if pattern.lower() in line.lower() and ("=" in line or ":" in line):
                findings.append({
                    "line": i,
                    "severity": severity,
                    "type": label,
                    "matched_pattern": pattern,
                    "snippet": line.strip()[:80],
                    "source": "regex",
                })

    if not findings:
        findings.append({"severity": "INFO", "finding": "No secret patterns detected", "source": "regex"})

    return json.dumps({
        "status": "success",
        "file": filename,
        "analyzer": "regex",
        "note": "Install gitleaks (https://gitleaks.io) for more accurate secret detection.",
        "findings": findings,
    })


def check_dependency_injection_vulnerabilities(code_snippet: str, language: str) -> str:
    """Analyze a code snippet for injection vulnerabilities (SQL, command, SSRF, XSS, etc.).
    Uses Semgrep (preferred) → regex pattern matching (fallback).
    Returns CWE IDs and remediation hints. No credentials required.
    """
    # 1. Semgrep
    semgrep_findings = _run_semgrep(code_snippet, language, f"snippet.{language}")
    if semgrep_findings is not None:
        if not semgrep_findings:
            semgrep_findings = [{"severity": "INFO", "finding": "No injection vulnerabilities detected by semgrep"}]
        return json.dumps({
            "status": "success",
            "language": language,
            "analyzer": "semgrep",
            "findings": semgrep_findings,
        })

    # 2. Regex fallback
    findings = []
    for i, line in enumerate(code_snippet.splitlines(), 1):
        for pattern, cwe, severity, vuln_type, fix in INJECTION_PATTERNS:
            if pattern in line:
                findings.append({
                    "line": i,
                    "cwe": cwe,
                    "severity": severity,
                    "vulnerability": vuln_type,
                    "snippet": line.strip()[:80],
                    "remediation": fix,
                    "source": "regex",
                })

    if not findings:
        findings.append({"severity": "INFO", "finding": "No injection patterns detected in snippet", "source": "regex"})

    return json.dumps({
        "status": "success",
        "language": language,
        "analyzer": "regex",
        "note": "Install semgrep (https://semgrep.dev) for comprehensive SAST coverage.",
        "findings": findings,
    })
