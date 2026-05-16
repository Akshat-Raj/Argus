"""
CI/CD monitoring tools.

Real integrations:
  - GitHub Actions: GITHUB_PERSONAL_ACCESS_TOKEN / GITHUB_TOKEN / GITHUB_PAT
  - Jenkins: JENKINS_URL + JENKINS_USER + JENKINS_TOKEN
    OR set JENKINS_MCP_URL for an HTTP MCP server endpoint.
"""

import base64
import io
import json
import logging
import os
import time
import zipfile

import httpx

from tools.patterns import SECRET_PATTERNS

logger = logging.getLogger(__name__)

_GH_API_VERSION = "2022-11-28"
_GH_BASE = "https://api.github.com"


# ---------------------------------------------------------------------------
# Auth helpers
# ---------------------------------------------------------------------------

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


def _jenkins_base_and_headers() -> tuple[str, dict] | None:
    base = os.environ.get("JENKINS_URL", "").rstrip("/")
    user = os.environ.get("JENKINS_USER", "").strip()
    token = os.environ.get("JENKINS_TOKEN", "").strip()
    if base and user and token:
        encoded = base64.b64encode(f"{user}:{token}".encode()).decode()
        return base, {"Authorization": f"Basic {encoded}"}
    return None


# ---------------------------------------------------------------------------
# Retry-aware GitHub GET
# ---------------------------------------------------------------------------

def _gh_get(path: str, **params) -> httpx.Response:
    url = f"{_GH_BASE}{path}"
    for attempt in range(3):
        r = httpx.get(url, headers=_gh_headers(), params=params or None, timeout=30)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", 2 ** (attempt + 1)))
            logger.warning("GitHub rate limited — waiting %ds (attempt %d)", wait, attempt + 1)
            time.sleep(min(wait, 60))
            continue
        return r
    return r  # return final response even if still 429


# ---------------------------------------------------------------------------
# GitHub Actions tools
# ---------------------------------------------------------------------------

def list_github_workflow_runs(repo: str, workflow_id: str, limit: int = 10) -> str:
    """List recent GitHub Actions workflow runs for a repo.
    Returns run IDs, status, conclusion, actor, and timestamps.
    Requires GITHUB_TOKEN.
    """
    if not _gh_token():
        return json.dumps({
            "status": "unconfigured",
            "error": "Set GITHUB_PERSONAL_ACCESS_TOKEN, GITHUB_TOKEN, or GITHUB_PAT to enable GitHub Actions monitoring.",
            "workflow_runs": [],
        })

    try:
        r = _gh_get(f"/repos/{repo}/actions/runs", per_page=min(limit * 3, 100))
        r.raise_for_status()
        data = r.json()
        runs = data.get("workflow_runs", [])

        if workflow_id:
            filtered = [
                run for run in runs
                if str(run.get("workflow_id")) == str(workflow_id)
                or run.get("name") == workflow_id
                or run.get("path", "").endswith(workflow_id)
            ]
            if filtered:
                runs = filtered

        runs = runs[:limit]
        return json.dumps({
            "status": "success",
            "repo": repo,
            "total_count": len(runs),
            "workflow_runs": [
                {
                    "id": run["id"],
                    "name": run.get("name"),
                    "status": run.get("status"),
                    "conclusion": run.get("conclusion"),
                    "created_at": run.get("created_at"),
                    "updated_at": run.get("updated_at"),
                    "actor": run.get("actor", {}).get("login"),
                    "head_branch": run.get("head_branch"),
                    "html_url": run.get("html_url"),
                }
                for run in runs
            ],
        })
    except httpx.HTTPStatusError as e:
        logger.error("GitHub API error listing runs for %s: %s", repo, e)
        return json.dumps({
            "status": "error",
            "error": f"GitHub API returned HTTP {e.response.status_code}: {e.response.text[:300]}",
            "workflow_runs": [],
        })
    except Exception as e:
        logger.exception("Unexpected error listing runs for %s", repo)
        return json.dumps({"status": "error", "error": str(e), "workflow_runs": []})


def get_github_workflow_run_logs(repo: str, run_id: int) -> str:
    """Download and return logs for a GitHub Actions workflow run.
    Fetches the log ZIP archive and extracts text, capped at 20 KB.
    Requires GITHUB_TOKEN.
    """
    if not _gh_token():
        return json.dumps({
            "status": "unconfigured",
            "error": "Set GITHUB_TOKEN to fetch workflow run logs.",
        })

    try:
        r = httpx.get(
            f"{_GH_BASE}/repos/{repo}/actions/runs/{run_id}/logs",
            headers=_gh_headers(),
            timeout=60,
            follow_redirects=True,
        )
        if r.status_code == 404:
            return json.dumps({"status": "error", "error": f"Run {run_id} not found or logs have expired (GitHub keeps logs for 90 days)."})
        r.raise_for_status()

        if not r.content:
            return json.dumps({"status": "error", "error": "Empty log archive returned by GitHub."})

        parts: list[str] = []
        truncated = False
        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            for name in sorted(zf.namelist())[:10]:
                with zf.open(name) as f:
                    text = f.read().decode("utf-8", errors="replace")
                    if len(text) > 5000:
                        truncated = True
                        text = text[:5000] + f"\n[...truncated {len(text) - 5000} additional bytes]"
                    parts.append(f"=== {name} ===\n{text}")

        logs = "\n".join(parts)[:20000]
        return json.dumps({
            "status": "success",
            "repo": repo,
            "run_id": run_id,
            "truncated": truncated,
            "logs": logs,
        })

    except zipfile.BadZipFile:
        return json.dumps({"status": "error", "error": "Could not parse log archive (not a valid ZIP file)."})
    except httpx.HTTPStatusError as e:
        logger.error("GitHub API error fetching logs for %s run %d: %s", repo, run_id, e)
        return json.dumps({"status": "error", "error": f"GitHub API HTTP {e.response.status_code}: {e.response.text[:300]}"})
    except Exception as e:
        logger.exception("Unexpected error fetching logs for %s run %d", repo, run_id)
        return json.dumps({"status": "error", "error": str(e)})


def check_github_actions_secrets_exposure(repo: str, run_id: int) -> str:
    """Download workflow run logs and scan every line for credential patterns.
    Returns all matching lines with pattern type and severity.
    Requires GITHUB_TOKEN.
    """
    if not _gh_token():
        return json.dumps({
            "status": "unconfigured",
            "error": "Set GITHUB_TOKEN to scan CI logs for secret exposure.",
            "findings": [],
        })

    try:
        r = httpx.get(
            f"{_GH_BASE}/repos/{repo}/actions/runs/{run_id}/logs",
            headers=_gh_headers(),
            timeout=60,
            follow_redirects=True,
        )
        if r.status_code == 404:
            return json.dumps({"status": "error", "error": f"Run {run_id} not found or logs expired.", "findings": []})
        r.raise_for_status()

        findings: list[dict] = []
        with zipfile.ZipFile(io.BytesIO(r.content)) as zf:
            for name in zf.namelist():
                with zf.open(name) as f:
                    for lineno, raw in enumerate(f, 1):
                        line = raw.decode("utf-8", errors="replace")
                        for pattern, severity, label in SECRET_PATTERNS:
                            if pattern in line:
                                findings.append({
                                    "log_file": name,
                                    "line": lineno,
                                    "pattern": pattern,
                                    "severity": severity,
                                    "note": label,
                                    "snippet": line.strip()[:120],
                                })

        return json.dumps({
            "status": "success",
            "repo": repo,
            "run_id": run_id,
            "total_findings": len(findings),
            "findings": findings,
        })

    except zipfile.BadZipFile:
        return json.dumps({"status": "error", "error": "Could not parse log archive.", "findings": []})
    except httpx.HTTPStatusError as e:
        logger.error("GitHub API error scanning secrets for %s run %d: %s", repo, run_id, e)
        return json.dumps({"status": "error", "error": f"GitHub API HTTP {e.response.status_code}", "findings": []})
    except Exception as e:
        logger.exception("Unexpected error scanning secrets for %s run %d", repo, run_id)
        return json.dumps({"status": "error", "error": str(e), "findings": []})


# ---------------------------------------------------------------------------
# Jenkins tools
# ---------------------------------------------------------------------------

def list_jenkins_pipeline_builds(job_name: str, limit: int = 5) -> str:
    """List recent Jenkins pipeline builds for a job.
    Requires JENKINS_URL, JENKINS_USER, and JENKINS_TOKEN environment variables.
    """
    client = _jenkins_base_and_headers()
    if not client:
        return json.dumps({
            "status": "unconfigured",
            "error": "Set JENKINS_URL, JENKINS_USER, and JENKINS_TOKEN to enable Jenkins monitoring.",
            "builds": [],
        })

    base, headers = client
    try:
        r = httpx.get(
            f"{base}/job/{job_name}/api/json",
            headers={**headers, "Accept": "application/json"},
            params={"tree": f"builds[number,result,duration,timestamp,causes[shortDescription]]{{,{limit}}}"},
            timeout=20,
        )
        r.raise_for_status()
        data = r.json()
        builds = [
            {
                "number": b.get("number"),
                "result": b.get("result"),
                "duration_ms": b.get("duration"),
                "timestamp_ms": b.get("timestamp"),
                "causes": [c.get("shortDescription", "") for c in b.get("causes", [])],
            }
            for b in data.get("builds", [])[:limit]
        ]
        return json.dumps({"status": "success", "job": job_name, "builds": builds})
    except httpx.HTTPStatusError as e:
        logger.error("Jenkins API error for job %s: %s", job_name, e)
        return json.dumps({"status": "error", "error": f"Jenkins returned HTTP {e.response.status_code}", "builds": []})
    except httpx.ConnectError as e:
        return json.dumps({"status": "error", "error": f"Cannot connect to Jenkins at {base}: {e}", "builds": []})
    except Exception as e:
        logger.exception("Unexpected error listing Jenkins builds for %s", job_name)
        return json.dumps({"status": "error", "error": str(e), "builds": []})


def get_jenkins_build_console_output(job_name: str, build_number: int) -> str:
    """Retrieve console output for a Jenkins build.
    Requires JENKINS_URL, JENKINS_USER, and JENKINS_TOKEN environment variables.
    """
    client = _jenkins_base_and_headers()
    if not client:
        return json.dumps({
            "status": "unconfigured",
            "error": "Set JENKINS_URL, JENKINS_USER, and JENKINS_TOKEN to fetch Jenkins build logs.",
        })

    base, headers = client
    try:
        r = httpx.get(
            f"{base}/job/{job_name}/{build_number}/consoleText",
            headers=headers,
            timeout=30,
        )
        r.raise_for_status()
        text = r.text
        truncated = len(text) > 20000
        return json.dumps({
            "status": "success",
            "job": job_name,
            "build": build_number,
            "truncated": truncated,
            "console_output": text[:20000],
        })
    except httpx.HTTPStatusError as e:
        return json.dumps({"status": "error", "error": f"Jenkins returned HTTP {e.response.status_code}", "job": job_name, "build": build_number})
    except httpx.ConnectError as e:
        return json.dumps({"status": "error", "error": f"Cannot connect to Jenkins: {e}"})
    except Exception as e:
        logger.exception("Unexpected error fetching Jenkins console for %s #%d", job_name, build_number)
        return json.dumps({"status": "error", "error": str(e)})
