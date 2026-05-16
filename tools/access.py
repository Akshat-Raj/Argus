"""
Access control audit tools.

Real integrations:
  - GitHub org MFA status: GITHUB_TOKEN with read:org or admin:org scope
  - GitHub org members and roles: GITHUB_TOKEN
  - Cloud IAM (AWS/GCP/Azure): set IAM_API_URL for a REST-compatible IAM endpoint,
    or configure the custom-security MCP server via SECURITY_MCP_URL.
  - Policy document review: works on any policy string (no credentials needed).
"""

import json
import logging
import os
import time

import httpx

logger = logging.getLogger(__name__)

_GH_BASE = "https://api.github.com"
_GH_API_VERSION = "2022-11-28"


def _gh_token() -> str | None:
    for key in ("GITHUB_PERSONAL_ACCESS_TOKEN", "GITHUB_TOKEN", "GITHUB_PAT"):
        val = os.environ.get(key, "").strip()
        if val:
            return val
    return None


def _gh_headers() -> dict:
    headers = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": _GH_API_VERSION}
    token = _gh_token()
    if token:
        headers["Authorization"] = f"Bearer {token}"
    return headers


def _gh_get(path: str, **params) -> httpx.Response:
    url = f"{_GH_BASE}{path}"
    for attempt in range(3):
        r = httpx.get(url, headers=_gh_headers(), params=params or None, timeout=20)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", 2 ** (attempt + 1)))
            logger.warning("GitHub rate limited — waiting %ds", wait)
            time.sleep(min(wait, 60))
            continue
        return r
    return r


def _iam_api_url() -> str | None:
    return os.environ.get("IAM_API_URL", "").strip() or None


def list_iam_policies(scope: str) -> str:
    """List IAM policies for a given scope (org, project, or service).
    Calls IAM_API_URL if configured, or the GitHub org roles API for GitHub scopes.
    Set IAM_API_URL or SECURITY_MCP_URL for full cloud IAM integration.
    """
    # Try GitHub org roles if scope looks like a GitHub org
    token = _gh_token()
    if token:
        try:
            r = _gh_get(f"/orgs/{scope}/teams", per_page=50)
            if r.status_code == 200:
                teams = r.json()
                policies = []
                for team in teams:
                    policies.append({
                        "name": team.get("name"),
                        "scope": scope,
                        "slug": team.get("slug"),
                        "permission": team.get("permission"),
                        "members_count": team.get("members_count", 0),
                        "privacy": team.get("privacy"),
                        "source": "github_org_teams",
                    })
                return json.dumps({"status": "success", "scope": scope, "source": "github_org_teams", "policies": policies, "total": len(policies)})
        except Exception as e:
            logger.warning("GitHub org teams lookup failed for %s: %s", scope, e)

    # Try generic IAM REST API
    iam_url = _iam_api_url()
    if iam_url:
        try:
            r = httpx.get(f"{iam_url}/policies", params={"scope": scope}, timeout=15)
            r.raise_for_status()
            data = r.json()
            return json.dumps({"status": "success", "scope": scope, "source": "iam_api", **data})
        except Exception as e:
            logger.error("IAM API error for scope %s: %s", scope, e)
            return json.dumps({"status": "error", "error": str(e), "scope": scope, "policies": []})

    return json.dumps({
        "status": "unconfigured",
        "scope": scope,
        "policies": [],
        "error": (
            "No IAM integration configured. Options:\n"
            "  1. Set GITHUB_TOKEN to audit GitHub org teams and roles.\n"
            "  2. Set IAM_API_URL pointing to a REST-compatible IAM endpoint.\n"
            "  3. Configure SECURITY_MCP_URL for a custom security MCP server."
        ),
    })


def audit_overprivileged_roles(scope: str) -> str:
    """Identify roles or teams with excessive permissions (wildcards, admin grants).
    Works with GitHub org teams when GITHUB_TOKEN is set.
    """
    token = _gh_token()
    if token:
        try:
            r = _gh_get(f"/orgs/{scope}/teams", per_page=100)
            if r.status_code == 200:
                teams = r.json()
                findings = []
                for team in teams:
                    perm = team.get("permission", "")
                    if perm == "admin":
                        findings.append({
                            "role": team.get("name"),
                            "slug": team.get("slug"),
                            "permission": perm,
                            "members_count": team.get("members_count", 0),
                            "severity": "CRITICAL",
                            "finding": f"Team '{team.get('name')}' has admin permission across all repos in org",
                            "recommendation": "Restrict to 'maintain' or 'write' and limit admin to a dedicated ops team",
                        })
                    elif perm in ("maintain", "write"):
                        findings.append({
                            "role": team.get("name"),
                            "slug": team.get("slug"),
                            "permission": perm,
                            "members_count": team.get("members_count", 0),
                            "severity": "MEDIUM",
                            "finding": f"Team '{team.get('name')}' has broad '{perm}' permission",
                            "recommendation": "Review member list and verify this is least-privilege",
                        })
                return json.dumps({"status": "success", "scope": scope, "source": "github_org_teams", "findings": findings, "total_flagged": len(findings)})
        except Exception as e:
            logger.warning("GitHub overprivileged roles check failed for %s: %s", scope, e)

    iam_url = _iam_api_url()
    if iam_url:
        try:
            r = httpx.get(f"{iam_url}/audit/overprivileged", params={"scope": scope}, timeout=15)
            r.raise_for_status()
            return json.dumps({"status": "success", "scope": scope, "source": "iam_api", **r.json()})
        except Exception as e:
            return json.dumps({"status": "error", "error": str(e), "findings": []})

    return json.dumps({
        "status": "unconfigured",
        "scope": scope,
        "findings": [],
        "error": "Set GITHUB_TOKEN (for GitHub org auditing) or IAM_API_URL (for cloud IAM) to enable overprivileged role detection.",
    })


def check_mfa_enforcement(org: str) -> str:
    """Check MFA enforcement status for all members of a GitHub organization.
    Requires GITHUB_TOKEN with read:org scope (or admin:org to list 2FA-disabled members).
    """
    token = _gh_token()
    if not token:
        return json.dumps({
            "status": "unconfigured",
            "org": org,
            "error": "Set GITHUB_TOKEN with read:org or admin:org scope to check MFA enforcement.",
        })

    try:
        # Members without 2FA — requires admin:org; may return 404 if insufficient scope
        r_no_mfa = _gh_get(f"/orgs/{org}/members", filter="2fa_disabled", per_page=100)

        if r_no_mfa.status_code == 200:
            no_mfa_members = [{"login": m["login"], "html_url": m["html_url"], "mfa_enabled": False} for m in r_no_mfa.json()]
        elif r_no_mfa.status_code in (403, 404):
            logger.warning("Insufficient scope to list 2FA-disabled members for %s — need admin:org", org)
            no_mfa_members = None
        else:
            r_no_mfa.raise_for_status()
            no_mfa_members = []

        # All members
        r_all = _gh_get(f"/orgs/{org}/members", per_page=100)
        if r_all.status_code == 404:
            return json.dumps({"status": "error", "org": org, "error": f"Organization '{org}' not found or token lacks org access."})
        r_all.raise_for_status()
        all_members = r_all.json()

        if no_mfa_members is not None:
            no_mfa_logins = {m["login"] for m in no_mfa_members}
            users = [
                {"login": m["login"], "mfa_enabled": m["login"] not in no_mfa_logins, "html_url": m["html_url"]}
                for m in all_members
            ]
            return json.dumps({
                "status": "success",
                "org": org,
                "total_members": len(all_members),
                "mfa_disabled_count": len(no_mfa_members),
                "mfa_disabled_members": no_mfa_members,
                "users": users,
            })
        else:
            # Could only get total members, not MFA status
            return json.dumps({
                "status": "partial",
                "org": org,
                "total_members": len(all_members),
                "members": [{"login": m["login"], "html_url": m["html_url"]} for m in all_members],
                "note": "MFA status unavailable — token needs admin:org scope to list 2FA-disabled members.",
            })

    except httpx.HTTPStatusError as e:
        logger.error("GitHub API error checking MFA for org %s: %s", org, e)
        return json.dumps({"status": "error", "org": org, "error": f"GitHub API HTTP {e.response.status_code}: {e.response.text[:300]}"})
    except Exception as e:
        logger.exception("Unexpected error checking MFA for org %s", org)
        return json.dumps({"status": "error", "org": org, "error": str(e)})


def list_service_account_keys(project: str) -> str:
    """List service account / deploy keys and flag stale or over-permissive ones.
    For GitHub: lists deploy keys across repos in the org.
    For cloud providers: set IAM_API_URL or SECURITY_MCP_URL.
    """
    token = _gh_token()
    if token:
        try:
            # List repos then their deploy keys
            r_repos = _gh_get(f"/orgs/{project}/repos", per_page=50, type="all")
            if r_repos.status_code == 200:
                repos = r_repos.json()
                all_keys: list[dict] = []
                for repo in repos[:20]:  # cap to avoid rate limits
                    repo_name = repo.get("full_name", "")
                    r_keys = _gh_get(f"/repos/{repo_name}/keys")
                    if r_keys.status_code == 200:
                        for key in r_keys.json():
                            all_keys.append({
                                "repo": repo_name,
                                "key_id": key.get("id"),
                                "title": key.get("title"),
                                "read_only": key.get("read_only"),
                                "created_at": key.get("created_at"),
                                "verified": key.get("verified"),
                                "severity": "LOW" if key.get("read_only") else "HIGH",
                                "risk_note": "Read-only deploy key" if key.get("read_only") else "Write-access deploy key — can push code",
                            })
                return json.dumps({
                    "status": "success",
                    "project": project,
                    "source": "github_deploy_keys",
                    "total_keys": len(all_keys),
                    "write_access_keys": [k for k in all_keys if not k["read_only"]],
                    "keys": all_keys,
                })
        except Exception as e:
            logger.warning("GitHub deploy keys lookup failed for %s: %s", project, e)

    iam_url = _iam_api_url()
    if iam_url:
        try:
            r = httpx.get(f"{iam_url}/service-accounts/keys", params={"project": project}, timeout=15)
            r.raise_for_status()
            return json.dumps({"status": "success", "source": "iam_api", **r.json()})
        except Exception as e:
            return json.dumps({"status": "error", "error": str(e), "keys": []})

    return json.dumps({
        "status": "unconfigured",
        "project": project,
        "keys": [],
        "error": (
            "Set GITHUB_TOKEN to audit GitHub deploy keys, or set IAM_API_URL "
            "for cloud service account key auditing (GCP, AWS, Azure)."
        ),
    })


def review_access_policy(policy_name: str, policy_document: str) -> str:
    """Review an access policy document string for security violations.
    Checks for wildcard permissions, missing conditions, and over-broad principals.
    Works on any policy document — no credentials required.
    """
    findings = []

    if "*" in policy_document:
        count = policy_document.count("*")
        findings.append({
            "severity": "CRITICAL",
            "finding": f"Wildcard (*) permission detected ({count} occurrence(s))",
            "recommendation": "Replace wildcards with explicit resource ARNs and action lists.",
        })

    if '"Principal": "*"' in policy_document or "'Principal': '*'" in policy_document:
        findings.append({
            "severity": "CRITICAL",
            "finding": "Policy grants access to ANY principal (*)",
            "recommendation": "Restrict Principal to specific accounts, roles, or services.",
        })

    if "Condition" not in policy_document and "condition" not in policy_document:
        findings.append({
            "severity": "MEDIUM",
            "finding": "No conditions on policy statements",
            "recommendation": "Add conditions such as MFA requirement: aws:MultiFactorAuthPresent: 'true'",
        })

    lower = policy_document.lower()
    if any(kw in lower for kw in ("delete", "destroy", "terminate", "drop")):
        findings.append({
            "severity": "HIGH",
            "finding": "Policy includes destructive actions (delete/destroy/terminate/drop)",
            "recommendation": "Verify these destructive permissions are intentional; apply break-glass procedures.",
        })

    if '"Effect": "Allow"' in policy_document and '"NotResource"' in policy_document:
        findings.append({
            "severity": "HIGH",
            "finding": "Policy uses NotResource with Allow — grants access to everything EXCEPT listed resources",
            "recommendation": "Replace NotResource/Allow with explicit Resource/Allow list.",
        })

    if not findings:
        findings.append({
            "severity": "INFO",
            "finding": "No obvious violations detected by automated review",
            "recommendation": "Manual peer review recommended for all IAM policy changes.",
        })

    return json.dumps({
        "status": "success",
        "policy": policy_name,
        "total_findings": len(findings),
        "findings": findings,
    })
