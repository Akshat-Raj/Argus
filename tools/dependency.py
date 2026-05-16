"""
Dependency security tools (SCA — Software Composition Analysis).

Real integrations:
  - fetch_sbom         → GitHub Dependency Graph SBOM API (requires GITHUB_TOKEN)
  - check_cve_database → OSV API (https://api.osv.dev/v1/query, no auth needed)
  - check_npm_audit    → `npm audit --json` subprocess (requires npm)
  - check_pypi_safety  → `pip-audit --format json` subprocess, then OSV API fallback
  - list_outdated_deps → GitHub SBOM + PyPI/npm registry APIs for latest versions

No mock data is returned. When real data is unavailable a clear error status is given.
"""

import json
import logging
import os
import shutil
import subprocess
import time

import httpx

logger = logging.getLogger(__name__)

_GH_BASE = "https://api.github.com"
_GH_API_VERSION = "2022-11-28"
_OSV_API = "https://api.osv.dev/v1/query"
_MAX_REGISTRY_CHECKS = 30


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
        r = httpx.get(url, headers=_gh_headers(), params=params or None, timeout=30)
        if r.status_code == 429:
            wait = int(r.headers.get("Retry-After", 2 ** (attempt + 1)))
            logger.warning("GitHub rate limited — waiting %ds", wait)
            time.sleep(min(wait, 60))
            continue
        return r
    return r


def _ecosystem_to_osv(ecosystem: str) -> str:
    return {
        "npm": "npm",
        "pypi": "PyPI",
        "pip": "PyPI",
        "python": "PyPI",
        "maven": "Maven",
        "go": "Go",
        "rubygems": "RubyGems",
        "cargo": "crates.io",
        "nuget": "NuGet",
    }.get(ecosystem.lower(), ecosystem)


def _osv_severity(vuln: dict) -> str:
    db = vuln.get("database_specific", {})
    if isinstance(db, dict) and "severity" in db:
        return str(db["severity"]).upper()
    # Parse CVSS vector
    for s in vuln.get("severity", []):
        score_str = s.get("score", "")
        if not score_str or "/" not in score_str:
            continue
        try:
            parts = dict(p.split(":") for p in score_str.split("/")[1:] if ":" in p)
            c, i, a = parts.get("C", "N"), parts.get("I", "N"), parts.get("A", "N")
            if any(x == "H" for x in (c, i, a)):
                return "HIGH"
            if any(x == "L" for x in (c, i, a)):
                return "MEDIUM"
            return "LOW"
        except Exception:
            continue
    return "MEDIUM"


def _osv_fix_version(vuln: dict, package_name: str) -> str | None:
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() == package_name.lower():
            for r in affected.get("ranges", []):
                for event in r.get("events", []):
                    if "fixed" in event:
                        return event["fixed"]
    return None


def _osv_affected_range(vuln: dict, package_name: str) -> str:
    ranges = []
    for affected in vuln.get("affected", []):
        if affected.get("package", {}).get("name", "").lower() == package_name.lower():
            for r in affected.get("ranges", []):
                introduced = fixed = None
                for event in r.get("events", []):
                    if "introduced" in event:
                        introduced = event["introduced"]
                    if "fixed" in event:
                        fixed = event["fixed"]
                if introduced and fixed:
                    ranges.append(f">={introduced},<{fixed}")
                elif introduced:
                    ranges.append(f">={introduced}")
    return ", ".join(ranges) if ranges else "unknown"


def _parse_requirements(path: str) -> list[tuple[str, str]]:
    packages = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#") or line.startswith("-"):
                continue
            for op in ("==", ">=", "<=", "~=", "!=", ">", "<"):
                if op in line:
                    parts = line.split(op, 1)
                    pkg = parts[0].strip().split("[")[0]
                    ver = parts[1].strip().split(",")[0].strip() if op == "==" else ""
                    packages.append((pkg, ver))
                    break
            else:
                packages.append((line.split("[")[0].strip(), ""))
    return packages


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _build_npm_chain(
    pkg_name: str,
    via_names: list[str],
    vuln_dict: dict,
    direct_deps: set[str],
    _visited: set[str] | None = None,
) -> list[str]:
    """Walk npm audit `via` chains upward to produce a root→...→vulnerable path."""
    if _visited is None:
        _visited = set()
    if pkg_name in _visited:
        return [pkg_name]
    _visited.add(pkg_name)

    # If this package is itself a direct dep, it is the root of the chain.
    if pkg_name in direct_deps:
        return [pkg_name]

    # via_names may contain parent package names (strings) — find one that is
    # a direct dep or recurse further up.
    for parent in via_names:
        if parent == pkg_name:
            continue
        parent_entry = vuln_dict.get(parent, {})
        parent_via = parent_entry.get("via", [])
        parent_via_names = [
            x.get("name", x.get("title", str(x))) if isinstance(x, dict) else str(x)
            for x in parent_via
        ]
        ancestor_chain = _build_npm_chain(parent, parent_via_names, vuln_dict, direct_deps, _visited)
        return ancestor_chain + [pkg_name]

    # Could not resolve — return just the package name
    return [pkg_name]


def _pip_chain(package: str, max_depth: int = 6) -> list[str]:
    """Walk `pip show` Required-by links upward to find the direct dependency."""
    chain: list[str] = [package]
    seen: set[str] = {package.lower()}
    current = package
    for _ in range(max_depth):
        try:
            r = subprocess.run(
                ["pip", "show", current],
                capture_output=True, text=True, timeout=10,
            )
        except Exception:
            break
        required_by: list[str] = []
        for line in r.stdout.splitlines():
            if line.startswith("Required-by:"):
                names = line.split(":", 1)[1].strip()
                required_by = [n.strip() for n in names.split(",") if n.strip()]
                break
        if not required_by:
            break
        parent = required_by[0]
        if parent.lower() in seen:
            break
        seen.add(parent.lower())
        chain.insert(0, parent)
        current = parent
    return chain


# ---------------------------------------------------------------------------
# Public tools
# ---------------------------------------------------------------------------

def fetch_sbom(repo: str, ref: str = "main") -> str:
    """Fetch the Software Bill of Materials (SBOM) for a GitHub repository.
    Returns SPDX-formatted JSON with package names, versions, and ecosystems.
    Requires GITHUB_TOKEN with dependency-graph read access.
    """
    if not _gh_token():
        return json.dumps({
            "status": "unconfigured",
            "error": "Set GITHUB_TOKEN with repo scope to fetch the dependency graph SBOM.",
            "packages": [],
        })

    try:
        r = _gh_get(f"/repos/{repo}/dependency-graph/sbom")
        if r.status_code == 404:
            return json.dumps({"status": "error", "error": f"Repo '{repo}' not found or SBOM not available (enable Dependency Graph in repo settings).", "packages": []})
        if r.status_code == 403:
            return json.dumps({"status": "error", "error": "Token lacks access to dependency graph. Ensure the repo has Dependency Graph enabled and the token has 'repo' scope.", "packages": []})
        r.raise_for_status()

        data = r.json()
        sbom = data.get("sbom", data)
        packages = []
        for pkg in sbom.get("packages", []):
            ecosystem = "unknown"
            for ref_entry in pkg.get("externalRefs", []):
                purl = ref_entry.get("referenceLocator", "")
                if purl.startswith("pkg:npm/"):
                    ecosystem = "npm"
                elif purl.startswith("pkg:pypi/"):
                    ecosystem = "pypi"
                elif purl.startswith("pkg:maven/"):
                    ecosystem = "maven"
                elif purl.startswith("pkg:golang/"):
                    ecosystem = "go"
                elif purl.startswith("pkg:cargo/"):
                    ecosystem = "cargo"
            packages.append({
                "name": pkg.get("name", ""),
                "version": pkg.get("versionInfo", ""),
                "ecosystem": ecosystem,
                "license": pkg.get("licenseDeclared", "NOASSERTION"),
            })

        return json.dumps({
            "status": "success",
            "spdxVersion": sbom.get("spdxVersion", "SPDX-2.3"),
            "repo": repo,
            "ref": ref,
            "total": len(packages),
            "packages": packages,
        })
    except httpx.HTTPStatusError as e:
        logger.error("GitHub API error fetching SBOM for %s: %s", repo, e)
        return json.dumps({"status": "error", "error": f"GitHub API HTTP {e.response.status_code}: {e.response.text[:300]}", "packages": []})
    except Exception as e:
        logger.exception("Unexpected error fetching SBOM for %s", repo)
        return json.dumps({"status": "error", "error": str(e), "packages": []})


def check_cve_database(package_name: str, version: str, ecosystem: str) -> str:
    """Query the OSV vulnerability database for known CVEs in a package version.
    Returns vulnerability IDs, CVSS scores, affected ranges, and fix versions.
    No authentication required — uses the public OSV API.
    """
    osv_ecosystem = _ecosystem_to_osv(ecosystem)
    payload: dict = {"package": {"name": package_name, "ecosystem": osv_ecosystem}}
    if version:
        payload["version"] = version

    try:
        r = httpx.post(_OSV_API, json=payload, timeout=15)
        r.raise_for_status()
        data = r.json()
        vulns = []
        for v in data.get("vulns", []):
            cve_ids = [a for a in v.get("aliases", []) if a.startswith("CVE-")]
            vulns.append({
                "id": v.get("id"),
                "cve": cve_ids[0] if cve_ids else None,
                "aliases": v.get("aliases", [])[:5],
                "severity": _osv_severity(v),
                "summary": v.get("summary", "")[:200],
                "affected_range": _osv_affected_range(v, package_name),
                "fix_version": _osv_fix_version(v, package_name),
                "published": v.get("published", ""),
            })
        return json.dumps({
            "status": "success",
            "package": package_name,
            "version": version,
            "ecosystem": ecosystem,
            "vulnerable": len(vulns) > 0,
            "total_vulns": len(vulns),
            "vulnerabilities": vulns,
        })
    except httpx.HTTPStatusError as e:
        logger.error("OSV API error for %s@%s: %s", package_name, version, e)
        return json.dumps({"status": "error", "error": f"OSV API HTTP {e.response.status_code}", "package": package_name, "vulnerabilities": []})
    except httpx.ConnectError as e:
        return json.dumps({"status": "error", "error": f"Cannot reach OSV API: {e}", "vulnerabilities": []})
    except Exception as e:
        logger.exception("Unexpected OSV error for %s@%s", package_name, version)
        return json.dumps({"status": "error", "error": str(e), "vulnerabilities": []})


def check_npm_audit(package_json_path: str) -> str:
    """Run `npm audit --json` on a package.json directory.
    Requires npm in PATH and a valid package.json with a lockfile.
    Returns vulnerability data including dependency chains and direct-dep fix paths.
    """
    import os
    if not os.path.exists(package_json_path):
        return json.dumps({"status": "error", "error": f"Path '{package_json_path}' does not exist.", "vulnerabilities": []})

    target_dir = (
        os.path.dirname(os.path.abspath(package_json_path))
        if os.path.isfile(package_json_path)
        else package_json_path
    )

    if not shutil.which("npm"):
        return json.dumps({
            "status": "unconfigured",
            "error": "npm is not in PATH. Install Node.js to enable npm audit.",
            "manifest": package_json_path,
            "vulnerabilities": [],
        })

    try:
        result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=target_dir,
            capture_output=True,
            text=True,
            timeout=120,
        )
        if not result.stdout.strip():
            stderr = result.stderr.strip()[:300]
            return json.dumps({"status": "error", "error": f"npm audit produced no output. stderr: {stderr}", "vulnerabilities": []})

        data = json.loads(result.stdout)
        vuln_dict = data.get("vulnerabilities", {})

        # Build a map of direct dependencies from package.json for chain resolution
        pkg_json_file = os.path.join(target_dir, "package.json")
        direct_deps: set[str] = set()
        try:
            with open(pkg_json_file, encoding="utf-8") as f:
                pkg_data = json.load(f)
            direct_deps = set(pkg_data.get("dependencies", {}).keys()) | set(pkg_data.get("devDependencies", {}).keys())
        except Exception:
            pass

        vulnerabilities = []
        for pkg_name, v in vuln_dict.items():
            via = v.get("via", [])
            # via entries can be strings (transitive chain links) or dicts (actual advisories)
            via_names = [x.get("name", x.get("title", str(x))) if isinstance(x, dict) else str(x) for x in via]

            # Build dependency chain: walk via chain to find the root direct dep
            chain_parts = _build_npm_chain(pkg_name, via_names, vuln_dict, direct_deps)
            dependency_chain = " → ".join(chain_parts) if chain_parts else pkg_name

            # Extract fix path from fixAvailable
            fix_avail = v.get("fixAvailable")
            fix_via_direct_dep = None
            fix_direct_dep_version = None
            if isinstance(fix_avail, dict):
                fix_via_direct_dep = fix_avail.get("name")
                fix_direct_dep_version = fix_avail.get("version")
                fix_note = (
                    f"upgrade {fix_via_direct_dep} → {fix_direct_dep_version} "
                    f"(pulls in safe transitive)"
                )
            elif fix_avail is True:
                fix_note = "run `npm audit fix`"
            else:
                fix_note = "no automated fix available"

            is_transitive = pkg_name not in direct_deps

            vulnerabilities.append({
                "package": pkg_name,
                "severity": v.get("severity", "").upper(),
                "dependency_chain": dependency_chain,
                "is_transitive": is_transitive,
                "fix_available": bool(fix_avail),
                "fix_note": fix_note,
                "fix_via_direct_dep": fix_via_direct_dep,
                "fix_direct_dep_version": fix_direct_dep_version,
                "range": v.get("range", ""),
                "reachability_check_hint": (
                    f"Use semgrep_scan_with_custom_rule to check if your code calls "
                    f"the vulnerable API in {pkg_name}"
                ),
            })

        metadata = data.get("metadata", {}).get("vulnerabilities", {})
        return json.dumps({
            "status": "success",
            "manifest": package_json_path,
            "total_vulnerabilities": len(vulnerabilities),
            "critical": metadata.get("critical", 0),
            "high": metadata.get("high", 0),
            "moderate": metadata.get("moderate", 0),
            "low": metadata.get("low", 0),
            "vulnerabilities": vulnerabilities,
        })
    except json.JSONDecodeError as e:
        raw = result.stdout[:300] if result.stdout else ""
        logger.error("npm audit JSON parse error: %s. Raw: %s", e, raw)
        return json.dumps({"status": "error", "error": f"Could not parse npm audit output: {e}", "vulnerabilities": []})
    except subprocess.TimeoutExpired:
        return json.dumps({"status": "error", "error": "npm audit timed out after 120 seconds.", "vulnerabilities": []})
    except Exception as e:
        logger.exception("Unexpected error running npm audit for %s", package_json_path)
        return json.dumps({"status": "error", "error": str(e), "vulnerabilities": []})


def check_pypi_safety(requirements_path: str) -> str:
    """Check Python dependencies for known vulnerabilities.
    Uses pip-audit (preferred) → OSV API direct query (fallback).
    """
    if not os.path.exists(requirements_path):
        return json.dumps({"status": "error", "error": f"File '{requirements_path}' does not exist.", "vulnerabilities": []})

    # 1. pip-audit
    if shutil.which("pip-audit"):
        try:
            result = subprocess.run(
                ["pip-audit", "--format", "json", "-r", requirements_path],
                capture_output=True,
                text=True,
                timeout=180,
            )
            if result.stdout.strip():
                data = json.loads(result.stdout)
                vulnerabilities = []
                for dep in data.get("dependencies", []):
                    for v in dep.get("vulns", []):
                        fix_versions = v.get("fix_versions", [])
                        vulnerabilities.append({
                            "package": dep["name"],
                            "installed_version": dep["version"],
                            "cve": v.get("id"),
                            "severity": "HIGH",
                            "advisory": v.get("description", "")[:200],
                            "safe_version": fix_versions[0] if fix_versions else None,
                        })
                return json.dumps({
                    "status": "success",
                    "analyzer": "pip-audit",
                    "requirements_file": requirements_path,
                    "vulnerable_packages": len(vulnerabilities),
                    "vulnerabilities": vulnerabilities,
                })
        except subprocess.TimeoutExpired:
            logger.warning("pip-audit timed out for %s — falling back to OSV API", requirements_path)
        except json.JSONDecodeError as e:
            logger.error("pip-audit JSON parse error: %s", e)
        except Exception as e:
            logger.error("pip-audit error: %s", e)

    # 2. OSV API direct query
    try:
        packages = _parse_requirements(requirements_path)
        all_vulns: list[dict] = []
        for pkg, ver in packages[:_MAX_REGISTRY_CHECKS]:
            if not ver:
                continue
            try:
                r = httpx.post(_OSV_API, json={"package": {"name": pkg, "ecosystem": "PyPI"}, "version": ver}, timeout=10)
                if r.status_code == 200:
                    for v in r.json().get("vulns", []):
                        all_vulns.append({
                            "package": pkg,
                            "installed_version": ver,
                            "cve": next((a for a in v.get("aliases", []) if a.startswith("CVE-")), v.get("id")),
                            "severity": _osv_severity(v),
                            "advisory": v.get("summary", "")[:200],
                            "safe_version": _osv_fix_version(v, pkg),
                        })
            except Exception as e:
                logger.warning("OSV query failed for %s==%s: %s", pkg, ver, e)

        return json.dumps({
            "status": "success",
            "analyzer": "osv-api",
            "requirements_file": requirements_path,
            "packages_checked": len(packages),
            "vulnerable_packages": len(all_vulns),
            "vulnerabilities": all_vulns,
        })
    except Exception as e:
        logger.exception("OSV API fallback failed for %s", requirements_path)
        return json.dumps({"status": "error", "error": str(e), "vulnerabilities": []})


def trace_dependency_chain(package: str, ecosystem: str, manifest_path: str) -> str:
    """Trace the full dependency chain for a vulnerable package and identify the fix path.

    For transitive vulnerabilities this answers three questions the plain CVE listing misses:
    - Chain path  : which direct dep pulls in the vulnerable transitive (A → B → C)
    - Fix path    : which direct dep to upgrade, and to what version, to get a safe transitive
    - Reachability: whether a Semgrep check is feasible and what pattern to look for

    Supports ecosystems: npm, pypi/pip.
    manifest_path: path to package.json (npm) or requirements.txt/pyproject.toml (pip).
    """
    eco = ecosystem.lower().strip()

    if eco == "npm":
        return _trace_npm_chain(package, manifest_path)
    elif eco in ("pypi", "pip", "python"):
        return _trace_pip_chain(package, manifest_path)
    else:
        return json.dumps({
            "status": "unsupported",
            "error": f"Ecosystem '{ecosystem}' is not yet supported. Use 'npm' or 'pypi'.",
        })


def _trace_npm_chain(package: str, manifest_path: str) -> str:
    if not os.path.exists(manifest_path):
        return json.dumps({"status": "error", "error": f"Path '{manifest_path}' does not exist."})

    target_dir = os.path.dirname(os.path.abspath(manifest_path)) if os.path.isfile(manifest_path) else manifest_path

    if not shutil.which("npm"):
        return json.dumps({"status": "unconfigured", "error": "npm is not in PATH."})

    # Load direct deps from package.json
    direct_deps: set[str] = set()
    pkg_json_file = os.path.join(target_dir, "package.json")
    try:
        with open(pkg_json_file, encoding="utf-8") as f:
            pkg_data = json.load(f)
        direct_deps = set(pkg_data.get("dependencies", {}).keys()) | set(pkg_data.get("devDependencies", {}).keys())
        app_name = pkg_data.get("name", "your-app")
    except Exception as e:
        return json.dumps({"status": "error", "error": f"Could not read package.json: {e}"})

    # --- 1. Dependency chain via `npm ls` ---
    chains: list[list[str]] = []
    try:
        ls_result = subprocess.run(
            ["npm", "ls", package, "--json", "--all"],
            cwd=target_dir, capture_output=True, text=True, timeout=60,
        )
        if ls_result.stdout.strip():
            ls_data = json.loads(ls_result.stdout)
            chains = _npm_ls_find_chains(ls_data, package, [app_name])
    except Exception as e:
        logger.warning("npm ls failed for %s: %s", package, e)

    # --- 2. Fix path via `npm audit --json` ---
    fix_via_direct_dep = None
    fix_direct_dep_version = None
    fix_note = "unknown — run `npm audit` for details"
    severity = "UNKNOWN"
    cve_ids: list[str] = []
    try:
        audit_result = subprocess.run(
            ["npm", "audit", "--json"],
            cwd=target_dir, capture_output=True, text=True, timeout=120,
        )
        if audit_result.stdout.strip():
            audit_data = json.loads(audit_result.stdout)
            vuln_entry = audit_data.get("vulnerabilities", {}).get(package, {})
            fix_avail = vuln_entry.get("fixAvailable")
            severity = vuln_entry.get("severity", "unknown").upper()
            # Extract CVE IDs from via advisory entries
            for via in vuln_entry.get("via", []):
                if isinstance(via, dict):
                    for alias in via.get("cves", []):
                        if alias not in cve_ids:
                            cve_ids.append(alias)
            if isinstance(fix_avail, dict):
                fix_via_direct_dep = fix_avail.get("name")
                fix_direct_dep_version = fix_avail.get("version")
                fix_note = (
                    f"upgrade {fix_via_direct_dep} to {fix_direct_dep_version} "
                    f"(pulls in a safe version of {package})"
                )
            elif fix_avail is True:
                fix_note = "run `npm audit fix` (semver-compatible fix available)"
            else:
                fix_note = "no automated fix — check for manual workaround or pin transitive"
    except Exception as e:
        logger.warning("npm audit failed during chain trace for %s: %s", package, e)

    # --- 3. Registry lookup: minimum safe direct-dep version (if fix_via known) ---
    min_safe_version_note = None
    if fix_via_direct_dep and fix_direct_dep_version:
        min_safe_version_note = (
            f"Verified via npm audit: {fix_via_direct_dep}@{fix_direct_dep_version} "
            f"is the minimum version that ships a safe {package}."
        )

    is_transitive = package not in direct_deps
    chain_strs = [" → ".join(c) for c in chains[:5]]  # cap at 5 paths

    return json.dumps({
        "status": "success",
        "package": package,
        "ecosystem": "npm",
        "severity": severity,
        "cve_ids": cve_ids,
        "is_transitive": is_transitive,
        "dependency_chains": chain_strs or ([package] if not is_transitive else ["chain not resolved — run npm ls manually"]),
        "fix_via_direct_dep": fix_via_direct_dep,
        "fix_direct_dep_version": fix_direct_dep_version,
        "fix_note": fix_note,
        "min_safe_version_note": min_safe_version_note,
        "cannot_fix_directly": is_transitive and fix_via_direct_dep is not None,
        "reachability": {
            "feasible": True,
            "tool": "semgrep_scan_with_custom_rule",
            "hint": (
                f"Run a Semgrep rule to find calls to the vulnerable API in {package}. "
                f"If 0 call sites are found in application code, severity can be downgraded "
                f"(unreachable transitive). If found, severity stays at {severity} and call sites should be shown."
            ),
        },
    })


def _npm_ls_find_chains(node: dict, target: str, path: list[str]) -> list[list[str]]:
    """Recursively walk an `npm ls --json --all` tree to find all paths to `target`."""
    chains: list[list[str]] = []
    for name, child in node.get("dependencies", {}).items():
        current_path = path + [name]
        if name.lower() == target.lower():
            chains.append(current_path)
        else:
            chains.extend(_npm_ls_find_chains(child, target, current_path))
    return chains


def _trace_pip_chain(package: str, manifest_path: str) -> str:
    if not shutil.which("pip"):
        return json.dumps({"status": "unconfigured", "error": "pip is not in PATH."})

    # Walk Required-by chain upward
    chain = _pip_chain(package)
    is_transitive = len(chain) > 1

    # OSV lookup for fix version
    fix_version: str | None = None
    severity = "UNKNOWN"
    cve_ids: list[str] = []
    try:
        # Get installed version
        show_result = subprocess.run(
            ["pip", "show", package], capture_output=True, text=True, timeout=10,
        )
        installed_version = ""
        for line in show_result.stdout.splitlines():
            if line.startswith("Version:"):
                installed_version = line.split(":", 1)[1].strip()
                break

        if installed_version:
            r = httpx.post(
                _OSV_API,
                json={"package": {"name": package, "ecosystem": "PyPI"}, "version": installed_version},
                timeout=10,
            )
            if r.status_code == 200:
                for v in r.json().get("vulns", []):
                    cve_ids += [a for a in v.get("aliases", []) if a.startswith("CVE-")]
                    severity = _osv_severity(v)
                    fv = _osv_fix_version(v, package)
                    if fv:
                        fix_version = fv
    except Exception as e:
        logger.warning("OSV lookup failed during pip chain trace for %s: %s", package, e)

    direct_dep = chain[0] if chain else package
    fix_note: str
    if is_transitive and fix_version:
        fix_note = (
            f"upgrade {direct_dep} to a version that depends on {package}>={fix_version}. "
            f"You cannot fix this by pinning {package} directly in requirements.txt "
            f"if it is only a transitive dep."
        )
    elif fix_version:
        fix_note = f"upgrade {package} to >={fix_version}"
    else:
        fix_note = "no fix version identified — check OSV or PyPI advisories"

    return json.dumps({
        "status": "success",
        "package": package,
        "ecosystem": "pypi",
        "severity": severity,
        "cve_ids": list(dict.fromkeys(cve_ids)),
        "is_transitive": is_transitive,
        "dependency_chain": " → ".join(chain),
        "direct_dep": direct_dep,
        "fix_version_for_package": fix_version,
        "fix_note": fix_note,
        "cannot_fix_directly": is_transitive,
        "reachability": {
            "feasible": True,
            "tool": "semgrep_scan_with_custom_rule",
            "hint": (
                f"Run a Semgrep rule to check if your code imports or calls the vulnerable "
                f"function in {package}. If 0 call sites found, severity can be downgraded "
                f"(unreachable transitive). If found, severity stays at {severity}."
            ),
        },
    })


def list_outdated_dependencies(repo: str, ecosystem: str) -> str:
    """List dependencies that are out of date by querying the GitHub SBOM and package registries.
    Requires GITHUB_TOKEN. Queries PyPI/npm for latest versions.
    """
    if not _gh_token():
        return json.dumps({
            "status": "unconfigured",
            "error": "Set GITHUB_TOKEN to fetch the SBOM and compare against registry versions.",
            "packages": [],
        })

    # Fetch SBOM
    packages: list[dict] = []
    try:
        r = _gh_get(f"/repos/{repo}/dependency-graph/sbom")
        if r.status_code not in (200,):
            return json.dumps({"status": "error", "error": f"Could not fetch SBOM for {repo}: HTTP {r.status_code}", "packages": []})
        sbom = r.json().get("sbom", r.json())
        for pkg in sbom.get("packages", []):
            pkg_ecosystem = "unknown"
            for ref_entry in pkg.get("externalRefs", []):
                purl = ref_entry.get("referenceLocator", "")
                if purl.startswith("pkg:npm/"):
                    pkg_ecosystem = "npm"
                elif purl.startswith("pkg:pypi/"):
                    pkg_ecosystem = "pypi"
            if not ecosystem or ecosystem.lower() in (pkg_ecosystem, "all"):
                name = pkg.get("name", "")
                current = pkg.get("versionInfo", "")
                if name and current:
                    packages.append({"name": name, "current": current, "ecosystem": pkg_ecosystem})
    except Exception as e:
        logger.error("SBOM fetch error for %s: %s", repo, e)
        return json.dumps({"status": "error", "error": str(e), "packages": []})

    if not packages:
        return json.dumps({"status": "success", "repo": repo, "ecosystem": ecosystem, "note": "No packages found in SBOM for this ecosystem.", "packages": []})

    # Check registry for latest versions
    outdated: list[dict] = []
    checked = 0
    for pkg in packages[:_MAX_REGISTRY_CHECKS]:
        name, current, eco = pkg["name"], pkg["current"], pkg["ecosystem"]
        try:
            latest = None
            if eco == "pypi":
                r = httpx.get(f"https://pypi.org/pypi/{name}/json", timeout=10)
                if r.status_code == 200:
                    latest = r.json().get("info", {}).get("version")
            elif eco == "npm":
                r = httpx.get(f"https://registry.npmjs.org/{name}/latest", timeout=10)
                if r.status_code == 200:
                    latest = r.json().get("version")

            if latest and latest != current:
                try:
                    cur_major = int(current.lstrip("v").split(".")[0])
                    lat_major = int(latest.lstrip("v").split(".")[0])
                    behind = lat_major - cur_major
                except ValueError:
                    behind = 0
                risk = "CRITICAL" if behind >= 3 else "HIGH" if behind >= 1 else "LOW"
                outdated.append({
                    "package": name,
                    "current": current,
                    "latest": latest,
                    "major_versions_behind": max(behind, 0),
                    "ecosystem": eco,
                    "risk": risk,
                })
            checked += 1
        except Exception as e:
            logger.warning("Registry check failed for %s: %s", name, e)

    return json.dumps({
        "status": "success",
        "repo": repo,
        "ecosystem": ecosystem,
        "packages_checked": checked,
        "outdated_count": len(outdated),
        "packages": sorted(outdated, key=lambda x: x["major_versions_behind"], reverse=True),
    })
