"""
Live package registry tools for supply chain analysis.

The agent calls these to get real metadata and actual package source files,
then reasons about what it finds rather than matching against hardcoded lists.

Tools:
  list_project_manifests    — find all manifest files under a project directory (pure Python, no MCP)
  fetch_manifest_packages   — parse requirements.txt / package.json → package list
  query_pypi_metadata       — PyPI JSON API + pypistats download counts
  query_npm_metadata        — npm registry metadata + install scripts
  fetch_package_source_files— download the tarball, return key source files for code analysis
"""

import io
import json
import logging
import os
import re
import tarfile
import time
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_PYPI_BASE = "https://pypi.org/pypi"
_PYPISTATS_BASE = "https://pypistats.org/api/packages"
_NPM_BASE = "https://registry.npmjs.org"
_NPM_DOWNLOADS = "https://api.npmjs.org/downloads/point/last-month"

# Files we care about when inspecting a downloaded package
_PYPI_FILES_OF_INTEREST = {
    "setup.py", "setup.cfg", "pyproject.toml",
    "__init__.py", "METADATA", "PKG-INFO",
}
_NPM_FILES_OF_INTEREST = {
    "package.json", "index.js", "index.ts", "main.js",
    ".npmrc", "binding.gyp",
}

# Hard cap on tarball size we'll fetch (5 MB)
_MAX_TARBALL_BYTES = 5 * 1024 * 1024
# Hard cap on individual file content returned
_MAX_FILE_BYTES = 32 * 1024


def _get(url: str, timeout: int = 15, **kwargs) -> httpx.Response:
    for attempt in range(3):
        try:
            r = httpx.get(url, timeout=timeout, follow_redirects=True, **kwargs)
            if r.status_code == 429:
                time.sleep(2 ** attempt)
                continue
            return r
        except httpx.TransportError as exc:
            if attempt == 2:
                raise
            logger.warning("GET %s failed (attempt %d): %s", url, attempt + 1, exc)
            time.sleep(1)
    raise RuntimeError(f"GET {url} failed after 3 attempts")


def _days_ago(iso: str) -> int | None:
    """Return how many days ago an ISO-8601 timestamp was, or None."""
    try:
        dt = datetime.fromisoformat(iso.rstrip("Z").split("+")[0]).replace(tzinfo=timezone.utc)
        return (datetime.now(timezone.utc) - dt).days
    except Exception:
        return None


# ─────────────────────────────────────────────────────────────────────────────
# 0. list_project_manifests  (pure Python — no MCP, no shell)
# ─────────────────────────────────────────────────────────────────────────────

_MANIFEST_NAMES = {
    "requirements.txt", "requirements-dev.txt", "requirements-test.txt",
    "package.json", "pyproject.toml",
}


def list_project_manifests(project_path: str) -> str:
    """Walk a local project directory and return paths to all package manifest files.

    Uses Python's os.walk — does NOT go through MCP filesystem tools or shell commands.
    Skips .venv, node_modules, .git. Returns absolute paths.

    Pass each returned path directly to fetch_manifest_packages.
    """
    project_path = os.path.abspath(project_path)
    if not os.path.isdir(project_path):
        return json.dumps({"status": "error", "error": f"Not a directory: {project_path}"})

    skip_dirs = {".venv", "venv", "env", "node_modules", ".git", "__pycache__", ".tox"}
    found: list[str] = []

    for root, dirs, files in os.walk(project_path):
        dirs[:] = [d for d in dirs if d not in skip_dirs]
        for name in files:
            if name in _MANIFEST_NAMES:
                found.append(os.path.join(root, name))

    return json.dumps({
        "status": "success",
        "project_path": project_path,
        "manifests": found,
        "count": len(found),
    })


# ─────────────────────────────────────────────────────────────────────────────
# 1. fetch_manifest_packages
# ─────────────────────────────────────────────────────────────────────────────

def fetch_manifest_packages(manifest_path: str) -> str:
    """Parse a requirements.txt or package.json and return every declared package.

    For each package returns: name, pinned_version (if any), ecosystem.
    The agent can then call query_pypi_metadata / query_npm_metadata on each entry.

    Supports:
      - requirements.txt  (pip format, including extras and environment markers)
      - package.json      (dependencies + devDependencies)
      - pyproject.toml    (project.dependencies table, PEP 621)
    """
    path = os.path.abspath(manifest_path)
    if not os.path.exists(path):
        return json.dumps({"status": "error", "error": f"File not found: {path}"})

    filename = os.path.basename(path)
    packages: list[dict] = []

    try:
        content = open(path, encoding="utf-8").read()

        if filename == "package.json":
            data: dict = json.loads(content)
            # Also surface any install scripts so the agent can inspect them
            scripts = {
                k: v for k, v in data.get("scripts", {}).items()
                if k in ("preinstall", "install", "postinstall", "prepare")
            }
            all_deps = {
                **{n: {"version": v, "type": "prod"} for n, v in data.get("dependencies", {}).items()},
                **{n: {"version": v, "type": "dev"}  for n, v in data.get("devDependencies", {}).items()},
            }
            for name, meta in all_deps.items():
                ver = meta["version"].lstrip("^~>=<").split(" ")[0] if meta["version"] else ""
                packages.append({"name": name, "pinned_version": ver, "ecosystem": "npm", "dep_type": meta["type"]})
            return json.dumps({
                "status": "success",
                "ecosystem": "npm",
                "manifest": path,
                "install_scripts": scripts,
                "package_count": len(packages),
                "packages": packages,
            })

        if filename in ("requirements.txt", "requirements-dev.txt", "requirements-test.txt"):
            for line in content.splitlines():
                line = line.strip()
                if not line or line.startswith("#") or line.startswith("-"):
                    continue
                # Strip environment markers and extras
                line = line.split(";")[0].strip()
                name = re.split(r"[=<>!~\[ ]", line)[0].strip()
                ver_match = re.search(r"==([^\s,]+)", line)
                ver = ver_match.group(1) if ver_match else ""
                if name:
                    packages.append({"name": name, "pinned_version": ver, "ecosystem": "pypi"})
            return json.dumps({
                "status": "success",
                "ecosystem": "pypi",
                "manifest": path,
                "package_count": len(packages),
                "packages": packages,
            })

        if filename == "pyproject.toml":
            # Minimal TOML parse for [project].dependencies
            in_deps = False
            for line in content.splitlines():
                if re.match(r"^\[project\]", line):
                    in_deps = False
                if re.match(r"^dependencies\s*=", line):
                    in_deps = True
                    continue
                if in_deps:
                    if line.strip().startswith("["):
                        in_deps = False
                        continue
                    dep = line.strip().strip('",').strip()
                    if dep:
                        name = re.split(r"[=<>!~\[ ]", dep)[0].strip()
                        ver_match = re.search(r"==([^\s,]+)", dep)
                        ver = ver_match.group(1) if ver_match else ""
                        if name:
                            packages.append({"name": name, "pinned_version": ver, "ecosystem": "pypi"})
            return json.dumps({
                "status": "success",
                "ecosystem": "pypi",
                "manifest": path,
                "package_count": len(packages),
                "packages": packages,
            })

        return json.dumps({"status": "error", "error": f"Unsupported manifest: {filename}"})

    except Exception as exc:
        logger.exception("fetch_manifest_packages failed for %s", path)
        return json.dumps({"status": "error", "error": str(exc)})


# ─────────────────────────────────────────────────────────────────────────────
# 2. query_pypi_metadata
# ─────────────────────────────────────────────────────────────────────────────

def query_pypi_metadata(package_name: str, version: str = "") -> str:
    """Query the PyPI JSON API (and pypistats) for a package.

    Returns:
      - maintainers / author info
      - release date of the requested version (and of the earliest version)
      - package age in days
      - days since this specific version was published
      - recent download count (last 30 days, from pypistats)
      - whether a GitHub/source repo is linked
      - list of all versions with their upload timestamps
      - whether any version has a yanked flag

    The agent uses this data to reason about trust signals:
    low downloads + very new + no source repo + no prior versions = high risk.
    """
    url = f"{_PYPI_BASE}/{package_name}/json"
    try:
        r = _get(url)
        if r.status_code == 404:
            return json.dumps({
                "status": "not_found",
                "package": package_name,
                "note": "Package does not exist on PyPI — may be a typo, private package, or already removed malicious package.",
            })
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        return json.dumps({"status": "error", "package": package_name, "error": str(exc)})

    info: dict[str, Any] = data.get("info", {})
    releases: dict[str, list] = data.get("releases", {})

    # Release timestamps across all versions
    version_timeline: list[dict] = []
    for ver, files in releases.items():
        if files:
            upload_time = files[0].get("upload_time", "")
            yanked = any(f.get("yanked") for f in files)
            version_timeline.append({
                "version": ver,
                "upload_time": upload_time,
                "yanked": yanked,
                "days_ago": _days_ago(upload_time),
            })
    version_timeline.sort(key=lambda x: x.get("upload_time", ""))

    # Age of the package (first ever release)
    first_release = version_timeline[0] if version_timeline else {}
    package_age_days = first_release.get("days_ago")

    # Info about the requested version specifically
    target_version = version or info.get("version", "")
    target_files = releases.get(target_version, [])
    version_upload = target_files[0].get("upload_time", "") if target_files else ""
    version_age_days = _days_ago(version_upload) if version_upload else None

    # Maintainers / author
    author = info.get("author") or info.get("maintainer") or ""
    author_email = info.get("author_email") or info.get("maintainer_email") or ""

    # Source repo link
    project_urls: dict = info.get("project_urls") or {}
    source_url = (
        project_urls.get("Source")
        or project_urls.get("Homepage")
        or project_urls.get("Repository")
        or info.get("home_page")
        or ""
    )

    # Download stats via pypistats (best-effort)
    downloads_last_month: int | None = None
    try:
        stats_r = _get(f"{_PYPISTATS_BASE}/{package_name.lower()}/recent", timeout=8)
        if stats_r.status_code == 200:
            stats = stats_r.json().get("data", {})
            downloads_last_month = stats.get("last_month")
    except Exception:
        pass

    # Yanked versions
    yanked_versions = [v["version"] for v in version_timeline if v.get("yanked")]

    return json.dumps({
        "status": "success",
        "package": package_name,
        "version_queried": target_version,
        "latest_version": info.get("version"),
        "author": author,
        "author_email": author_email,
        "source_url": source_url,
        "license": info.get("license", ""),
        "summary": (info.get("summary") or "")[:200],
        "package_age_days": package_age_days,
        "version_age_days": version_age_days,
        "version_upload_time": version_upload,
        "total_versions": len(version_timeline),
        "downloads_last_month": downloads_last_month,
        "yanked_versions": yanked_versions,
        "version_timeline": version_timeline[-10:],  # last 10 versions
        "requires_python": info.get("requires_python"),
        "trust_signals": {
            "has_source_repo": bool(source_url),
            "package_new": package_age_days is not None and package_age_days < 30,
            "version_new": version_age_days is not None and version_age_days < 7,
            "low_downloads": downloads_last_month is not None and downloads_last_month < 1000,
            "no_prior_versions": len(version_timeline) <= 1,
            "has_yanked_versions": bool(yanked_versions),
        },
    }, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# 3. query_npm_metadata
# ─────────────────────────────────────────────────────────────────────────────

def query_npm_metadata(package_name: str, version: str = "") -> str:
    """Query the npm registry for a package.

    Returns:
      - maintainers and their npm usernames
      - package creation date and latest-modify date
      - package age in days
      - weekly download count
      - install scripts (postinstall, preinstall, prepare) from the published package.json
      - dist.tarball URL (for fetching source files)
      - list of all published versions with timestamps

    The agent uses this to detect: new packages with suspicious scripts,
    maintainer changes, low downloads despite claimed popularity.
    """
    try:
        r = _get(f"{_NPM_BASE}/{package_name}")
        if r.status_code == 404:
            return json.dumps({
                "status": "not_found",
                "package": package_name,
                "note": "Package does not exist on npm — possible typo or removed malicious package.",
            })
        r.raise_for_status()
        data = r.json()
    except Exception as exc:
        return json.dumps({"status": "error", "package": package_name, "error": str(exc)})

    # Version timeline
    times: dict = data.get("time", {})
    created = times.get("created", "")
    modified = times.get("modified", "")
    package_age_days = _days_ago(created) if created else None

    version_timeline = [
        {"version": v, "published": ts, "days_ago": _days_ago(ts)}
        for v, ts in times.items()
        if v not in ("created", "modified")
    ]
    version_timeline.sort(key=lambda x: x.get("published", ""))

    # Target version
    dist_tags: dict = data.get("dist-tags", {})
    target_version = version or dist_tags.get("latest", "")
    version_data: dict = data.get("versions", {}).get(target_version, {})

    # Install scripts from the published package.json for this version
    published_scripts: dict = version_data.get("scripts", {})
    install_scripts = {
        k: v for k, v in published_scripts.items()
        if k in ("preinstall", "install", "postinstall", "prepare")
    }

    # Maintainers
    maintainers: list[dict] = data.get("maintainers", [])
    version_maintainers: list[dict] = version_data.get("maintainers", [])

    # Source repo
    repo: Any = data.get("repository", {})
    source_url = repo.get("url", "") if isinstance(repo, dict) else str(repo)

    # Tarball URL for source inspection
    dist: dict = version_data.get("dist", {})
    tarball_url = dist.get("tarball", "")

    # Download stats
    weekly_downloads: int | None = None
    try:
        dl_r = _get(f"{_NPM_DOWNLOADS}/{package_name}", timeout=8)
        if dl_r.status_code == 200:
            weekly_downloads = dl_r.json().get("downloads")
    except Exception:
        pass

    # Deprecation flag
    deprecated = version_data.get("deprecated", "")

    return json.dumps({
        "status": "success",
        "package": package_name,
        "version_queried": target_version,
        "latest_version": dist_tags.get("latest"),
        "created": created,
        "modified": modified,
        "package_age_days": package_age_days,
        "maintainers": maintainers,
        "version_maintainers": version_maintainers,
        "source_url": source_url,
        "weekly_downloads": weekly_downloads,
        "install_scripts": install_scripts,
        "tarball_url": tarball_url,
        "deprecated": deprecated,
        "total_versions": len(version_timeline),
        "version_timeline": version_timeline[-10:],
        "trust_signals": {
            "has_source_repo": bool(source_url),
            "package_new": package_age_days is not None and package_age_days < 30,
            "low_downloads": weekly_downloads is not None and weekly_downloads < 500,
            "has_install_scripts": bool(install_scripts),
            "no_prior_versions": len(version_timeline) <= 1,
            "is_deprecated": bool(deprecated),
            "maintainer_count": len(maintainers),
        },
    }, indent=2)


# ─────────────────────────────────────────────────────────────────────────────
# 4. fetch_package_source_files
# ─────────────────────────────────────────────────────────────────────────────

def fetch_package_source_files(package_name: str, version: str, ecosystem: str) -> str:
    """Download a package's published tarball and return the contents of key source files.

    For PyPI: returns setup.py, setup.cfg, pyproject.toml, __init__.py, METADATA.
    For npm : returns package.json, index.js / main entry, binding.gyp.

    The agent passes these file contents to scan_code_for_secrets or
    check_dependency_injection_vulnerabilities to find malicious code.

    Max tarball size: 5 MB. Max per-file content: 32 KB.
    """
    eco = ecosystem.lower().strip()
    if eco not in ("pypi", "npm"):
        return json.dumps({"status": "error", "error": f"Unsupported ecosystem '{ecosystem}'. Use 'pypi' or 'npm'."})

    try:
        # ── Resolve tarball URL ───────────────────────────────────────────────
        tarball_url: str = ""
        if eco == "pypi":
            r = _get(f"{_PYPI_BASE}/{package_name}/{version}/json")
            if r.status_code == 404:
                # Try latest
                r2 = _get(f"{_PYPI_BASE}/{package_name}/json")
                if r2.status_code == 200:
                    releases = r2.json().get("releases", {})
                    files = releases.get(version, [])
                    # prefer sdist
                    sdists = [f for f in files if f.get("packagetype") == "sdist"]
                    wheels = [f for f in files if f.get("packagetype") == "bdist_wheel"]
                    target = (sdists or wheels or files)
                    if target:
                        tarball_url = target[0].get("url", "")
            elif r.status_code == 200:
                urls = r.json().get("urls", [])
                sdists = [u for u in urls if u.get("packagetype") == "sdist"]
                wheels = [u for u in urls if u.get("packagetype") == "bdist_wheel"]
                target = sdists or wheels or urls
                if target:
                    tarball_url = target[0].get("url", "")
            if not tarball_url:
                return json.dumps({
                    "status": "not_found",
                    "package": package_name,
                    "version": version,
                    "ecosystem": eco,
                    "note": "Version not found on PyPI or no downloadable files available.",
                })

        elif eco == "npm":
            r = _get(f"{_NPM_BASE}/{package_name}/{version or 'latest'}")
            if r.status_code == 404:
                return json.dumps({
                    "status": "not_found",
                    "package": package_name,
                    "version": version,
                    "ecosystem": eco,
                    "note": "Version not found on npm.",
                })
            r.raise_for_status()
            tarball_url = r.json().get("dist", {}).get("tarball", "")
            if not tarball_url:
                return json.dumps({"status": "error", "error": "No tarball URL in npm response."})

        # ── Download tarball ──────────────────────────────────────────────────
        dl = _get(tarball_url, timeout=30)
        dl.raise_for_status()
        if len(dl.content) > _MAX_TARBALL_BYTES:
            return json.dumps({
                "status": "error",
                "error": f"Tarball too large ({len(dl.content)//1024} KB > {_MAX_TARBALL_BYTES//1024} KB limit).",
            })

        # ── Extract files of interest ─────────────────────────────────────────
        files_of_interest = _PYPI_FILES_OF_INTEREST if eco == "pypi" else _NPM_FILES_OF_INTEREST
        extracted: dict[str, str] = {}

        with tarfile.open(fileobj=io.BytesIO(dl.content), mode="r:gz") as tf:
            for member in tf.getmembers():
                basename = os.path.basename(member.name)
                # Always grab __init__.py files (may be in subdirs)
                is_init = basename == "__init__.py"
                if basename in files_of_interest or is_init:
                    try:
                        f = tf.extractfile(member)
                        if f:
                            raw = f.read(_MAX_FILE_BYTES)
                            text = raw.decode("utf-8", errors="replace")
                            # Use relative path as key so agent knows location
                            rel = member.name
                            extracted[rel] = text
                    except Exception:
                        continue

        if not extracted:
            return json.dumps({
                "status": "success",
                "package": package_name,
                "version": version,
                "ecosystem": eco,
                "files": {},
                "note": "No files of interest found in the tarball.",
            })

        return json.dumps({
            "status": "success",
            "package": package_name,
            "version": version,
            "ecosystem": eco,
            "tarball_url": tarball_url,
            "files_extracted": list(extracted.keys()),
            "files": extracted,
        }, indent=2)

    except Exception as exc:
        logger.exception("fetch_package_source_files failed for %s@%s (%s)", package_name, version, ecosystem)
        return json.dumps({"status": "error", "package": package_name, "error": str(exc)})
