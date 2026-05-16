"""
Configuration audit tools for Docker, Kubernetes, and IaC.

Real integrations (in priority order):
  - Trivy   : container/IaC scanner (https://trivy.dev) — preferred
  - Checkov : IaC security scanner — used if trivy unavailable
  - Regex   : last-resort fallback on actual file content
  - No mock data is returned; missing files or tools return a clear error status.
"""

import json
import logging
import os
import shutil
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
_MAX_FILES = 100


def _safe_path(raw: str) -> Path | None:
    """Resolve path and ensure it stays within allowed roots."""
    try:
        resolved = Path(raw).resolve()
        allowed_roots = [PROJECT_ROOT.resolve()]
        extra = os.environ.get("FILESYSTEM_MCP_ROOTS", "")
        for part in extra.split(os.pathsep):
            if part.strip():
                allowed_roots.append(Path(part.strip()).resolve())
        if any(str(resolved).startswith(str(root)) for root in allowed_roots):
            return resolved
    except Exception:
        pass
    return None


def _classify_file(path: Path) -> str | None:
    name = path.name.lower()
    if name == "dockerfile" or name.startswith("dockerfile."):
        return "dockerfile"
    if name in ("docker-compose.yml", "docker-compose.yaml"):
        return "docker-compose"
    if path.suffix in (".yaml", ".yml"):
        return "kubernetes"
    if path.suffix == ".tf":
        return "terraform"
    if path.suffix == ".json" and "terraform" in str(path).lower():
        return "terraform"
    return None


# ---------------------------------------------------------------------------
# Trivy integration
# ---------------------------------------------------------------------------

def _run_trivy(target: str, scanners: str = "misconfig,secret") -> list[dict] | None:
    """Run trivy and return parsed findings, or None if trivy is unavailable."""
    if not shutil.which("trivy"):
        return None
    try:
        result = subprocess.run(
            ["trivy", "fs", "--scanners", scanners, "--format", "json", "--quiet", target],
            capture_output=True,
            text=True,
            timeout=120,
        )
        if not result.stdout.strip():
            return []
        data = json.loads(result.stdout)
        findings = []
        for res in data.get("Results", []):
            target_file = res.get("Target", target)
            for m in res.get("Misconfigurations", []):
                findings.append({
                    "file": target_file,
                    "rule": m.get("ID", ""),
                    "severity": m.get("Severity", "MEDIUM").upper(),
                    "finding": m.get("Title", ""),
                    "description": m.get("Description", "")[:300],
                    "recommendation": m.get("Resolution", ""),
                    "references": m.get("References", [])[:3],
                    "source": "trivy",
                })
            for s in res.get("Secrets", []):
                findings.append({
                    "file": target_file,
                    "rule": s.get("RuleID", ""),
                    "severity": s.get("Severity", "HIGH").upper(),
                    "finding": f"Secret detected: {s.get('Title', '')}",
                    "line": s.get("StartLine"),
                    "source": "trivy",
                })
        return findings
    except subprocess.TimeoutExpired:
        logger.warning("Trivy timed out on %s", target)
        return None
    except json.JSONDecodeError as e:
        logger.error("Trivy JSON parse error for %s: %s", target, e)
        return None
    except Exception as e:
        logger.error("Trivy error for %s: %s", target, e)
        return None


# ---------------------------------------------------------------------------
# Checkov integration
# ---------------------------------------------------------------------------

def _parse_checkov_output(raw: str) -> list[dict]:
    findings = []
    try:
        data = json.loads(raw)
        results = data if isinstance(data, list) else [data]
        for block in results:
            for check in block.get("results", {}).get("failed_checks", []):
                check_obj = check.get("check", {})
                findings.append({
                    "rule": check.get("check_id", ""),
                    "severity": check.get("severity", "MEDIUM").upper() if check.get("severity") else "MEDIUM",
                    "resource": check.get("resource", ""),
                    "finding": check_obj.get("name", str(check_obj)) if isinstance(check_obj, dict) else str(check_obj),
                    "file_line": check.get("file_line_range", []),
                    "recommendation": check_obj.get("guide", "") if isinstance(check_obj, dict) else "",
                    "source": "checkov",
                })
    except Exception as e:
        logger.warning("Checkov output parse error: %s", e)
    return findings


def _run_checkov(file_path: str, framework: str) -> list[dict] | None:
    if not shutil.which("checkov"):
        return None
    try:
        result = subprocess.run(
            ["checkov", "-f", file_path, "--framework", framework, "-o", "json", "--quiet"],
            capture_output=True,
            text=True,
            timeout=90,
        )
        if result.stdout.strip():
            return _parse_checkov_output(result.stdout)
        return []
    except subprocess.TimeoutExpired:
        logger.warning("Checkov timed out on %s", file_path)
        return None
    except Exception as e:
        logger.error("Checkov error for %s: %s", file_path, e)
        return None


# ---------------------------------------------------------------------------
# Regex fallback analyzers (used only if trivy and checkov are unavailable)
# ---------------------------------------------------------------------------

def _audit_dockerfile_regex(content: str) -> list[dict]:
    findings = []
    lines = content.splitlines()
    has_nonroot_user = any(
        line.strip().upper().startswith("USER ") and "ROOT" not in line.upper()
        for line in lines
    )
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        upper = stripped.upper()
        if upper.startswith("USER ROOT") or upper == "USER ROOT":
            findings.append({"rule": "CIS-DI-0001", "severity": "HIGH", "line": i, "finding": "Container runs as root (USER root)", "recommendation": "Add non-root USER directive: USER appuser", "source": "regex"})
        if upper.startswith("ENV ") and any(kw in upper for kw in ("SECRET", "PASSWORD", "TOKEN", "KEY", "PASS", "CREDENTIAL")):
            findings.append({"rule": "CIS-DI-0010", "severity": "CRITICAL", "line": i, "finding": f"Potential secret baked into ENV: {stripped[:80]}", "recommendation": "Use Docker secrets or runtime env injection; never bake secrets into images", "source": "regex"})
        if upper.startswith("FROM ") and ":LATEST" in upper:
            findings.append({"rule": "CIS-DI-0006", "severity": "MEDIUM", "line": i, "finding": "Base image uses :latest tag", "recommendation": "Pin to a specific version or digest", "source": "regex"})
        if upper == "EXPOSE 22":
            findings.append({"rule": "CIS-DI-0005", "severity": "HIGH", "line": i, "finding": "SSH port (22) exposed in image", "recommendation": "Avoid SSH in containers; use kubectl exec or cloud shell", "source": "regex"})
        if upper.startswith("ADD ") and not upper.startswith("ADD HTTP"):
            findings.append({"rule": "CIS-DI-0009", "severity": "LOW", "line": i, "finding": "ADD used instead of COPY", "recommendation": "Prefer COPY; use ADD only for URL fetching or tar extraction", "source": "regex"})
    if not has_nonroot_user and not any(f["rule"] == "CIS-DI-0001" for f in findings):
        findings.append({"rule": "CIS-DI-0001", "severity": "HIGH", "line": 0, "finding": "No non-root USER directive found — container likely runs as root", "recommendation": "Add USER appuser before CMD/ENTRYPOINT", "source": "regex"})
    return findings


def _audit_k8s_regex(content: str) -> list[dict]:
    findings = []
    checks = [
        ("privileged: true", "CIS-K8S-5.2.1", "CRITICAL", "Container runs in privileged mode", "Set securityContext.privileged: false"),
        ("hostNetwork: true", "CIS-K8S-5.2.4", "HIGH", "hostNetwork: true — shares host network namespace", "Remove hostNetwork or restrict via admission policy"),
        ("hostPID: true", "CIS-K8S-5.2.2", "HIGH", "hostPID: true — shares host process namespace", "Set hostPID: false"),
    ]
    for pattern, rule, severity, finding, rec in checks:
        if pattern in content:
            findings.append({"rule": rule, "severity": severity, "finding": finding, "recommendation": rec, "source": "regex"})
    if "resources:" not in content:
        findings.append({"rule": "CIS-K8S-5.2.3", "severity": "MEDIUM", "finding": "No resource limits (cpu/memory)", "recommendation": "Add resources.limits.cpu and resources.limits.memory", "source": "regex"})
    if "securityContext:" not in content:
        findings.append({"rule": "CIS-K8S-5.2.6", "severity": "HIGH", "finding": "No securityContext block defined", "recommendation": "Add securityContext with runAsNonRoot, readOnlyRootFilesystem, allowPrivilegeEscalation: false", "source": "regex"})
    return findings


def _audit_terraform_regex(content: str) -> list[dict]:
    findings = []
    if '"0.0.0.0/0"' in content and "ingress" in content.lower():
        findings.append({"rule": "CKV_AWS_24", "severity": "HIGH", "finding": "Security group allows unrestricted ingress from 0.0.0.0/0", "recommendation": "Restrict to known IP ranges", "source": "regex"})
    if "::/0" in content and "ingress" in content.lower():
        findings.append({"rule": "CKV_AWS_24", "severity": "HIGH", "finding": "Security group allows unrestricted IPv6 ingress", "recommendation": "Restrict ingress to known IPv6 ranges", "source": "regex"})
    if "public-read" in content or '"public"' in content:
        findings.append({"rule": "CKV_AWS_20", "severity": "CRITICAL", "finding": "Resource configured with public read access", "recommendation": "Set acl = 'private' and use bucket policies", "source": "regex"})
    if "aws_s3_bucket" in content and "server_side_encryption_configuration" not in content:
        findings.append({"rule": "CKV_AWS_19", "severity": "HIGH", "finding": "S3 bucket encryption not configured", "recommendation": "Add aws_s3_bucket_server_side_encryption_configuration", "source": "regex"})
    if "aws_db_instance" in content and "storage_encrypted" not in content:
        findings.append({"rule": "CKV_AWS_16", "severity": "HIGH", "finding": "RDS instance storage encryption not enabled", "recommendation": "Set storage_encrypted = true", "source": "regex"})
    return findings


# ---------------------------------------------------------------------------
# Public tool functions
# ---------------------------------------------------------------------------

def list_config_files(directory: str, pattern: str = "*.yaml") -> str:
    """Discover security-relevant configuration files in a directory.
    Returns Dockerfiles, K8s manifests, Terraform configs, and Compose files.
    """
    safe = _safe_path(directory)
    if not safe:
        return json.dumps({
            "status": "error",
            "error": f"Directory '{directory}' does not exist or is outside allowed roots.",
            "files": [],
        })

    if not safe.is_dir():
        return json.dumps({"status": "error", "error": f"'{directory}' is not a directory.", "files": []})

    try:
        files = []
        for p in safe.rglob("*"):
            if not p.is_file():
                continue
            # Skip hidden dirs
            if any(part.startswith(".") for part in p.relative_to(safe).parts):
                continue
            file_type = _classify_file(p)
            if file_type:
                files.append({"path": str(p), "type": file_type, "size_bytes": p.stat().st_size})
            if len(files) >= _MAX_FILES:
                break

        return json.dumps({
            "status": "success",
            "directory": directory,
            "pattern": pattern,
            "total": len(files),
            "capped_at": _MAX_FILES if len(files) == _MAX_FILES else None,
            "files": files,
        })
    except PermissionError as e:
        return json.dumps({"status": "error", "error": f"Permission denied: {e}", "files": []})
    except Exception as e:
        logger.exception("Error listing config files in %s", directory)
        return json.dumps({"status": "error", "error": str(e), "files": []})


def read_dockerfile(file_path: str) -> str:
    """Read and return the contents of a Dockerfile."""
    safe = _safe_path(file_path)
    if not safe:
        return json.dumps({"status": "error", "error": f"'{file_path}' does not exist or is outside allowed roots."})
    if not safe.is_file():
        return json.dumps({"status": "error", "error": f"'{file_path}' is not a file."})
    try:
        content = safe.read_text(encoding="utf-8", errors="replace")
        return json.dumps({"status": "success", "path": str(safe), "content": content})
    except PermissionError:
        return json.dumps({"status": "error", "error": f"Permission denied reading '{file_path}'"})
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e)})


def audit_dockerfile_security(file_path: str) -> str:
    """Analyze a Dockerfile for security misconfigurations.
    Uses Trivy (preferred) → Checkov → regex analysis on real file content.
    Returns CIS Docker Benchmark findings.
    """
    safe = _safe_path(file_path)
    if not safe or not safe.is_file():
        return json.dumps({"status": "error", "error": f"File '{file_path}' not found or outside allowed roots.", "findings": []})

    # 1. Trivy (covers misconfig + secret detection)
    trivy_findings = _run_trivy(str(safe))
    if trivy_findings is not None:
        return json.dumps({"status": "success", "file": str(safe), "analyzer": "trivy", "findings": trivy_findings, "total": len(trivy_findings)})

    # 2. Checkov
    checkov_findings = _run_checkov(str(safe), "dockerfile")
    if checkov_findings is not None:
        return json.dumps({"status": "success", "file": str(safe), "analyzer": "checkov", "findings": checkov_findings, "total": len(checkov_findings)})

    # 3. Regex on real file content
    try:
        content = safe.read_text(encoding="utf-8", errors="replace")
        findings = _audit_dockerfile_regex(content)
        return json.dumps({
            "status": "success",
            "file": str(safe),
            "analyzer": "regex",
            "note": "Install trivy (https://trivy.dev) or checkov for more accurate results.",
            "findings": findings,
            "total": len(findings),
        })
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e), "findings": []})


def audit_kubernetes_manifest(file_path: str) -> str:
    """Analyze a Kubernetes manifest against CIS Kubernetes Benchmark.
    Uses Trivy → Checkov → regex analysis.
    """
    safe = _safe_path(file_path)
    if not safe or not safe.is_file():
        return json.dumps({"status": "error", "error": f"File '{file_path}' not found or outside allowed roots.", "findings": []})

    trivy_findings = _run_trivy(str(safe))
    if trivy_findings is not None:
        return json.dumps({"status": "success", "file": str(safe), "benchmark": "CIS Kubernetes v1.9", "analyzer": "trivy", "findings": trivy_findings})

    checkov_findings = _run_checkov(str(safe), "kubernetes")
    if checkov_findings is not None:
        return json.dumps({"status": "success", "file": str(safe), "benchmark": "CIS Kubernetes v1.9", "analyzer": "checkov", "findings": checkov_findings})

    try:
        content = safe.read_text(encoding="utf-8", errors="replace")
        findings = _audit_k8s_regex(content)
        return json.dumps({
            "status": "success",
            "file": str(safe),
            "benchmark": "CIS Kubernetes v1.9",
            "analyzer": "regex",
            "note": "Install trivy or checkov for more accurate results.",
            "findings": findings,
        })
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e), "findings": []})


def audit_terraform_config(file_path: str) -> str:
    """Analyze a Terraform .tf file for IaC security misconfigurations.
    Uses Trivy → Checkov → regex analysis.
    """
    safe = _safe_path(file_path)
    if not safe or not safe.is_file():
        return json.dumps({"status": "error", "error": f"File '{file_path}' not found or outside allowed roots.", "findings": []})

    trivy_findings = _run_trivy(str(safe))
    if trivy_findings is not None:
        return json.dumps({"status": "success", "file": str(safe), "benchmark": "Checkov v3 / Trivy", "analyzer": "trivy", "findings": trivy_findings})

    checkov_findings = _run_checkov(str(safe), "terraform")
    if checkov_findings is not None:
        return json.dumps({"status": "success", "file": str(safe), "benchmark": "Checkov v3", "analyzer": "checkov", "findings": checkov_findings})

    try:
        content = safe.read_text(encoding="utf-8", errors="replace")
        findings = _audit_terraform_regex(content)
        return json.dumps({
            "status": "success",
            "file": str(safe),
            "benchmark": "Checkov v3",
            "analyzer": "regex",
            "note": "Install trivy or checkov for more accurate results.",
            "findings": findings,
        })
    except Exception as e:
        return json.dumps({"status": "error", "error": str(e), "findings": []})
