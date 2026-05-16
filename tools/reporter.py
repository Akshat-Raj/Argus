"""Report formatting: JSON, SARIF 2.1.0, and plain text output."""

import json
from datetime import datetime, timezone

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
_SARIF_LEVEL = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "none"}


def filter_by_severity(findings: list[dict], min_severity: str = "LOW") -> list[dict]:
    """Return only findings at or above min_severity."""
    threshold = SEVERITY_ORDER.get(min_severity.upper(), 4)
    return [f for f in findings if SEVERITY_ORDER.get(f.get("severity", "INFO").upper(), 4) <= threshold]


def deduplicate_findings(findings: list[dict]) -> list[dict]:
    """Remove duplicate findings keyed on CVE ID or rule+file."""
    seen: set[str] = set()
    unique = []
    for f in findings:
        key = (
            f.get("cve")
            or f.get("id")
            or f"{f.get('rule', '')}/{f.get('resource', '')}/{f.get('file', '')}/{f.get('line', '')}"
        )
        if key not in seen:
            seen.add(key)
            unique.append(f)
    return unique


def sort_by_severity(findings: list[dict]) -> list[dict]:
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.get("severity", "INFO").upper(), 4))


def to_sarif(findings: list[dict], tool_name: str = "LigmaFirewall", version: str = "0.1.0") -> dict:
    """Convert a flat findings list to SARIF 2.1.0."""
    rules: dict[str, dict] = {}
    results = []

    for f in findings:
        rule_id = f.get("rule") or f.get("cwe") or f.get("id") or "LIGMA-001"
        severity = f.get("severity", "MEDIUM").upper()

        if rule_id not in rules:
            rules[rule_id] = {
                "id": rule_id,
                "name": f.get("vulnerability") or f.get("type") or rule_id,
                "shortDescription": {"text": (f.get("finding") or f.get("summary") or "Security finding")[:200]},
                "defaultConfiguration": {"level": _SARIF_LEVEL.get(severity, "warning")},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{rule_id.replace('CWE-', '')}.html" if rule_id.startswith("CWE-") else None,
            }

        result: dict = {
            "ruleId": rule_id,
            "level": _SARIF_LEVEL.get(severity, "warning"),
            "message": {"text": (f.get("finding") or f.get("advisory") or f.get("summary") or "")[:500]},
        }

        file_path = f.get("file") or f.get("path") or f.get("log_file")
        line_no = max(int(f.get("line") or 1), 1)
        if file_path:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": str(file_path).replace("\\", "/")},
                    "region": {"startLine": line_no},
                }
            }]

        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": version,
                    "informationUri": "https://github.com/Zenith1415/cybersecurity-ligma-firewall",
                    "rules": list(rules.values()),
                }
            },
            "results": results,
            "invocations": [{"executionSuccessful": True, "endTimeUtc": datetime.now(timezone.utc).isoformat()}],
        }],
    }


def format_text(report_content: str, min_severity: str = "LOW") -> str:
    """Pretty-print agent report content, filtering by severity if it contains JSON."""
    try:
        data = json.loads(report_content)
        findings = (
            data if isinstance(data, list)
            else data.get("findings", [])
        )
        if findings and isinstance(findings[0], dict) and "severity" in findings[0]:
            filtered = filter_by_severity(findings, min_severity)
            deduped = deduplicate_findings(filtered)
            sorted_f = sort_by_severity(deduped)
            lines = [f"[{f.get('severity','?')}] {f.get('finding') or f.get('summary') or f.get('advisory','')}" for f in sorted_f]
            return "\n".join(lines)
    except Exception:
        pass
    return report_content
