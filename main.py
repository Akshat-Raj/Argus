"""
LigmaFirewall — entry point.

Usage:
  uv run python main.py
  uv run python main.py --repo myorg/myrepo
  uv run python main.py --repo myorg/myrepo --format sarif
  uv run python main.py --repo myorg/myrepo --severity HIGH
  uv run python main.py "audit the access controls for myorg"
"""

import argparse
import asyncio
import json
import sys

from agent import agent
from tools.reporter import deduplicate_findings, filter_by_severity, sort_by_severity, to_sarif


def _message_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(
            block.get("text", str(block))
            for block in content
            if isinstance(block, dict)
        )
    return str(content)


def build_prompt(repo: str | None, custom: str | None) -> str:
    if custom:
        return custom
    if repo:
        return (
            f"Run a comprehensive security audit on repository {repo}: "
            "check CI/CD pipelines for secret exposure and failures, "
            "audit access controls and MFA enforcement, "
            "scan infrastructure configs (Docker, K8s, Terraform) with Trivy/Checkov, "
            "review recent PRs for vulnerabilities with Semgrep and Gitleaks, "
            "and check all dependencies for CVEs via OSV API."
        )
    return (
        "Run a comprehensive security audit: "
        "check CI/CD pipelines, access controls, infrastructure configs, "
        "recent code changes for vulnerabilities, and dependency CVEs."
    )


def extract_findings(report_text: str) -> list[dict]:
    findings = []
    try:
        data = json.loads(report_text)
        if isinstance(data, list):
            return data
        if isinstance(data, dict):
            for key in ("findings", "vulnerabilities", "results"):
                if isinstance(data.get(key), list):
                    findings.extend(data[key])
    except Exception:
        pass
    return findings


def main() -> None:
    parser = argparse.ArgumentParser(description="LigmaFirewall — AI supply chain security auditor")
    parser.add_argument("prompt", nargs="?", help="Custom audit prompt (overrides --repo)")
    parser.add_argument("--repo", "-r", help="GitHub repo in owner/repo format to audit")
    parser.add_argument(
        "--format", "-f",
        choices=["text", "json", "sarif"],
        default="text",
        help="Output format (default: text)",
    )
    parser.add_argument(
        "--severity", "-s",
        choices=["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
        default="LOW",
        help="Minimum severity level to include in output (default: LOW)",
    )
    parser.add_argument(
        "--output", "-o",
        help="Write output to this file path (in addition to stdout)",
    )
    args = parser.parse_args()

    prompt = build_prompt(args.repo, args.prompt)

    print(f"[LigmaFirewall] Starting audit...", file=sys.stderr)
    if args.repo:
        print(f"[LigmaFirewall] Target: {args.repo}", file=sys.stderr)
    print(f"[LigmaFirewall] Output: {args.format.upper()}, min severity: {args.severity}", file=sys.stderr)
    print("", file=sys.stderr)

    result = asyncio.run(agent.ainvoke({"messages": [{"role": "user", "content": prompt}]}))
    report_content = _message_text(result["messages"][-1].content)

    # --- STRUCTURED LOGGING ---
    findings = extract_findings(report_content)
    if findings:
        from tools.logger import log_vulnerability
        deduped_for_log = deduplicate_findings(findings)
        for f in deduped_for_log:
            log_vulnerability(
                agent_name="LigmaFirewall-Orchestrator",
                action_taken="Reported",
                target_file=str(f.get("file") or f.get("path") or f.get("resource") or "unknown"),
                cve_id=str(f.get("cve") or f.get("id") or f.get("rule") or "N/A"),
                reasoning=str(f.get("finding") or f.get("summary") or f.get("advisory") or "")[:200],
                severity=str(f.get("severity", "INFO")).upper()
            )

    if args.format == "text":
        output = report_content

    elif args.format == "json":
        if findings:
            filtered = filter_by_severity(findings, args.severity)
            deduped = deduplicate_findings(filtered)
            sorted_f = sort_by_severity(deduped)
            output = json.dumps({"findings": sorted_f, "total": len(sorted_f)}, indent=2)
        else:
            output = json.dumps({"report": report_content}, indent=2)

    elif args.format == "sarif":
        if findings:
            filtered = filter_by_severity(findings, args.severity)
            deduped = deduplicate_findings(filtered)
            sarif = to_sarif(deduped)
        else:
            sarif = to_sarif([])
            sarif["runs"][0]["invocations"][0]["toolExecutionNotifications"] = [
                {"message": {"text": report_content[:2000]}, "level": "note"}
            ]
        output = json.dumps(sarif, indent=2)

    print(output)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(output)
        print(f"[LigmaFirewall] Report saved to {args.output}", file=sys.stderr)


if __name__ == "__main__":
    main()
