import os

from tools.mcp import load_mcp_tools_by_server

# Load .env before importing tools so all env vars are available
from tools.mcp import _load_dotenv as _init_env
_init_env()

from deepagents import SubAgent, create_deep_agent

# Local analysis tools (unique logic — no MCP equivalent)
from tools.access import (
    audit_overprivileged_roles,
    check_mfa_enforcement,
    list_iam_policies,
    list_service_account_keys,
    review_access_policy,
)
from tools.config_audit import (
    audit_dockerfile_security,
    audit_kubernetes_manifest,
    audit_terraform_config,
)
from tools.code_analysis import (
    check_dependency_injection_vulnerabilities,
    scan_code_for_secrets,
)
from tools.dependency import (
    check_cve_database,
    check_npm_audit,
    check_pypi_safety,
    trace_dependency_chain,
    list_outdated_dependencies,
)
from tools.registry import (
    list_project_manifests,
    fetch_manifest_packages,
    query_pypi_metadata,
    query_npm_metadata,
    fetch_package_source_files,
)
from tools.supply_chain import check_supply_chain_risks


_DEFAULT_MODEL = "openai:gpt-5.4-mini"


def _model() -> str:
    return os.environ.get("AGENT_MODEL", _DEFAULT_MODEL).strip() or _DEFAULT_MODEL


_MCP_TOOLS_BY_SERVER = load_mcp_tools_by_server()


def _mcp_tools(*server_names: str) -> list:
    tools: list = []
    for name in server_names:
        tools.extend(_MCP_TOOLS_BY_SERVER.get(name, []))
    return tools


# ---------------------------------------------------------------------------
# Subagent: CI/CD Monitoring
# MCP: github-mcp-server, jenkins-mcp-server
# ---------------------------------------------------------------------------
cicd_monitoring_agent: SubAgent = {
    "name": "cicd-monitoring",
    "description": (
        "Monitors GitHub Actions workflows and Jenkins pipelines for failures, "
        "anomalies, and credential/secret exposure in build logs. "
        "Delegate for: pipeline security audits, suspicious build investigations, "
        "secrets leaked in CI logs, or unusual workflow step patterns."
    ),
    "system_prompt": (
        "You are a CI/CD security analyst. Monitor GitHub Actions and Jenkins pipelines "
        "for security issues.\n\n"
        "You have GitHub MCP tools (github_get_file_contents, github_list_commits, etc.) "
        "and a scan_code_for_secrets tool. Use the GitHub tools to fetch real workflow "
        "files from .github/workflows/ and analyze them for security issues.\n\n"
        "When given a repo or job name:\n"
        "1. If given owner/repo, split it into owner and repo fields. Use github_search_code "
        "with 'repo:owner/repo path:.github/workflows' to discover workflow files, then "
        "github_get_file_contents for specific files. Try branch 'main' first; if a file "
        "or branch is not found, try 'master' and then continue with any files found.\n"
        "2. Scan workflow file contents for secret exposure patterns, excessive permissions, "
        "and untrusted input injection.\n"
        "3. Use github_list_commits to check recent CI-related changes.\n"
        "4. If a tool returns status='unconfigured', include that in your report with setup instructions.\n"
        "5. Return a structured JSON report: affected files, findings (CRITICAL/HIGH/MEDIUM/LOW), "
        "and remediations.\n\n"
        "Call independent tools in parallel. Always return a JSON-structured report."
    ),
    "model": _model(),
    "tools": [
        scan_code_for_secrets,
        *_mcp_tools("github", "jenkins"),
    ],
}

# ---------------------------------------------------------------------------
# Subagent: Access Control
# MCP: custom-security-mcp-server
# ---------------------------------------------------------------------------
access_control_agent: SubAgent = {
    "name": "access-control",
    "description": (
        "Audits IAM policies, service account/deploy keys, MFA enforcement, and "
        "over-privileged principals. Delegate for: least-privilege reviews, "
        "IAM policy analysis, stale key detection, or MFA compliance checks."
    ),
    "system_prompt": (
        "You are an access control security auditor enforcing least-privilege principles.\n\n"
        "When given a scope (org, project, or service):\n"
        "1. List IAM policies/teams and flag wildcards, admin grants, or over-broad permissions.\n"
        "2. Check MFA enforcement for all users in the org.\n"
        "3. Find stale or write-access deploy keys and service account keys.\n"
        "4. Review specific policy documents for violations using review_access_policy.\n"
        "5. If a tool returns status='unconfigured', explain what credentials are needed.\n"
        "6. Return a JSON report: principals at risk, policy violations, remediations by severity.\n\n"
        "Parallel-call tools on independent scopes. Return a JSON-structured report."
    ),
    "model": _model(),
    "tools": [
        list_iam_policies,
        audit_overprivileged_roles,
        check_mfa_enforcement,
        list_service_account_keys,
        review_access_policy,
        *_mcp_tools("security"),
    ],
}

# ---------------------------------------------------------------------------
# Subagent: Configuration Audit
# MCP: filesystem-mcp-server
# ---------------------------------------------------------------------------
config_audit_agent: SubAgent = {
    "name": "config-audit",
    "description": (
        "Audits Docker, Kubernetes, and IaC (Terraform) configs against CIS Benchmarks "
        "and Checkov/Trivy rules. Delegate for: container security reviews, K8s manifest "
        "audits, or Terraform misconfiguration scans."
    ),
    "system_prompt": (
        "You are an infrastructure security auditor applying CIS Benchmarks and Checkov/Trivy rules.\n\n"
        "You have GitHub MCP tools for remote repositories, filesystem MCP tools "
        "(filesystem_read_file, filesystem_list_directory, filesystem_search_files, "
        "filesystem_directory_tree) for local workspace paths only, and security audit tools "
        "(audit_dockerfile_security, audit_kubernetes_manifest, audit_terraform_config).\n\n"
        "When given a GitHub repo as owner/repo:\n"
        "1. Split it into owner and repo fields. Use github_search_code with queries like "
        "'repo:owner/repo filename:Dockerfile', 'repo:owner/repo extension:tf', "
        "'repo:owner/repo path:k8s extension:yaml', and 'repo:owner/repo path:.github/workflows'.\n"
        "2. Use github_get_file_contents for specific files you discover. Try branch 'main' first; "
        "if a file or branch is not found, try 'master' and then continue with any files found.\n"
        "3. For each discovered Dockerfile, Kubernetes YAML, or Terraform file, pass its path to the "
        "matching audit tool. Trivy is tried first, then Checkov, then regex analysis.\n"
        "4. Map findings to CIS control IDs or Checkov/Trivy rule IDs.\n"
        "5. Note which analyzer was used (trivy/checkov/regex) for each finding.\n"
        "6. Return a JSON report: affected file paths, rule IDs, severity, fixes, and skipped paths.\n\n"
        "When given a local directory or file path, use filesystem_list_directory or "
        "filesystem_search_files to discover config files, then read their contents.\n\n"
        "Process multiple files in parallel. Return a JSON-structured report."
    ),
    "model": _model(),
    "tools": [
        audit_dockerfile_security,
        audit_kubernetes_manifest,
        audit_terraform_config,
        *_mcp_tools("github"),
        *_mcp_tools("filesystem"),
    ],
}

# ---------------------------------------------------------------------------
# Subagent: Code Analysis (SAST)
# MCP: github-mcp-server, custom-security-mcp-server
# ---------------------------------------------------------------------------
code_analysis_agent: SubAgent = {
    "name": "code-analysis",
    "description": (
        "SAST-style security review of GitHub commits and pull requests. "
        "Detects hardcoded secrets (via Gitleaks), injection vulnerabilities (via Semgrep), "
        "and insecure patterns. Delegate for PR security gates or commit-level reviews."
    ),
    "system_prompt": (
        "You are a static application security testing (SAST) analyst. Semgrep MCP tools may be available "
        "when Semgrep Pro Engine is installed; otherwise use the local code analysis tools.\n\n"
        "You have GitHub MCP tools (github_list_commits, github_get_file_contents, "
        "github_get_pull_request, github_get_pull_request_files, github_search_code) "
        "and local security scanning tools (scan_code_for_secrets, "
        "check_dependency_injection_vulnerabilities).\n\n"
        "When given a repo and PR/commit reference:\n"
        "1. Use github_list_commits to find recent commits, then github_get_file_contents "
        "to read changed files. Use github_get_pull_request_files to get the PR diff when a PR number is given.\n"
        "2. If Semgrep MCP tools are loaded, use 'security_check' or 'semgrep_scan' on the diff/added code.\n"
        "3. If Semgrep MCP tools are not loaded, use check_dependency_injection_vulnerabilities; it runs local Semgrep when available.\n"
        "4. Also run scan_code_for_secrets for secret/credential detection (uses Gitleaks if installed).\n"
        "5. If SEMGREP_APP_TOKEN is set, call 'semgrep_findings' to pull findings from the AppSec Platform.\n"
        "6. Note the analyzer (semgrep-mcp/gitleaks/regex) for each finding.\n"
        "7. Return a JSON report: affected files, line numbers, CWE IDs, severity, remediation.\n\n"
        "Scan added code only (lines beginning with '+' in the diff). "
        "Return a JSON-structured report."
    ),
    "model": _model(),
    "tools": [
        scan_code_for_secrets,
        check_dependency_injection_vulnerabilities,
        # Semgrep MCP: security_check, semgrep_scan, semgrep_scan_with_custom_rule,
        # get_abstract_syntax_tree, semgrep_findings (AppSec Platform), supported_languages
        *_mcp_tools("semgrep", "github", "security"),
    ],
}

# ---------------------------------------------------------------------------
# Subagent: Dependency Security (SCA)
# MCP: github-mcp-server, filesystem-mcp-server, custom-security-mcp-server
# ---------------------------------------------------------------------------
dependency_security_agent: SubAgent = {
    "name": "dependency-security",
    "description": (
        "SCA (Software Composition Analysis): checks SBOMs and dependency manifests "
        "for known CVEs (via OSV API), outdated packages, and license risks. "
        "Delegate for third-party dependency audits, CVE triage, or SBOM analysis."
    ),
    "system_prompt": (
        "You are a software composition analysis (SCA) security analyst using OSV, pip-audit, and npm audit.\n\n"
        "You have GitHub MCP tools (github_get_file_contents, github_search_code) to "
        "fetch dependency manifests (package.json, requirements.txt, pyproject.toml), "
        "filesystem MCP tools to read local files, and local security tools "
        "(check_cve_database, check_npm_audit, check_pypi_safety, trace_dependency_chain, list_outdated_dependencies).\n\n"
        "When given a repo or manifest path:\n"
        "1. If given owner/repo, split it into owner and repo fields. Use github_search_code "
        "for manifest discovery, then github_get_file_contents for specific paths. Try branch "
        "'main' first; if a file or branch is not found, try 'master' and then continue with "
        "any manifests found.\n"
        "2. Parse dependency names and versions from the manifest contents.\n"
        "3. Use check_cve_database for each dependency to check for known CVEs (OSV API — no auth needed).\n"
        "4. Run check_npm_audit or check_pypi_safety on manifest files.\n"
        "5. For every HIGH/CRITICAL vulnerability, call trace_dependency_chain(package, ecosystem, manifest_path) "
        "to get the full chain path, the direct-dep fix path, and a Semgrep reachability hint. "
        "Report the chain as 'your-app → direct-dep → ... → vulnerable-pkg' and the fix as "
        "'upgrade <direct-dep> to <version>' (not 'upgrade the transitive directly').\n"
        "6. For every HIGH/CRITICAL transitive vulnerability, use semgrep_scan_with_custom_rule "
        "with the reachability hint from trace_dependency_chain to check if application code "
        "actually calls the vulnerable function. If 0 call sites found, downgrade severity to LOW "
        "and annotate as '(unreachable transitive — fix when convenient)'. If call sites are found, "
        "keep the severity and include the file/line in the report.\n"
        "7. Use list_outdated_dependencies to find version lag.\n"
        "8. Deduplicate findings by CVE ID before reporting.\n"
        "9. Return a JSON report: CVE IDs, CVSS scores, dependency_chain, fix_note, reachability "
        "status, and risk-ordered remediation steps.\n\n"
        "Process dependency checks in parallel. Return a JSON-structured report."
    ),
    "model": _model(),
    "tools": [
        check_cve_database,
        check_npm_audit,
        check_pypi_safety,
        trace_dependency_chain,
        list_outdated_dependencies,
        # Semgrep MCP: semgrep_scan_with_custom_rule for reachability checks
        *_mcp_tools("semgrep", "github", "filesystem", "security"),
    ],
}

# ---------------------------------------------------------------------------
# Subagent: Supply Chain Attack Detection
# ---------------------------------------------------------------------------
supply_chain_agent: SubAgent = {
    "name": "supply-chain",
    "description": (
        "Detects supply chain attacks by querying live package registries and reasoning "
        "about real metadata: typosquatted names, malicious install scripts, compromised "
        "package source files with import-time exfiltration. "
        "Delegate for: dependency confusion, typosquatting scans, postinstall script analysis, "
        "compromised-package triage."
    ),
    "system_prompt": (
        "You are a supply chain security analyst. You reason about real package registry data "
        "rather than matching against static lists.\n\n"
        "## Tools available\n"
        "- list_project_manifests(project_path)   → find all manifest files under a directory "
        "(pure Python os.walk — use this first when given a directory path)\n"
        "- fetch_manifest_packages(manifest_path) → parse requirements.txt or package.json\n"
        "- query_pypi_metadata(name, version)      → PyPI metadata: maintainer, age, downloads, "
        "trust signals\n"
        "- query_npm_metadata(name, version)       → npm metadata: maintainer, age, downloads, "
        "install scripts, trust signals\n"
        "- fetch_package_source_files(name, version, ecosystem) → download tarball, return "
        "setup.py / __init__.py / package.json / index.js contents\n"
        "- scan_code_for_secrets(code)             → detect hardcoded secrets / credentials\n"
        "- check_dependency_injection_vulnerabilities(code) → detect eval, exec, subprocess, "
        "urllib calls in source code\n\n"
        "## Investigation workflow\n"
        "1. NEVER use read_file, ls, or shell commands. ALL file access goes through the "
        "tools listed above — they use Python's os.walk / open() directly, bypassing MCP.\n"
        "   - Given a DIRECTORY path → call list_project_manifests(path) first.\n"
        "   - Given an explicit FILE path → call fetch_manifest_packages(path) directly.\n"
        "2. Call fetch_manifest_packages on every manifest path returned by step 1.\n"
        "3. For ALL packages in parallel, call query_pypi_metadata or query_npm_metadata.\n"
        "4. Examine the trust_signals block in each response. Flag any package where:\n"
        "   - package_new=true  (created < 30 days ago)\n"
        "   - low_downloads=true (< 1 000/month PyPI, < 500/week npm)\n"
        "   - no_prior_versions=true (first ever release)\n"
        "   - has_install_scripts=true (npm postinstall/preinstall/prepare)\n"
        "   - maintainer_count == 1 and no source repo\n"
        "   - package does not exist (status=not_found) — possible already-removed malicious pkg\n"
        "5. For every flagged package, call fetch_package_source_files to get the actual code.\n"
        "6. Pass each extracted file through scan_code_for_secrets and "
        "check_dependency_injection_vulnerabilities.\n"
        "7. For npm packages with install_scripts, decode exactly what the script does "
        "(e.g. 'base64-encodes process.env and POSTs to attacker-c2.xyz').\n"
        "8. Assess typosquatting by reasoning: does the name differ from a well-known package "
        "by one character, transposition, or hyphenation? Cross-check download counts "
        "(suspicious: 47/week vs real package: 50M/month).\n\n"
        "## Severity rules\n"
        "CRITICAL: install script with outbound network call OR __init__.py with network/subprocess "
        "call OR package doesn't exist on registry (already yanked malicious pkg)\n"
        "HIGH: clear typosquat (name differs by 1 char from popular package, << downloads)\n"
        "MEDIUM: new package, low downloads, no source repo — suspicious but not confirmed\n\n"
        "## Output\n"
        "Return a JSON report: total_findings, critical, high, medium, findings[]. "
        "Each finding: type, severity, package, evidence (registry data that triggered the flag), "
        "what_it_does (decoded attack), remediation (exact pip/npm command + credentials to rotate). "
        "Be precise. Every CRITICAL/HIGH finding must cite specific registry data as evidence."
    ),
    "model": _model(),
    "tools": [
        list_project_manifests,
        fetch_manifest_packages,
        query_pypi_metadata,
        query_npm_metadata,
        fetch_package_source_files,
        scan_code_for_secrets,
        check_dependency_injection_vulnerabilities,
    ],
}


# ---------------------------------------------------------------------------
# Orchestrator
# ---------------------------------------------------------------------------
_ORCHESTRATOR_PROMPT = """\
You are LigmaFirewall, an AI security orchestration platform for software supply chain security.
You coordinate 6 specialized security subagents, each using real tool integrations.
You also have direct access to check_supply_chain_risks(project_path) for local
supply-chain scans; use it whenever the user gives a local path and asks about
package compromise, typosquatting, LiteLLM/Axios-style attacks, install hooks,
or import-time secret exfiltration.

Subagents and when to delegate:
- supply-chain       : typosquatted packages, malicious postinstall scripts, compromised __init__.py exfil code
- cicd-monitoring    : CI/CD pipeline failures, secrets in logs, suspicious workflow steps
- access-control     : IAM/team policy review, over-privileged roles, MFA gaps, stale deploy keys
- config-audit       : Docker/K8s/Terraform misconfigurations via Trivy, Checkov, CIS Benchmarks
- code-analysis      : PR/commit SAST review via Semgrep MCP (security_check, semgrep_scan) + Gitleaks; hardcoded secrets, injections
- dependency-security: CVE checks via OSV API, outdated packages, SBOM analysis, pip-audit/npm audit

Coordination rules:
1. Comprehensive audit request → launch all 6 subagents in parallel via the task tool.
2. Domain-specific request → launch only the relevant subagent(s).
   If the request mentions supply-chain attacks, typosquatting, malicious package
   install/import behavior, LiteLLM-style compromise, Axios-style compromise, or
   a local filesystem path to scan, call check_supply_chain_risks(project_path)
   directly or delegate to the supply-chain subagent before writing the report.
3. When a tool returns status='unconfigured', include setup instructions in the report.
4. Synthesize all subagent results into a single prioritized security report.
5. Order findings by severity: CRITICAL → HIGH → MEDIUM → LOW → INFO.
6. Deduplicate findings with the same CVE ID or rule+file combination.
7. Include an executive summary (3-5 bullet points) at the top of every report.
8. Note which real analyzer (trivy/semgrep/gitleaks/checkov/osv/pip-audit/npm/supply-chain-scanner) produced each finding.
9. Do not invent analyzer names. If a finding came from check_supply_chain_risks,
   cite the analyzer as supply-chain-scanner.

IMPORTANT — pass repo to subagents as 'owner/repo' string exactly (e.g. 'Shrey327/Adaptive-Threat-modeling').
Subagents will split it into owner and repo fields themselves.
Do NOT pre-verify the repo exists — delegate immediately and let subagents use their tools.

When delegating to supply-chain for a LOCAL project path, pass the ABSOLUTE paths to the manifest
files directly (e.g. '/path/to/requirements.txt' and '/path/to/package.json'), not just the
directory. supply-chain's fetch_manifest_packages reads files by path — it does not shell out.
"""

agent = create_deep_agent(
    model=_model(),
    tools=[check_supply_chain_risks],
    system_prompt=_ORCHESTRATOR_PROMPT,
    subagents=[
        supply_chain_agent,
        cicd_monitoring_agent,
        access_control_agent,
        config_audit_agent,
        code_analysis_agent,
        dependency_security_agent,
    ],
)
