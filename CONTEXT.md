# LigmaFirewall Technical Context (KT Document)

> [!NOTE]
> This document is designed for AI Agent Knowledge Transfer (KT). It details the deep architecture, tool usage, Model Context Protocol (MCP) integrations, and Reinforcement Learning (RL) pipelines of the `cybersecurity-ligma-firewall` repository.

## 1. System Overview
LigmaFirewall is an **Agentic AI framework for software supply chain security**. It uses a central orchestrator (built on `deepagents`) to coordinate specialized subagents. It is designed to be highly resilient, safely executing read-only audits using a combination of local deterministic Python tools and real Model Context Protocol (MCP) servers.

## 2. Orchestration Architecture
The primary entrypoint is `agent.py`, which defines the main orchestrator and its 5 subagents using `create_deep_agent` and `SubAgent`. The orchestrator uses `openai:gpt-4o-mini` by default (configurable via `AGENT_MODEL`). 

### Subagent Delegation Rules
The orchestrator delegates tasks to the following subagents in parallel based on the user's prompt:
1. **`cicd-monitoring`**: Scans GitHub Actions and Jenkins pipelines for log leaks, suspicious steps, and failures.
2. **`access-control`**: Audits IAM policies, MFA enforcement, and service account keys for over-privileged access.
3. **`config-audit`**: Checks Dockerfiles, Kubernetes manifests, and Terraform files against CIS benchmarks using Trivy/Checkov rules.
4. **`code-analysis`**: Acts as an AI SAST tool. Analyzes commit/PR diffs for hardcoded secrets (via Gitleaks) and injections (via Semgrep).
5. **`dependency-security`**: Acts as an AI SCA tool. Checks SBOMs and package manifests for CVEs via the OSV API, outdated packages, and evaluates vulnerability reachability.

## 3. Tooling & MCP Integration
The framework seamlessly blends local tools and real infrastructure tools via the Model Context Protocol (MCP). `tools/mcp.py` is the workhorse for dynamic tool loading.

### Configured MCP Servers
1. **`github`**: Loads via remote HTTP, local Docker (`ghcr.io/github/github-mcp-server`), or `npx` fallback. Provides tools like `github_search_code`, `github_get_file_contents`.
2. **`semgrep`**: Loads via `semgrep mcp`, `uvx`, or Docker. Provides `security_check`, `semgrep_scan`, and `semgrep_scan_with_custom_rule`. Used heavily by `code-analysis`.
3. **`filesystem`**: Scoped to the workspace, providing local code access via `npx @modelcontextprotocol/server-filesystem`.
4. **`jenkins` & `security`**: Connected via streamable HTTP endpoints (`JENKINS_MCP_URL`, `SECURITY_MCP_URL`).

### Tool Safety & Resilience
- **Read-Only Enforcement**: By default (`MCP_READ_ONLY=1`), `mcp.py` filters out any mutating tools (e.g., matching "create_", "delete", "push") to ensure audits cannot destroy infrastructure.
- **Recoverability**: Tools are wrapped via `_make_tool_recoverable()`. If an MCP tool throws an exception, it is caught and returned as a string observation so the LLM can try fallbacks without crashing the audit.

## 4. Reinforcement Learning (RL) Evaluation Pipeline
To solve the problem of LLM orchestrators being overly cautious (generating False Positives and too many "Manual Review" requests), an RL pipeline was built to train decision-making models.

### RL Components
1. **`scenario_generator.py`**: A dynamic dataset generator. Instead of static synthetic data, it uses the GitHub API to randomly sample real commits from curated intentionally vulnerable repositories (e.g., `juice-shop/juice-shop`, `cider-security-research/cicd-goat`). It caches these commits in-memory (`cache_size`) to avoid GitHub API rate limits.
2. **`rl_env.py` (`SecurityOrchestratorEnv`)**: A custom `gymnasium` environment. The environment simulates the output of the 5 subagents by parsing the real commit diffs from the `ScenarioGenerator` using heuristics (e.g., counting "eval", "password", "TODO: hack"). The state space is an 8-dimensional numerical vector.
   - **Action Space (Discrete 5)**: 0 (Allow), 1 (Quarantine), 2 (Halt CI/CD), 3 (Block User), 4 (Manual Review).
   - **Rewards**: Heavily penalizes False Positives and unnecessary Manual Reviews, rewarding decisive True Positives (Blocks/Quarantines).
3. **`train_rl.py`**: Uses `stable-baselines3` to train PPO and DQN models over the `SecurityOrchestratorEnv`.
4. **`test_rl.py`**: Evaluates the trained PPO/DQN models against fresh commits from the `ScenarioGenerator`, outputting an evaluation report containing Precision, Recall, F1-Score, and Developer Intervention Overhead.
5. **`telemetry.py`**: Tracks CPU, memory usage, and inference latency using `psutil` in a background thread to calculate operational overhead.

## 5. Execution Flows
- **General Audit**: `uv run python main.py --repo owner/repo --format sarif`
  - `main.py` parses arguments, formats the prompt, invokes the `agent`, and uses `tools/reporter.py` to deduplicate findings, filter by severity, and format the output as JSON or SARIF 2.1.0.
- **RL Training**: `uv run python train_rl.py` -> trains and saves `models/ppo_security_agent.zip`.

## 6. Key Files for AI Context
- `agent.py`: Read this to understand how LangChain/DeepAgents prompts are structured and what tools are delegated.
- `tools/mcp.py`: Read this to understand how MCP tools are dynamically resolved, filtered, and wrapped.
- `tools/reporter.py`: Handles deduplication (by CVE or file+line) and SARIF 2.1.0 output formatting.
- `rl_env.py` & `scenario_generator.py`: The core of the new reinforcement learning logic simulating real-world security inputs.
