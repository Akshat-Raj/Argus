## LigmaFirewall

Agentic security orchestration for software supply chain audits.

LigmaFirewall coordinates specialized AI security subagents to inspect CI/CD
pipelines, infrastructure configuration, application code, dependencies, and
access-control posture. It can run with local demo tools for development, and
it can load real MCP tools at startup when the relevant MCP server configuration
is available.

### What It Audits

- **CI/CD monitoring**: GitHub Actions and Jenkins workflow issues, suspicious
  build activity, and possible secret exposure in logs.
- **Access control**: IAM policies, over-privileged principals, MFA enforcement,
  and stale service-account keys.
- **Configuration security**: Dockerfiles, Kubernetes manifests, and Terraform
  using CIS Benchmark and Checkov-style checks.
- **Code analysis**: SAST-style review for hardcoded secrets, injection risks,
  and insecure coding patterns.
- **Dependency security**: SCA checks for CVEs, outdated packages, npm audit,
  PyPI safety, and SBOM-style dependency review.
- **Supply chain attack detection**: typosquats, malicious install hooks,
  import-time secret harvesting, and outbound exfil patterns in vendored or
  installed packages.

### Architecture

`agent.py` builds one DeepAgents orchestrator plus six delegated subagents:

- `supply-chain`
- `cicd-monitoring`
- `access-control`
- `config-audit`
- `code-analysis`
- `dependency-security`

Each subagent gets a focused system prompt and a small set of tools. Local tools
live under `tools/` and provide deterministic demo behavior. `tools/mcp.py`
optionally adds real MCP tools from configured servers, while filtering mutating
tools out by default.

### Requirements

- Python `>=3.14`
- `uv`
- OpenAI API key
- Optional, for real GitHub MCP access:
  - Docker, or
  - `npx`
  - A GitHub token with the permissions needed for the repositories you audit

### Setup

```bash
uv sync
cp .env.example .env
```

Set at least:

```bash
OPENAI_API_KEY=...
```

For GitHub-backed audits, set one of:

```bash
GITHUB_PERSONAL_ACCESS_TOKEN=...
GITHUB_TOKEN=...
GITHUB_PAT=...
```

### MCP Configuration

The app loads real MCP tools at startup when the required environment variables
are present, and falls back to local demo tools when they are not.

MCP tools are filtered to read-only operations by default. Keep this setting for
normal audit runs:

```bash
MCP_READ_ONLY=1
```

Set `MCP_READ_ONLY=0` only when you intentionally want mutating MCP tools
available to the agents.

Configured MCP servers:

- `github`: GitHub MCP tools for repositories, pull requests, Actions, code
  security, and Dependabot.
- `filesystem`: `@modelcontextprotocol/server-filesystem`, scoped to this
  workspace by default.
- `jenkins`: streamable HTTP MCP endpoint via `JENKINS_MCP_URL`.
- `security`: streamable HTTP MCP endpoint via `SECURITY_MCP_URL`.

With `GITHUB_MCP_URL` unset, GitHub MCP runs locally through Docker using:

```text
ghcr.io/github/github-mcp-server
```

If Docker is unavailable and `npx` is installed, the app falls back to:

```text
@modelcontextprotocol/server-github
```

Set `GITHUB_MCP_URL` to use a remote streamable HTTP MCP endpoint instead.

### Environment Variables

| Variable | Required | Description |
| --- | --- | --- |
| `OPENAI_API_KEY` | Yes | API key used by the OpenAI-backed agents. |
| `GITHUB_PERSONAL_ACCESS_TOKEN` / `GITHUB_TOKEN` / `GITHUB_PAT` | For GitHub MCP | GitHub token used by GitHub MCP tools. |
| `GITHUB_TOOLSETS` | No | GitHub MCP toolsets. Defaults to `context,repos,pull_requests,actions,code_security,dependabot`. |
| `GITHUB_READ_ONLY` | No | Keeps GitHub MCP read-only. Defaults to `1`. |
| `GITHUB_MCP_URL` | No | Remote GitHub MCP streamable HTTP endpoint. |
| `FILESYSTEM_MCP_ROOTS` | No | Filesystem MCP roots separated by `:` on macOS/Linux. Defaults to this workspace. |
| `FILESYSTEM_MCP_DISABLED` | No | Set to `1` to skip filesystem MCP loading. |
| `JENKINS_MCP_URL` | No | Jenkins MCP streamable HTTP endpoint. |
| `SECURITY_MCP_URL` | No | Custom security MCP streamable HTTP endpoint. |
| `MCP_LOAD_TIMEOUT_SECONDS` | No | Startup timeout per MCP server. Defaults to `12`. |
| `MCP_READ_ONLY` | No | Filters mutating MCP tool names. Defaults to `1`. |

### Run

```bash
uv run python main.py
```

`main.py` currently runs a sample full audit against:

```text
Shrey327/Adaptive-Threat-modeling
```

To audit a different target, update the user message in `main.py` or import
`agent` and invoke it with your own prompt:

```python
import asyncio

from agent import agent


async def run():
    result = await agent.ainvoke(
        {
            "messages": [
                {
                    "role": "user",
                    "content": "Run a full security audit on repo owner/name.",
                }
            ]
        }
    )
    print(result["messages"][-1].content)


asyncio.run(run())
```

### Supply Chain Demo

The repository includes `demo_victim_repo/`, an intentionally vulnerable sample
project modeled after maintainer credential theft followed by a malicious patch
release. The manifest includes fictional suspicious versions for narrative
realism, but the scanner flags the reusable attack behavior: an npm typosquat,
malicious install hooks, import-time triggers, and secret-exfiltration code
under `vendor/`.

Run the deterministic scanner directly:

```bash
uv run python -c 'from tools.supply_chain import check_supply_chain_risks; print(check_supply_chain_risks("demo_victim_repo"))'
```

Or ask the agent to scan:

```text
Run a supply chain attack scan on /Users/shreyansh/Documents/ligma_firewall/demo_victim_repo
```

### Development Notes

- Local tools are intentionally simple and JSON-returning so the agent flow can
  be tested without live infrastructure.
- MCP loading is best-effort by default. A server that is missing or times out
  is skipped unless strict loading is enabled in code.
- MCP tool errors are converted into observations so subagents can continue and
  try fallbacks instead of crashing the whole audit.
- Remote repository inputs should be passed to subagents as `owner/repo`.
- Filesystem MCP should only be used for paths under configured
  `FILESYSTEM_MCP_ROOTS`.
