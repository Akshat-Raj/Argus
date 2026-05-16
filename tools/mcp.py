"""MCP server configuration and tool loading.

Configured servers:
  - github     : GitHub MCP server (Docker / npx / remote URL)
  - filesystem : @modelcontextprotocol/server-filesystem (npx)
  - semgrep    : semgrep mcp (pip install semgrep / uvx / Docker) — SAST + secret scanning
  - jenkins    : Jenkins HTTP MCP endpoint (JENKINS_MCP_URL)
  - security   : Custom security MCP endpoint (SECURITY_MCP_URL)
"""

from __future__ import annotations

import asyncio
import logging
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).resolve().parents[1]
MUTATING_TOOL_WORDS = (
    "add_",
    "create_",
    "delete",
    "edit",
    "fork",
    "merge",
    "move",
    "push",
    "remove",
    "update",
    "write",
)


def _make_tool_recoverable(tool: Any) -> Any:
    """Return MCP tool errors as observations so agents can try fallbacks."""
    from langchain_core.tools import StructuredTool

    coroutine = getattr(tool, "coroutine", None)
    if coroutine is not None:
        tool_name = getattr(tool, "name", "mcp_tool")

        async def _safe_coroutine(*args: Any, **kwargs: Any) -> str:
            try:
                return await coroutine(*args, **kwargs)
            except Exception as exc:
                return f"{tool_name} failed: {type(exc).__name__}: {exc}"

        return StructuredTool.from_function(
            coroutine=_safe_coroutine,
            name=tool_name,
            description=getattr(tool, "description", "") or tool_name,
            args_schema=getattr(tool, "args_schema", None),
            infer_schema=False,
            response_format="content",
            metadata=getattr(tool, "metadata", None),
            tags=getattr(tool, "tags", None),
            handle_tool_error=True,
            handle_validation_error=True,
        )

    try:
        return tool.model_copy(
            update={
                "handle_tool_error": True,
                "handle_validation_error": True,
            }
        )
    except AttributeError:
        return tool


def _load_dotenv(path: Path = PROJECT_ROOT / ".env") -> None:
    """Load simple KEY=VALUE entries without requiring python-dotenv."""
    if not path.exists():
        return
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip()
        if key.startswith("export "):
            key = key.removeprefix("export ").strip()
        value = value.strip().strip('"').strip("'")
        if key and key not in os.environ:
            os.environ[key] = value


def _env(name: str, default: str | None = None) -> str | None:
    value = os.getenv(name, default)
    return value if value else None


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        return subprocess.run(["docker", "info"], capture_output=True, timeout=5).returncode == 0
    except Exception:
        return False


# ---------------------------------------------------------------------------
# Per-server connection builders
# ---------------------------------------------------------------------------

def _github_connection() -> dict[str, Any] | None:
    token = _env("GITHUB_PERSONAL_ACCESS_TOKEN") or _env("GITHUB_TOKEN") or _env("GITHUB_PAT")
    if not token:
        logger.info("Skipping GitHub MCP: set GITHUB_PERSONAL_ACCESS_TOKEN, GITHUB_TOKEN, or GITHUB_PAT.")
        return None

    toolsets = _env("GITHUB_TOOLSETS", "context,repos,pull_requests,actions,code_security,dependabot")

    # Remote HTTP endpoint (fastest, no local runtime needed)
    github_url = _env("GITHUB_MCP_URL")
    if github_url:
        return {
            "transport": "streamable_http",
            "url": github_url,
            "headers": {"Authorization": f"Bearer {token}"},
        }

    # Local Docker
    if _docker_available():
        return {
            "transport": "stdio",
            "command": "docker",
            "args": [
                "run", "-i", "--rm",
                "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
                "-e", "GITHUB_TOOLSETS",
                "-e", "GITHUB_READ_ONLY",
                "ghcr.io/github/github-mcp-server",
            ],
            "env": {
                "GITHUB_PERSONAL_ACCESS_TOKEN": token,
                "GITHUB_TOOLSETS": toolsets,
                "GITHUB_READ_ONLY": _env("GITHUB_READ_ONLY", "1"),
            },
        }

    # npx fallback
    if shutil.which("npx"):
        logger.info("Docker unavailable — using npx @modelcontextprotocol/server-github")
        return {
            "transport": "stdio",
            "command": "npx",
            "args": ["-y", "@modelcontextprotocol/server-github"],
            "env": {
                **os.environ,
                "GITHUB_PERSONAL_ACCESS_TOKEN": token,
                "GITHUB_TOOLSETS": toolsets,
            },
        }

    logger.info("Skipping GitHub MCP: neither Docker nor npx is available.")
    return None


def _semgrep_connection() -> dict[str, Any] | None:
    """
    Semgrep MCP server — provides security_check, semgrep_scan,
    semgrep_scan_with_custom_rule, get_abstract_syntax_tree, and more.

    Install: pip install semgrep  OR  brew install semgrep
    Docs:    https://semgrep.dev/docs/mcp
    Auth:    SEMGREP_APP_TOKEN (optional — enables AppSec Platform findings)
    """
    if _env("SEMGREP_MCP_ENABLED", "0") != "1":
        logger.info(
            "Skipping Semgrep MCP: set SEMGREP_MCP_ENABLED=1 when Semgrep Pro Engine is installed. "
            "Local Semgrep CLI scans remain available through code_analysis tools."
        )
        return None

    token = _env("SEMGREP_APP_TOKEN", "")
    _venv_scripts = str(Path(sys.executable).parent)
    _path = os.environ.get("PATH", "")
    semgrep_cache = PROJECT_ROOT / ".cache" / "semgrep"
    semgrep_config = PROJECT_ROOT / ".config"
    semgrep_data = semgrep_config / ".semgrep"
    semgrep_cache.mkdir(parents=True, exist_ok=True)
    semgrep_data.mkdir(parents=True, exist_ok=True)
    extra_env = {
        **os.environ,
        "PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION": "python",
        "PATH": f"{_venv_scripts}{os.pathsep}{_path}",
        "XDG_CACHE_HOME": str(PROJECT_ROOT / ".cache"),
        "XDG_CONFIG_HOME": str(semgrep_config),
        "SEMGREP_LOG_FILE": str(semgrep_cache / "semgrep.log"),
        "SEMGREP_SETTINGS_FILE": str(semgrep_data / "settings.yml"),
        "SEMGREP_VERSION_CACHE_PATH": str(PROJECT_ROOT / ".cache" / "semgrep_version"),
    }
    cert_file = Path("/opt/homebrew/etc/ca-certificates/cert.pem")
    if cert_file.exists():
        extra_env.setdefault("SSL_CERT_FILE", str(cert_file))
        extra_env.setdefault("REQUESTS_CA_BUNDLE", str(cert_file))
    if token:
        extra_env["SEMGREP_APP_TOKEN"] = token

    # Primary: semgrep mcp — built-in MCP subcommand of the semgrep CLI.
    # Prefer Homebrew/system Semgrep over the Python package wrapper in .venv:
    # some pip builds expose an older/pro-engine-only MCP mode.
    candidates = [
        _env("SEMGREP_BIN"),
        "/opt/homebrew/bin/semgrep",
        "/usr/local/bin/semgrep",
        shutil.which("semgrep"),
    ]
    seen: set[str] = set()
    for candidate in candidates:
        if not candidate or candidate in seen or not Path(candidate).exists():
            continue
        seen.add(candidate)
        try:
            probe = subprocess.run(
                [candidate, "mcp", "--help"],
                capture_output=True,
                text=True,
                timeout=12,
                env=extra_env,
            )
        except Exception as exc:
            logger.info("Skipping Semgrep MCP candidate %s: %s", candidate, exc)
            continue
        help_text = f"{probe.stdout}\n{probe.stderr}"
        if probe.returncode != 0 or "--transport" not in help_text:
            logger.info("Skipping incompatible Semgrep MCP candidate %s: %s", candidate, help_text[:300])
            continue
        logger.info("Using semgrep mcp at %s", candidate)
        return {
            "transport": "stdio",
            "command": candidate,
            "args": ["mcp", "-t", "stdio"],
            "env": extra_env,
        }

    # Fallback: venv-local semgrep-mcp binary (legacy)
    _venv_bin = Path(sys.executable).parent / (
        "semgrep-mcp.exe" if sys.platform == "win32" else "semgrep-mcp"
    )
    if _venv_bin.exists():
        logger.info("Using venv semgrep-mcp at %s", _venv_bin)
        return {
            "transport": "stdio",
            "command": str(_venv_bin),
            "args": [],
            "env": extra_env,
        }

    # Fallback: pip-installed semgrep-mcp (legacy)
    if shutil.which("semgrep-mcp"):
        logger.info("Using locally installed semgrep-mcp")
        return {
            "transport": "stdio",
            "command": "semgrep-mcp",
            "args": [],
            "env": extra_env,
        }

    # uvx (uv's tool runner — no install needed)
    if shutil.which("uvx"):
        logger.info("semgrep not found — using uvx semgrep-mcp")
        return {
            "transport": "stdio",
            "command": "uvx",
            "args": ["semgrep-mcp"],
            "env": extra_env,
        }

    # Docker
    if _docker_available():
        logger.info("semgrep not found — using Docker semgrep/semgrep")
        docker_args = ["run", "-i", "--rm"]
        if token:
            docker_args += ["-e", "SEMGREP_APP_TOKEN"]
        docker_args += ["semgrep/semgrep", "semgrep", "mcp"]
        return {
            "transport": "stdio",
            "command": "docker",
            "args": docker_args,
            "env": extra_env,
        }

    logger.info(
        "Skipping Semgrep MCP: install semgrep (`pip install semgrep`) "
        "or ensure uvx/Docker is available."
    )
    return None


def _filesystem_connection() -> dict[str, Any] | None:
    if _env("FILESYSTEM_MCP_DISABLED", "0") == "1":
        return None
    if not shutil.which("npx"):
        logger.info("Skipping filesystem MCP: npx is not available.")
        return None

    allowed_dirs = _env("FILESYSTEM_MCP_ROOTS", str(PROJECT_ROOT))
    return {
        "transport": "stdio",
        "command": "npx",
        "args": [
            "-y",
            "@modelcontextprotocol/server-filesystem",
            *[part for part in allowed_dirs.split(os.pathsep) if part],
        ],
    }


def _http_connection(url_env: str, label: str) -> dict[str, Any] | None:
    url = _env(url_env)
    if not url:
        logger.info("Skipping %s MCP: set %s.", label, url_env)
        return None
    return {"transport": "streamable_http", "url": url}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_mcp_connections() -> dict[str, dict[str, Any]]:
    """Build all configured MCP server connections."""
    _load_dotenv()

    candidates = {
        "github":     _github_connection(),
        "semgrep":    _semgrep_connection(),
        "filesystem": _filesystem_connection(),
        "jenkins":    _http_connection("JENKINS_MCP_URL", "Jenkins"),
        "security":   _http_connection("SECURITY_MCP_URL", "custom security"),
    }
    active = {name: cfg for name, cfg in candidates.items() if cfg is not None}
    logger.info("Active MCP servers: %s", list(active.keys()) or ["none"])
    return active


async def _load_server_tools(name: str, config: dict[str, Any], timeout: float) -> list[Any]:
    from langchain_mcp_adapters.client import MultiServerMCPClient

    client = MultiServerMCPClient({name: config}, tool_name_prefix=True)
    tools = await asyncio.wait_for(client.get_tools(server_name=name), timeout=timeout)
    if _env("MCP_READ_ONLY", "1") != "1":
        return tools

    return [
        tool
        for tool in tools
        if not any(word in getattr(tool, "name", "") for word in MUTATING_TOOL_WORDS)
    ]


async def load_mcp_tools_by_server_async(strict: bool = False) -> dict[str, list[Any]]:
    """Load LangChain tools from each configured MCP server."""
    connections = build_mcp_connections()
    timeout = float(_env("MCP_LOAD_TIMEOUT_SECONDS", "12") or "12")
    semgrep_timeout = float(_env("SEMGREP_MCP_LOAD_TIMEOUT_SECONDS", str(max(timeout, 180))) or "180")
    tools_by_server: dict[str, list[Any]] = {}

    for name, config in connections.items():
        try:
            server_timeout = semgrep_timeout if name == "semgrep" else timeout
            tools_by_server[name] = [
                _make_tool_recoverable(tool)
                for tool in await _load_server_tools(name, config, server_timeout)
            ]
            logger.info("Loaded %d tools from %s MCP.", len(tools_by_server[name]), name)
        except Exception as exc:
            if strict:
                raise
            logger.warning("Could not load %s MCP tools: %s: %r", name, type(exc).__name__, exc)

    return tools_by_server


def load_mcp_tools_by_server(strict: bool = False) -> dict[str, list[Any]]:
    """Synchronous wrapper for module-level agent creation."""
    try:
        asyncio.get_running_loop()
        logger.warning("Could not load MCP tools from inside an existing event loop.")
        return {}
    except RuntimeError:
        return asyncio.run(load_mcp_tools_by_server_async(strict=strict))
