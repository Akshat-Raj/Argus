"""
LigmaFirewall — FastAPI streaming backend.

Run:  uv run uvicorn api:app --port 8000 --reload
"""

import asyncio
import json
from contextlib import asynccontextmanager
from concurrent.futures import ThreadPoolExecutor
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse
from pydantic import BaseModel

# Load env before any tool imports
from tools.mcp import _load_dotenv as _init_env
_init_env()

# Agent is built lazily in lifespan (MCP tools need a thread without a running loop)
_agent = None


def _build_agent_in_thread():
    """Runs in a ThreadPoolExecutor so asyncio.run() can create its own loop."""
    # Importing agent here triggers load_mcp_tools_by_server() in a thread-local context
    # with no running event loop — asyncio.run() succeeds.
    from agent import agent as _a
    return _a


@asynccontextmanager
async def lifespan(_app: FastAPI):
    global _agent
    loop = asyncio.get_event_loop()
    with ThreadPoolExecutor(max_workers=1) as pool:
        _agent = await loop.run_in_executor(pool, _build_agent_in_thread)
    print("[LigmaFirewall] Agent ready with MCP tools.")
    yield


app = FastAPI(title="LigmaFirewall API", lifespan=lifespan)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)


class ScanRequest(BaseModel):
    target: str
    mode: str = "repo"  # "repo" | "path" | "custom"


def _build_prompt(target: str, mode: str) -> str:
    if mode == "custom":
        return target
    if mode == "repo":
        return (
            f"Run a comprehensive security audit on repository {target}: "
            "check CI/CD pipelines for secret exposure and failures, "
            "audit access controls and MFA enforcement, "
            "scan infrastructure configs (Docker, K8s, Terraform) with Trivy/Checkov, "
            "review recent PRs for vulnerabilities with Semgrep and Gitleaks, "
            "and check all dependencies for CVEs via OSV API."
        )
    return (
        f"Run a comprehensive security audit on the local project at {target}: "
        "scan for supply chain risks (typosquatting, malicious packages), "
        "check dependencies for CVEs, "
        "audit configuration files (Docker, K8s, Terraform), "
        "and scan source code for hardcoded secrets and injection vulnerabilities."
    )


def _sse(data: dict) -> str:
    return f"data: {json.dumps(data)}\n\n"


async def _stream_scan(target: str, mode: str) -> AsyncIterator[str]:
    if _agent is None:
        yield _sse({"type": "error", "text": "Agent not ready yet — retry in a moment."})
        yield _sse({"type": "done"})
        return

    prompt = _build_prompt(target, mode)
    yield _sse({"type": "status", "text": f"Starting audit: {target}"})

    seen_agents: set[str] = set()
    # on_chat_model_end fires once per complete LLM response with the full text.
    # The last one at the shallowest parent_ids depth is the orchestrator's
    # final synthesis. We keep updating it so the last write wins.
    report_by_depth: dict[int, str] = {}

    SUBAGENT_LABELS = {
        "supply-chain":        "α  supply-chain",
        "cicd-monitoring":     "β  cicd-monitoring",
        "access-control":      "γ  access-control",
        "config-audit":        "δ  config-audit",
        "code-analysis":       "ε  code-analysis",
        "dependency-security": "ζ  dependency-security",
    }

    def _extract_text(content) -> str:
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            return "".join(
                b.get("text", "") for b in content
                if isinstance(b, dict) and b.get("type") == "text"
            )
        return ""

    try:
        async for event in _agent.astream_events(
            {"messages": [{"role": "user", "content": prompt}]},
            version="v2",
        ):
            kind = event.get("event", "")
            name = event.get("name", "")
            data = event.get("data", {})
            depth = len(event.get("parent_ids", []))

            if kind == "on_chain_start":
                for key, label in SUBAGENT_LABELS.items():
                    if key in name.lower() and key not in seen_agents:
                        seen_agents.add(key)
                        yield _sse({"type": "dispatch", "agent": label})
                        break

            elif kind == "on_chat_model_stream":
                chunk = data.get("chunk")
                if chunk and hasattr(chunk, "content") and chunk.content:
                    text = _extract_text(chunk.content)
                    if text:
                        yield _sse({"type": "token", "text": text})

            elif kind == "on_chat_model_end":
                # Capture complete response; shallowest depth = orchestrator
                output = data.get("output")
                if output is not None:
                    text = _extract_text(getattr(output, "content", "") or "")
                    if text:
                        report_by_depth[depth] = text

            elif kind == "on_tool_start":
                tool_name = name or data.get("name", "")
                tool_input = data.get("input", {})
                if tool_name:
                    preview = ""
                    if isinstance(tool_input, dict):
                        vals = [str(v) for v in tool_input.values() if v]
                        if vals:
                            preview = f" · {vals[0][:60]}"
                    yield _sse({"type": "tool", "text": f"→ {tool_name}{preview}"})

    except Exception as exc:
        yield _sse({"type": "error", "text": str(exc)})
        return

    # Use the shallowest-depth (orchestrator) complete response as the report
    final_report = ""
    if report_by_depth:
        final_report = report_by_depth[min(report_by_depth)]

    findings = _extract_findings(final_report)
    yield _sse({"type": "report", "text": final_report, "findings": findings})
    yield _sse({"type": "done"})


def _extract_findings(report: str) -> list[dict]:
    import re

    findings: list[dict] = []

    # 1. Try bare JSON
    try:
        data = json.loads(report)
        if isinstance(data, list):
            return _finalize(data)
        if isinstance(data, dict):
            for key in ("findings", "vulnerabilities", "results"):
                if isinstance(data.get(key), list):
                    findings.extend(data[key])
        if findings:
            return _finalize(findings)
    except Exception:
        pass

    # 2. Extract JSON blocks embedded in markdown (```json ... ```)
    for block in re.findall(r"```(?:json)?\s*(\{[\s\S]*?\}|\[[\s\S]*?\])\s*```", report):
        try:
            data = json.loads(block)
            items = data if isinstance(data, list) else data.get("findings") or data.get("results") or []
            if isinstance(items, list):
                findings.extend(items)
        except Exception:
            pass
    if findings:
        return _finalize(findings)

    # 3. Parse structured markdown headings
    sev_pattern   = re.compile(r"\b(CRITICAL|HIGH|MEDIUM|LOW|INFO)\b")
    heading_re    = re.compile(r"^#{1,4}\s+")
    chain_re      = re.compile(r"([\w@./:\-]+(?:\s*→\s*[\w@./:\-]+){1,})")
    package_re    = re.compile(r"`([a-z][\w.\-@/]{1,50})`")
    cve_re        = re.compile(r"\b(CVE-\d{4}-\d{4,})\b")

    current: dict | None = None
    body_lines: list[str] = []

    def flush() -> None:
        if current is None:
            return
        body = " ".join(body_lines).strip()
        current["summary"] = body[:300]
        # Dependency / supply-chain chain extraction
        chain_m = chain_re.search(body)
        if chain_m:
            current["dependency_chain"] = chain_m.group(1).strip()
        # CVE
        cve_m = cve_re.search(body)
        if cve_m:
            current["cve_id"] = cve_m.group(1)
        # Package from backtick — use as package if no chain found
        if "dependency_chain" not in current:
            pkg_m = package_re.search(body)
            if pkg_m:
                current["package"] = pkg_m.group(1)
        findings.append(current)

    for line in report.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        sev_m = sev_pattern.search(stripped)
        is_heading = bool(heading_re.match(stripped)) or stripped.startswith("**")
        if sev_m and is_heading:
            flush()
            heading_text = heading_re.sub("", stripped).strip()
            title = re.sub(
                r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO)\s*[—:\-]+\s*", "",
                heading_text, flags=re.IGNORECASE,
            ).strip()
            words = title.split()
            short_type = " ".join(words[:5]) if words else heading_text[:50]
            current = {"severity": sev_m.group(1), "type": short_type}
            body_lines = []
        elif current is not None and not heading_re.match(stripped):
            # Also pick up inline chain from heading itself
            if "dependency_chain" not in current:
                chain_m = chain_re.search(stripped)
                if chain_m:
                    current["dependency_chain"] = chain_m.group(1).strip()
            body_lines.append(stripped)

    flush()
    return _finalize(findings)


def _finalize(findings: list[dict]) -> list[dict]:
    seen: set[str] = set()
    out: list[dict] = []
    for f in findings:
        key = (f.get("severity", ""), f.get("type") or f.get("package") or f.get("summary", ""))[:80]
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out[:50]

    # Deduplicate by summary prefix
    seen: set[str] = set()
    unique: list[dict] = []
    for f in findings:
        key = f.get("summary", "")[:60]
        if key not in seen:
            seen.add(key)
            unique.append(f)

    return unique[:50]


@app.post("/scan")
async def scan(req: ScanRequest):
    return StreamingResponse(
        _stream_scan(req.target, req.mode),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


@app.get("/health")
async def health():
    return {"status": "ok", "agent_ready": _agent is not None}
