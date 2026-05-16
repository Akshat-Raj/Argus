"use client";

import { useEffect, useRef, useState, useCallback } from "react";
import Link from "next/link";
import DependencyGraph from "@/components/DependencyGraph";

const API_SCAN = "/api/scan";

type ScanMode = "repo" | "path" | "custom";

function normalizeTarget(raw: string, mode: ScanMode): string {
  if (mode !== "repo") return raw.trim();
  const t = raw.trim();
  // Strip full GitHub URL → owner/repo
  const m = t.match(/github\.com\/([^/]+\/[^/]+?)(?:\.git)?(?:\/.*)?$/);
  if (m) return m[1];
  return t;
}

const AGENTS = [
  { id: "supply-chain",       label: "α  supply-chain",        desc: "typosquats · install hooks" },
  { id: "cicd-monitoring",    label: "β  cicd-monitoring",      desc: "pipeline secrets · anomalies" },
  { id: "access-control",     label: "γ  access-control",       desc: "IAM · MFA · stale keys" },
  { id: "config-audit",       label: "δ  config-audit",         desc: "Docker · K8s · Terraform" },
  { id: "code-analysis",      label: "ε  code-analysis",        desc: "SAST · Semgrep · Gitleaks" },
  { id: "dependency-security",label: "ζ  dependency-security",  desc: "CVE · SCA · pip/npm audit" },
];

interface Finding {
  severity?: string;
  summary?: string;
  type?: string;
  package?: string;
  file?: string;
  [key: string]: unknown;
}

interface TermLine {
  type: "prompt" | "info" | "ok" | "warn" | "err" | "mute" | "token";
  text: string;
}

function severityColor(sev: string) {
  switch (sev?.toUpperCase()) {
    case "CRITICAL": return "#c08a8a";
    case "HIGH":     return "#d4a76a";
    case "MEDIUM":   return "var(--brass-2)";
    case "LOW":      return "#9bb89b";
    default:         return "var(--mute)";
  }
}

function getLineColor(type: TermLine["type"]) {
  switch (type) {
    case "ok":     return "#9bb89b";
    case "warn":   return "var(--brass-2)";
    case "err":    return "#c08a8a";
    case "prompt": return "var(--brass-2)";
    case "info":   return "var(--paper)";
    default:       return "var(--mute)";
  }
}

export default function ScanPage() {
  const [target, setTarget]   = useState("");
  const [mode, setMode]       = useState<ScanMode>("repo");
  const [scanning, setScanning]   = useState(false);
  const [done, setDone]       = useState(false);
  const [lines, setLines]     = useState<TermLine[]>([]);
  const [findings, setFindings]   = useState<Finding[]>([]);
  const [activeAgents, setActiveAgents] = useState<Set<string>>(new Set());
  const [clock, setClock]     = useState("--:--:--");
  const [tokenBuf, setTokenBuf]   = useState("");
  const [reportText, setReportText] = useState("");

  const termRef   = useRef<HTMLDivElement>(null);
  const abortRef  = useRef<AbortController | null>(null);
  const tokenRef  = useRef("");

  // Clock
  useEffect(() => {
    const id = setInterval(() => {
      const d = new Date();
      const f = (n: number) => String(n).padStart(2, "0");
      setClock(`${f(d.getUTCHours())}:${f(d.getUTCMinutes())}:${f(d.getUTCSeconds())} UTC`);
    }, 1000);
    return () => clearInterval(id);
  }, []);

  // Auto-scroll terminal
  useEffect(() => {
    if (termRef.current) {
      termRef.current.scrollTop = termRef.current.scrollHeight;
    }
  }, [lines, tokenBuf]);

  const pushLine = useCallback((line: TermLine) => {
    setLines((prev) => [...prev, line]);
  }, []);

  const flushToken = useCallback(() => {
    const t = tokenRef.current;
    if (!t) return;
    tokenRef.current = "";
    setTokenBuf("");
    // Split token buffer into lines, push each
    const parts = t.split("\n");
    setLines((prev) => {
      const next = [...prev];
      parts.forEach((p, i) => {
        if (i === 0 && next.length > 0 && next[next.length - 1].type === "token") {
          next[next.length - 1] = { type: "token", text: next[next.length - 1].text + p };
        } else if (p || i < parts.length - 1) {
          next.push({ type: "token", text: p });
        }
      });
      return next;
    });
  }, []);

  const startScan = useCallback(async () => {
    if (!target.trim() || scanning) return;

    const resolvedTarget = normalizeTarget(target, mode);

    // Reset
    setLines([]);
    setFindings([]);
    setActiveAgents(new Set());
    setDone(false);
    tokenRef.current = "";
    setTokenBuf("");
    setReportText("");
    setScanning(true);

    pushLine({ type: "prompt", text: `$ ligma-firewall scan --mode ${mode} ${resolvedTarget}` });
    pushLine({ type: "mute", text: "" });

    const abort = new AbortController();
    abortRef.current = abort;

    let tokenFlushTimer: ReturnType<typeof setTimeout> | null = null;

    function scheduleFlush() {
      if (tokenFlushTimer) clearTimeout(tokenFlushTimer);
      tokenFlushTimer = setTimeout(() => {
        flushToken();
      }, 80);
    }

    try {
      const res = await fetch(API_SCAN, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target: resolvedTarget, mode }),
        signal: abort.signal,
      });

      const reader = res.body!.getReader();
      const decoder = new TextDecoder();
      let buf = "";

      while (true) {
        const { done: doneReading, value } = await reader.read();
        if (doneReading) break;

        buf += decoder.decode(value, { stream: true });
        const parts = buf.split("\n\n");
        buf = parts.pop() ?? "";

        for (const part of parts) {
          const line = part.trim();
          if (!line.startsWith("data: ")) continue;
          let evt: Record<string, unknown>;
          try {
            evt = JSON.parse(line.slice(6));
          } catch {
            continue;
          }

          const type = evt.type as string;

          if (type === "status") {
            flushToken();
            pushLine({ type: "info", text: `  → ${evt.text}` });

          } else if (type === "dispatch") {
            flushToken();
            const agentLabel = evt.agent as string;
            const agentId = AGENTS.find((a) => agentLabel.includes(a.id.split("-")[0]))?.id ?? agentLabel;
            setActiveAgents((prev) => { const s = new Set(Array.from(prev)); s.add(agentLabel as string); return s; });
            pushLine({ type: "ok", text: `  ├─ ${agentLabel} · dispatched` });

          } else if (type === "tool") {
            flushToken();
            pushLine({ type: "mute", text: `  ${evt.text}` });

          } else if (type === "token") {
            tokenRef.current += evt.text as string;
            setTokenBuf(tokenRef.current);
            scheduleFlush();

          } else if (type === "report") {
            if (tokenFlushTimer) clearTimeout(tokenFlushTimer);
            flushToken();
            pushLine({ type: "mute", text: "" });
            pushLine({ type: "ok", text: "  ✓ audit complete · generating report" });
            const rawFindings = (evt.findings as Finding[]) ?? [];
            setFindings(rawFindings);
            setReportText((evt.text as string) ?? "");

          } else if (type === "done") {
            if (tokenFlushTimer) clearTimeout(tokenFlushTimer);
            flushToken();
            pushLine({ type: "mute", text: "" });
            pushLine({ type: "prompt", text: "  ✓ done · report attached below" });
            pushLine({ type: "mute", text: "" });
            pushLine({ type: "prompt", text: "$ _" });
            setDone(true);
            setScanning(false);

          } else if (type === "error") {
            if (tokenFlushTimer) clearTimeout(tokenFlushTimer);
            flushToken();
            pushLine({ type: "err", text: `  ✗ error: ${evt.text}` });
            setScanning(false);
          }
        }
      }
    } catch (err: unknown) {
      if ((err as Error)?.name !== "AbortError") {
        pushLine({ type: "err", text: `  ✗ connection error: ${String(err)}` });
      }
      setScanning(false);
    }
  }, [target, mode, scanning, pushLine, flushToken]);

  const stopScan = useCallback(() => {
    abortRef.current?.abort();
    setScanning(false);
    pushLine({ type: "warn", text: "  ⚑ scan aborted by user" });
  }, [pushLine]);

  const placeholders: Record<ScanMode, string> = {
    repo:   "owner/repo  (e.g. Shrey327/Adaptive-Threat-modeling)",
    path:   "/absolute/path/to/project",
    custom: "Audit the access controls for myorg and check supply chain risks",
  };

  return (
    <div style={{ minHeight: "100vh", background: "var(--ink)", color: "var(--paper)", fontFamily: "var(--sans)" }}>

      {/* Nav */}
      <nav style={{
        position: "fixed", top: 0, left: 0, right: 0, zIndex: 50,
        display: "flex", alignItems: "center", justifyContent: "space-between",
        padding: "20px 40px",
        backdropFilter: "blur(14px)",
        background: "linear-gradient(to bottom, rgba(10,10,10,.92), rgba(10,10,10,.70))",
        borderBottom: "1px solid rgba(255,255,255,.04)",
      }}>
        <Link href="/" style={{ display: "flex", alignItems: "center", gap: "12px", fontFamily: "var(--serif)", fontSize: "22px" }}>
          <span style={{ width: "28px", height: "28px", border: "1px solid var(--paper)", position: "relative", display: "grid", placeItems: "center", flexShrink: 0 }}>
            <span style={{ position: "absolute", inset: "4px", border: "1px solid var(--paper)" }} />
            <span style={{ width: "4px", height: "4px", background: "var(--brass)", position: "relative", zIndex: 1 }} />
          </span>
          <span>Ligma<em style={{ fontStyle: "italic", color: "var(--brass-2)", fontWeight: 400 }}>Firewall</em></span>
        </Link>

        <div style={{ fontFamily: "var(--mono)", fontSize: "11px", letterSpacing: "0.18em", textTransform: "uppercase", color: "var(--mute)" }}>
          Interactive Audit Terminal
        </div>

        <Link href="/" style={{ fontSize: "12px", letterSpacing: "0.14em", textTransform: "uppercase", padding: "10px 18px", border: "1px solid var(--line-2)", color: "var(--mute)", fontFamily: "var(--mono)", transition: "all 0.25s" }}
          onMouseEnter={(e) => { e.currentTarget.style.borderColor = "var(--paper)"; e.currentTarget.style.color = "var(--paper)"; }}
          onMouseLeave={(e) => { e.currentTarget.style.borderColor = "var(--line-2)"; e.currentTarget.style.color = "var(--mute)"; }}>
          ← Back
        </Link>
      </nav>

      <main style={{ maxWidth: "1360px", margin: "0 auto", padding: "120px 40px 80px" }}>

        {/* Header */}
        <div style={{ marginBottom: "48px" }}>
          <div style={{ display: "inline-flex", alignItems: "center", gap: "10px", fontFamily: "var(--mono)", fontSize: "11px", letterSpacing: "0.22em", textTransform: "uppercase", color: "var(--mute)", marginBottom: "16px" }}>
            <span style={{ width: "24px", height: "1px", background: "var(--brass)", display: "inline-block" }} />
            Live Audit Console
          </div>
          <h1 style={{ fontFamily: "var(--serif)", fontWeight: 400, fontSize: "clamp(40px, 5vw, 72px)", lineHeight: 1, letterSpacing: "-0.02em", marginBottom: "16px" }}>
            Run a{" "}
            <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>live scan.</em>
          </h1>
          <p style={{ fontSize: "17px", color: "var(--mute)", lineHeight: 1.55, maxWidth: "560px", fontWeight: 300 }}>
            Six subagents dispatched in parallel. Real findings from live tools — OSV, Semgrep, Gitleaks, Trivy, Checkov.
          </p>
        </div>

        {/* Input panel */}
        <div style={{ border: "1px solid var(--line)", background: "var(--ink-2)", marginBottom: "32px" }}>
          {/* Mode tabs */}
          <div style={{ display: "flex", borderBottom: "1px solid var(--line)", background: "var(--ink-3)" }}>
            {(["repo", "path", "custom"] as ScanMode[]).map((m) => (
              <button
                key={m}
                onClick={() => setMode(m)}
                style={{
                  padding: "14px 24px",
                  fontFamily: "var(--mono)",
                  fontSize: "11px",
                  letterSpacing: "0.16em",
                  textTransform: "uppercase",
                  color: mode === m ? "var(--paper)" : "var(--mute)",
                  borderRight: "1px solid var(--line)",
                  borderBottom: mode === m ? "2px solid var(--brass)" : "2px solid transparent",
                  transition: "color 0.2s",
                  background: "none",
                  cursor: "pointer",
                }}
              >
                {m === "repo" ? "GitHub Repo" : m === "path" ? "Local Path" : "Custom Prompt"}
              </button>
            ))}
          </div>

          {/* Input row */}
          <div style={{ padding: "24px", display: "flex", gap: "12px", alignItems: "stretch" }}>
            <div style={{ flex: 1, position: "relative" }}>
              <span style={{ position: "absolute", left: "16px", top: "50%", transform: "translateY(-50%)", fontFamily: "var(--mono)", fontSize: "13px", color: "var(--mute)", pointerEvents: "none" }}>$</span>
              <input
                value={target}
                onChange={(e) => setTarget(e.target.value)}
                onKeyDown={(e) => { if (e.key === "Enter") startScan(); }}
                placeholder={placeholders[mode]}
                disabled={scanning}
                style={{
                  width: "100%",
                  background: "var(--ink)",
                  border: "1px solid var(--line-2)",
                  color: "var(--paper)",
                  padding: "14px 16px 14px 32px",
                  fontFamily: "var(--mono)",
                  fontSize: "13px",
                  outline: "none",
                  transition: "border-color 0.2s",
                }}
                onFocus={(e) => e.target.style.borderColor = "var(--brass)"}
                onBlur={(e) => e.target.style.borderColor = "var(--line-2)"}
              />
            </div>

            {scanning ? (
              <button
                onClick={stopScan}
                style={{
                  padding: "14px 28px",
                  background: "#7a3a3a",
                  color: "var(--paper)",
                  border: "1px solid #c08a8a",
                  fontFamily: "var(--mono)",
                  fontSize: "12px",
                  letterSpacing: "0.14em",
                  textTransform: "uppercase",
                  cursor: "pointer",
                  whiteSpace: "nowrap",
                }}
              >
                ✗ Abort
              </button>
            ) : (
              <button
                onClick={startScan}
                disabled={!target.trim()}
                style={{
                  padding: "14px 32px",
                  background: target.trim() ? "var(--paper)" : "var(--ink-3)",
                  color: target.trim() ? "var(--ink)" : "var(--mute)",
                  border: "1px solid " + (target.trim() ? "var(--paper)" : "var(--line)"),
                  fontFamily: "var(--mono)",
                  fontSize: "12px",
                  letterSpacing: "0.14em",
                  textTransform: "uppercase",
                  cursor: target.trim() ? "pointer" : "not-allowed",
                  transition: "all 0.25s",
                  whiteSpace: "nowrap",
                }}
              >
                Scan →
              </button>
            )}
          </div>
        </div>

        {/* Agent status strip */}
        <div style={{ display: "flex", gap: "8px", flexWrap: "wrap", marginBottom: "24px" }}>
          {AGENTS.map((a) => {
            const active = Array.from(activeAgents).some((l) => l.includes(a.label.split(" ")[1]));
            return (
              <div
                key={a.id}
                style={{
                  display: "flex",
                  alignItems: "center",
                  gap: "8px",
                  padding: "7px 14px",
                  border: `1px solid ${active ? "var(--brass)" : "var(--line)"}`,
                  background: active ? "rgba(180,140,87,0.06)" : "transparent",
                  fontFamily: "var(--mono)",
                  fontSize: "11px",
                  color: active ? "var(--brass-2)" : "var(--mute)",
                  transition: "all 0.4s",
                }}
              >
                <span
                  style={{
                    width: "6px",
                    height: "6px",
                    borderRadius: "50%",
                    background: active ? "var(--brass)" : "var(--line-2)",
                    flexShrink: 0,
                    animation: active && scanning ? "blink 1.2s infinite" : "none",
                  }}
                />
                {a.label}
              </div>
            );
          })}
        </div>

        {/* Terminal */}
        <div style={{ border: "1px solid var(--line)", background: "var(--ink-2)", fontFamily: "var(--mono)", fontSize: "13px", lineHeight: 1.7, marginBottom: "40px" }}>
          {/* Terminal bar */}
          <div style={{ display: "flex", alignItems: "center", justifyContent: "space-between", padding: "12px 20px", borderBottom: "1px solid var(--line)", background: "var(--ink-3)" }}>
            <div style={{ display: "flex", gap: "8px" }}>
              <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#7a3a3a" }} />
              <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: "#7a6a3a" }} />
              <span style={{ width: "10px", height: "10px", borderRadius: "50%", background: scanning ? "#3a7a4a" : "#3a4a3a" }} />
            </div>
            <div style={{ fontSize: "11px", letterSpacing: "0.18em", textTransform: "uppercase", color: "var(--mute)" }}>
              ligma-firewall · audit.stream
              {scanning && <span style={{ marginLeft: "12px", color: "var(--brass-2)", animation: "blink 1s infinite" }}>● live</span>}
            </div>
            <div style={{ fontSize: "11px", color: "var(--mute)" }}>{clock}</div>
          </div>

          {/* Terminal body */}
          <div
            ref={termRef}
            style={{ padding: "28px 28px 32px", minHeight: "360px", maxHeight: "520px", overflowY: "auto", scrollBehavior: "smooth" }}
          >
            {lines.length === 0 && !scanning && (
              <div style={{ color: "var(--mute)", opacity: 0.5 }}>
                Enter a target above and press Scan →
              </div>
            )}
            {lines.map((ln, i) => (
              <div key={i} style={{ whiteSpace: "pre-wrap", color: getLineColor(ln.type) }}>
                {ln.text}
              </div>
            ))}
            {tokenBuf && (
              <div style={{ whiteSpace: "pre-wrap", color: "var(--paper)" }}>
                {tokenBuf}
                <span className="term-cursor" />
              </div>
            )}
            {scanning && !tokenBuf && (
              <div style={{ color: "var(--mute)" }}>
                <span className="term-cursor" />
              </div>
            )}
          </div>
        </div>

        {/* Findings table */}
        {findings.length > 0 && (
          <div>
            <div style={{ display: "flex", alignItems: "center", gap: "16px", marginBottom: "20px", flexWrap: "wrap" }}>
              <h2 style={{ fontFamily: "var(--serif)", fontWeight: 400, fontSize: "32px", letterSpacing: "-0.02em" }}>
                Findings
              </h2>
              <span style={{ fontFamily: "var(--mono)", fontSize: "11px", color: "var(--mute)", letterSpacing: "0.1em", flex: 1 }}>
                {findings.length} total
              </span>
              <ExportButtons target={target} reportText={reportText} findings={findings} />
            </div>

            <div style={{ border: "1px solid var(--line)", overflow: "hidden" }}>
              <table style={{ width: "100%", borderCollapse: "collapse", fontFamily: "var(--mono)", fontSize: "12px" }}>
                <thead>
                  <tr style={{ borderBottom: "1px solid var(--line)", background: "var(--ink-3)" }}>
                    {["Severity", "Type / Package", "Summary"].map((h) => (
                      <th key={h} style={{ padding: "12px 20px", textAlign: "left", letterSpacing: "0.12em", textTransform: "uppercase", color: "var(--mute)", fontWeight: 400 }}>{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {findings.map((f, i) => (
                    <tr
                      key={i}
                      style={{ borderBottom: "1px solid var(--line)", background: i % 2 === 0 ? "transparent" : "rgba(255,255,255,.015)" }}
                    >
                      <td style={{ padding: "12px 20px", color: severityColor(f.severity ?? ""), whiteSpace: "nowrap" }}>
                        {f.severity ?? "—"}
                      </td>
                      <td style={{ padding: "12px 20px", color: "var(--paper)", whiteSpace: "nowrap" }}>
                        {f.type ?? f.package ?? f.file ?? "—"}
                      </td>
                      <td style={{ padding: "12px 20px", color: "var(--mute)", maxWidth: "600px" }}>
                        {f.summary ?? JSON.stringify(f).slice(0, 120)}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        )}

        {/* Dependency / supply-chain graph */}
        {findings.length > 0 && <DependencyGraph findings={findings} />}

        {/* Empty done state */}
        {done && findings.length === 0 && (
          <div style={{ border: "1px solid var(--line)", padding: "32px 40px", display: "flex", alignItems: "center", justifyContent: "space-between", gap: "24px", flexWrap: "wrap" }}>
            <span style={{ color: "var(--mute)", fontFamily: "var(--mono)", fontSize: "13px" }}>
              ✓ No structured findings extracted — full report in terminal above.
            </span>
            <ExportButtons target={target} reportText={reportText} findings={findings} />
          </div>
        )}
      </main>
    </div>
  );
}

// ---------------------------------------------------------------------------
// Export buttons component
// ---------------------------------------------------------------------------
function ExportButtons({ target, reportText, findings }: {
  target: string;
  reportText: string;
  findings: Finding[];
}) {
  function slug() {
    return (target.replace(/[^a-z0-9]/gi, "-").toLowerCase() || "audit") +
      "-" + new Date().toISOString().slice(0, 10);
  }

  function download(content: string, filename: string, mime: string) {
    const blob = new Blob([content], { type: mime });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    a.click();
    URL.revokeObjectURL(url);
  }

  function exportMarkdown() {
    const lines = [
      `# LigmaFirewall Audit Report`,
      `**Target:** ${target}`,
      `**Date:** ${new Date().toISOString()}`,
      ``,
      reportText || "_No report text available._",
    ];
    if (findings.length > 0) {
      lines.push("", "## Findings", "");
      lines.push("| Severity | Type / Package | Summary |");
      lines.push("|----------|----------------|---------|");
      for (const f of findings) {
        const sev = f.severity ?? "—";
        const type = String(f.type ?? f.package ?? f.file ?? "—");
        const summary = String(f.summary ?? "").replace(/\|/g, "\\|").slice(0, 120);
        lines.push(`| ${sev} | ${type} | ${summary} |`);
      }
    }
    download(lines.join("\n"), `${slug()}.md`, "text/markdown");
  }

  function exportJSON() {
    const payload = {
      target,
      date: new Date().toISOString(),
      total: findings.length,
      findings,
      report: reportText || null,
    };
    download(JSON.stringify(payload, null, 2), `${slug()}.json`, "application/json");
  }

  const btnStyle = (color: string): React.CSSProperties => ({
    padding: "9px 18px",
    fontFamily: "var(--mono)",
    fontSize: "11px",
    letterSpacing: "0.14em",
    textTransform: "uppercase",
    border: `1px solid ${color}`,
    color,
    background: "none",
    cursor: "pointer",
    transition: "all 0.2s",
    display: "inline-flex",
    alignItems: "center",
    gap: "8px",
  });

  return (
    <div style={{ display: "flex", gap: "10px" }}>
      <button
        style={btnStyle("var(--brass-2)")}
        onClick={exportMarkdown}
        onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(212,180,131,0.1)"; }}
        onMouseLeave={(e) => { e.currentTarget.style.background = "none"; }}
      >
        ↓ Markdown
      </button>
      <button
        style={btnStyle("var(--mute)")}
        onClick={exportJSON}
        onMouseEnter={(e) => { e.currentTarget.style.background = "rgba(255,255,255,0.04)"; e.currentTarget.style.color = "var(--paper)"; e.currentTarget.style.borderColor = "var(--paper)"; }}
        onMouseLeave={(e) => { e.currentTarget.style.background = "none"; e.currentTarget.style.color = "var(--mute)"; e.currentTarget.style.borderColor = "var(--mute)"; }}
      >
        ↓ JSON
      </button>
    </div>
  );
}
