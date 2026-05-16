"use client";

import { useEffect, useRef, useState } from "react";

const termLines = [
  { t: "prompt", s: "$ ", c: "orchestrator.run --target ./service-platform --mcp auto" },
  { t: "mute", s: "  → loading subagents from agent.py · 6 found" },
  { t: "mute", s: "  → tools/mcp.py · 3 servers configured · mutating tools filtered (37 dropped)" },
  { t: "mute", s: "" },
  { t: "warn", s: "  ┌──── parallel dispatch ────┐" },
  { t: "ok", s: "  ├─ α  supply-chain         · scanning vendored packages (1,204)" },
  { t: "ok", s: "  ├─ β  cicd-monitoring      · 14 workflows · 2 runners · 90d window" },
  { t: "ok", s: "  ├─ γ  access-control       · iam graph · 3 accounts · 412 principals" },
  { t: "ok", s: "  ├─ δ  config-audit         · 38 manifests · CIS-K8s v1.9 · checkov" },
  { t: "ok", s: "  ├─ ε  code-analysis        · 41,802 LOC · taint-flow on entrypoints" },
  { t: "ok", s: "  └─ ζ  dependency-security  · npm audit · pypi-safety · sbom-merge" },
  { t: "mute", s: "" },
  { t: "err", s: "  ⚑ α: typosquat — `reqests` ≠ `requests` · post-install hook present" },
  { t: "err", s: "  ⚑ α: outbound POST to 185.x.x.x on import · package: helper-utils-pro" },
  { t: "warn", s: "  ⚑ β: secret echoed to GHA log · workflow: deploy-prod.yml#94" },
  { t: "warn", s: "  ⚑ γ: service-account key age 412d · scope `*` · principal: ci-deployer" },
  { t: "warn", s: "  ⚑ δ: container UID 0 · pod: prod-api · ns: payments" },
  { t: "warn", s: "  ⚑ ε: SQL concatenation · /billing/invoice.py:147 · taint reaches db.exec" },
  { t: "warn", s: "  ⚑ ζ: 7 CVE · CVSS ≥ 7.4 · transitive · upgrade path available" },
  { t: "mute", s: "" },
  { t: "prompt", s: "  ✓ ", c: "reconciled · 7 findings · severity-merged · provenance attached" },
  { t: "prompt", s: "  ✓ ", c: "report → ./out/audit-2026-04-30.md" },
  { t: "mute", s: "" },
  { t: "prompt", s: "$ ", c: "_", cursor: true },
];

function getLineColor(t: string) {
  switch (t) {
    case "prompt": return "var(--brass-2)";
    case "ok": return "#9bb89b";
    case "warn": return "var(--brass-2)";
    case "err": return "#c08a8a";
    default: return "var(--mute)";
  }
}

export default function Terminal() {
  const bodyRef = useRef<HTMLDivElement>(null);
  const [clock, setClock] = useState("--:--:--");
  const hasRunRef = useRef(false);

  // Clock
  useEffect(() => {
    function tick() {
      const d = new Date();
      const f = (n: number) => String(n).padStart(2, "0");
      setClock(`${f(d.getUTCHours())}:${f(d.getUTCMinutes())}:${f(d.getUTCSeconds())} UTC`);
    }
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  // Terminal type-on
  useEffect(() => {
    const prefersReduced = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;

    async function init() {
      const { ScrollTrigger } = await import("gsap/ScrollTrigger");
      const gsapModule = await import("gsap");
      const { default: gsap } = gsapModule;
      gsap.registerPlugin(ScrollTrigger);

      function run() {
        if (hasRunRef.current || !bodyRef.current) return;
        hasRunRef.current = true;

        if (prefersReduced) {
          // Show all lines immediately
          termLines.forEach((ln) => {
            if (!bodyRef.current) return;
            const div = document.createElement("div");
            div.style.whiteSpace = "pre-wrap";
            const prefix = document.createElement("span");
            prefix.style.color = getLineColor(ln.t);
            prefix.textContent = ln.s;
            div.appendChild(prefix);
            if (ln.c) {
              const cmd = document.createElement("span");
              cmd.style.color = "var(--paper)";
              cmd.textContent = ln.c;
              div.appendChild(cmd);
            }
            if (ln.cursor) {
              const cur = document.createElement("span");
              cur.className = "term-cursor";
              div.appendChild(cur);
            }
            bodyRef.current.appendChild(div);
          });
          return;
        }

        let i = 0;
        function step() {
          if (i >= termLines.length || !bodyRef.current) return;
          const ln = termLines[i++];
          const div = document.createElement("div");
          div.style.whiteSpace = "pre-wrap";
          const prefix = document.createElement("span");
          prefix.style.color = getLineColor(ln.t);
          prefix.textContent = ln.s;
          div.appendChild(prefix);
          if (ln.c && !ln.cursor) {
            const cmd = document.createElement("span");
            cmd.style.color = "var(--paper)";
            cmd.textContent = ln.c;
            div.appendChild(cmd);
          }
          if (ln.cursor) {
            const cur = document.createElement("span");
            cur.className = "term-cursor";
            div.appendChild(cur);
          }
          bodyRef.current.appendChild(div);
          const delay = ln.s.length > 0 ? 90 + Math.random() * 120 : 60;
          setTimeout(step, delay);
        }
        step();
      }

      ScrollTrigger.create({
        trigger: "#demo .terminal-block",
        start: "top 75%",
        onEnter: run,
      });
    }

    init();
  }, []);

  return (
    <section
      id="demo"
      style={{ padding: "140px 0", position: "relative" }}
    >
      <div
        style={{
          maxWidth: "1360px",
          margin: "0 auto",
          padding: "0 40px",
        }}
      >
        <div
          className="reveal"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "10px",
            fontFamily: "var(--mono)",
            fontSize: "11px",
            letterSpacing: "0.22em",
            textTransform: "uppercase",
            color: "var(--mute)",
          }}
        >
          <span
            style={{
              width: "24px",
              height: "1px",
              background: "var(--brass)",
              display: "inline-block",
            }}
          />
          § 03 · The Run
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 2fr",
            gap: "80px",
            marginTop: "24px",
            marginBottom: "80px",
            alignItems: "end",
          }}
          className="terminal-section-head"
        >
          <h2
            className="reveal"
            style={{
              fontSize: "clamp(48px, 6vw, 88px)",
              fontFamily: "var(--serif)",
              fontWeight: 400,
              lineHeight: 1,
              letterSpacing: "-0.02em",
            }}
          >
            A briefing in{" "}
            <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>
              real time.
            </em>
          </h2>
          <p
            className="reveal"
            style={{
              fontSize: "18px",
              lineHeight: 1.55,
              color: "var(--mute)",
              maxWidth: "520px",
              fontWeight: 300,
            }}
          >
            Below: a representative orchestrator transcript. Subagents are
            dispatched in parallel, findings are merged with provenance, and
            severity is reconciled before report. Local tools first; MCP tools
            when available.
          </p>
        </div>

        <div
          className="terminal-block reveal"
          style={{
            border: "1px solid var(--line)",
            background: "var(--ink-2)",
            fontFamily: "var(--mono)",
            fontSize: "13px",
            lineHeight: 1.7,
            color: "var(--paper)",
            marginTop: "40px",
          }}
        >
          <div
            style={{
              display: "flex",
              alignItems: "center",
              justifyContent: "space-between",
              padding: "14px 20px",
              borderBottom: "1px solid var(--line)",
              background: "var(--ink-3)",
            }}
          >
            <div style={{ display: "flex", gap: "8px" }}>
              <span
                style={{
                  width: "10px",
                  height: "10px",
                  borderRadius: "50%",
                  background: "#7a3a3a",
                }}
              />
              <span
                style={{
                  width: "10px",
                  height: "10px",
                  borderRadius: "50%",
                  background: "#7a6a3a",
                }}
              />
              <span
                style={{
                  width: "10px",
                  height: "10px",
                  borderRadius: "50%",
                  background: "#3a7a4a",
                }}
              />
            </div>
            <div
              style={{
                fontSize: "11px",
                letterSpacing: "0.18em",
                textTransform: "uppercase",
                color: "var(--mute)",
              }}
            >
              ligma-firewall · orchestrator.run()
            </div>
            <div
              style={{ fontSize: "11px", color: "var(--mute)" }}
            >
              {clock}
            </div>
          </div>
          <div
            ref={bodyRef}
            style={{ padding: "28px 28px 32px", minHeight: "440px" }}
          />
        </div>
      </div>

      <style>{`
        @media (max-width: 980px) {
          .terminal-section-head {
            grid-template-columns: 1fr !important;
            gap: 20px !important;
          }
        }
      `}</style>
    </section>
  );
}
