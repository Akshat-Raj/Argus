"use client";

import { useEffect, useRef } from "react";

const subagents = [
  {
    id: "α · 01",
    name: "supply-",
    italic: "chain",
    desc: "Typosquats, install hooks, exfil patterns.",
  },
  {
    id: "β · 02",
    name: "cicd-",
    italic: "monitoring",
    desc: "GHA, Jenkins, secret leakage in logs.",
  },
  {
    id: "γ · 03",
    name: "access-",
    italic: "control",
    desc: "IAM, MFA, stale keys, priv-esc.",
  },
  {
    id: "δ · 04",
    name: "config-",
    italic: "audit",
    desc: "Docker, K8s, Terraform, CIS.",
  },
  {
    id: "ε · 05",
    name: "code-",
    italic: "analysis",
    desc: "SAST, secrets, injection, taint.",
  },
  {
    id: "ζ · 06",
    name: "dependency-",
    italic: "security",
    desc: "CVE, npm/PyPI, SBOM, drift.",
  },
];

export default function Architecture() {
  const diagramRef = useRef<HTMLDivElement>(null);
  const pathsRef = useRef<SVGPathElement[]>([]);

  useEffect(() => {
    const prefersReduced = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;

    async function init() {
      const gsapModule = await import("gsap");
      const { default: gsap } = gsapModule;
      const { ScrollTrigger } = await import("gsap/ScrollTrigger");
      gsap.registerPlugin(ScrollTrigger);

      if (prefersReduced) return;

      pathsRef.current.forEach((p) => {
        if (!p) return;
        const len = p.getTotalLength();
        p.style.strokeDasharray = String(len);
        p.style.strokeDashoffset = String(len);
      });

      ScrollTrigger.create({
        trigger: diagramRef.current,
        start: "top 70%",
        onEnter: () => {
          pathsRef.current.forEach((p, i) => {
            if (!p) return;
            gsap.to(p, {
              strokeDashoffset: 0,
              duration: 1.2,
              delay: i * 0.08,
              ease: "power2.out",
            });
          });
        },
      });
    }

    init();
  }, []);

  return (
    <section
      id="architecture"
      style={{
        background: "var(--paper)",
        color: "var(--ink)",
        padding: "140px 0",
        position: "relative",
      }}
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
            color: "var(--mute-2)",
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
          § 02 · The Counsel
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
          className="arch-section-head"
        >
          <h2
            className="reveal"
            style={{
              fontSize: "clamp(48px, 6vw, 88px)",
              fontFamily: "var(--serif)",
              fontWeight: 400,
              lineHeight: 1,
              letterSpacing: "-0.02em",
              color: "var(--ink)",
            }}
          >
            One{" "}
            <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>
              orchestrator.
            </em>
            <br />
            Six specialists.
          </h2>
          <p
            className="reveal"
            style={{
              fontSize: "18px",
              lineHeight: 1.55,
              color: "var(--mute-2)",
              maxWidth: "520px",
              fontWeight: 300,
            }}
          >
            <code
              style={{
                fontFamily: "var(--mono)",
                fontSize: "13px",
                background: "rgba(0,0,0,.06)",
                padding: "2px 8px",
              }}
            >
              agent.py
            </code>{" "}
            builds a single DeepAgents orchestrator that delegates to six
            subagents. Local tools live under{" "}
            <code
              style={{
                fontFamily: "var(--mono)",
                fontSize: "13px",
                background: "rgba(0,0,0,.06)",
                padding: "2px 8px",
              }}
            >
              tools/
            </code>{" "}
            with deterministic demo behavior.{" "}
            <code
              style={{
                fontFamily: "var(--mono)",
                fontSize: "13px",
                background: "rgba(0,0,0,.06)",
                padding: "2px 8px",
              }}
            >
              tools/mcp.py
            </code>{" "}
            optionally loads real MCP tools at startup — mutating tools filtered
            by default.
          </p>
        </div>

        <div
          ref={diagramRef}
          className="reveal"
          style={{
            marginTop: "60px",
            border: "1px solid rgba(0,0,0,.12)",
            background: "var(--paper-2)",
            padding: "60px",
            position: "relative",
          }}
        >
          {/* Corner brackets */}
          {[
            { top: "-1px", left: "-1px", borderRight: "0", borderBottom: "0" },
            { top: "-1px", right: "-1px", borderLeft: "0", borderBottom: "0" },
            { bottom: "-1px", left: "-1px", borderRight: "0", borderTop: "0" },
            { bottom: "-1px", right: "-1px", borderLeft: "0", borderTop: "0" },
          ].map((style, i) => (
            <span
              key={i}
              style={{
                position: "absolute",
                width: "14px",
                height: "14px",
                border: "1px solid var(--ink)",
                ...style,
              }}
            />
          ))}

          {/* Orchestrator pill */}
          <div
            style={{
              margin: "0 auto",
              width: "fit-content",
              padding: "18px 40px",
              border: "1px solid var(--ink)",
              background: "var(--ink)",
              color: "var(--paper)",
              fontFamily: "var(--mono)",
              fontSize: "12px",
              letterSpacing: "0.18em",
              textTransform: "uppercase",
              display: "flex",
              alignItems: "center",
              gap: "14px",
            }}
          >
            <span
              className="pulse-dot"
              style={{
                width: "8px",
                height: "8px",
                background: "var(--brass)",
                borderRadius: "50%",
                flexShrink: 0,
              }}
            />
            DeepAgents Orchestrator · agent.py
          </div>

          {/* SVG connector lines */}
          <div style={{ height: "80px", position: "relative", width: "100%" }}>
            <svg
              width="100%"
              height="100%"
              viewBox="0 0 1200 80"
              preserveAspectRatio="none"
              style={{ overflow: "visible" }}
            >
              {[
                "M 600 0 L 600 30 L 100 30 L 100 80",
                "M 600 0 L 600 30 L 300 30 L 300 80",
                "M 600 0 L 600 30 L 500 30 L 500 80",
                "M 600 0 L 600 30 L 700 30 L 700 80",
                "M 600 0 L 600 30 L 900 30 L 900 80",
                "M 600 0 L 600 30 L 1100 30 L 1100 80",
              ].map((d, i) => (
                <path
                  key={i}
                  d={d}
                  stroke="var(--ink)"
                  strokeWidth="1"
                  fill="none"
                  strokeDasharray="3 4"
                  ref={(el) => {
                    if (el) pathsRef.current[i] = el;
                  }}
                />
              ))}
            </svg>
          </div>

          {/* Subagent grid */}
          <div
            style={{
              display: "grid",
              gridTemplateColumns: "repeat(6, 1fr)",
              gap: "1px",
              background: "var(--ink)",
              border: "1px solid var(--ink)",
            }}
            className="arch-subagents"
          >
            {subagents.map((a) => (
              <div
                key={a.id}
                style={{
                  background: "var(--paper-2)",
                  padding: "24px 18px",
                  display: "flex",
                  flexDirection: "column",
                  gap: "10px",
                  minHeight: "160px",
                  transition: "background 0.3s",
                  cursor: "default",
                }}
                onMouseEnter={(e) =>
                  (e.currentTarget.style.background = "var(--paper)")
                }
                onMouseLeave={(e) =>
                  (e.currentTarget.style.background = "var(--paper-2)")
                }
              >
                <span
                  style={{
                    fontFamily: "var(--mono)",
                    fontSize: "10px",
                    letterSpacing: "0.2em",
                    color: "var(--brass)",
                  }}
                >
                  {a.id}
                </span>
                <span
                  style={{
                    fontFamily: "var(--serif)",
                    fontSize: "22px",
                    lineHeight: 1.05,
                    letterSpacing: "-0.01em",
                  }}
                >
                  {a.name}
                  <em style={{ fontStyle: "italic" }}>{a.italic}</em>
                </span>
                <span
                  style={{
                    fontSize: "12px",
                    color: "var(--mute-2)",
                    marginTop: "auto",
                    lineHeight: 1.4,
                  }}
                >
                  {a.desc}
                </span>
              </div>
            ))}
          </div>
        </div>
      </div>

      <style>{`
        @media (max-width: 980px) {
          .arch-section-head {
            grid-template-columns: 1fr !important;
            gap: 20px !important;
          }
          .arch-subagents {
            grid-template-columns: repeat(2, 1fr) !important;
          }
        }
      `}</style>
    </section>
  );
}
