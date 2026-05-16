"use client";

import { useEffect, useRef, useState, useCallback } from "react";

const agents = [
  {
    id: "01",
    glyph: "α",
    titlePrefix: "supply-",
    titleSuffix: "chain",
    body: "Hunts typosquats, malicious post-install hooks, import-time secret harvesting, and outbound exfil patterns in vendored or installed packages. The first line of defense before anything reaches your build.",
    tools: ["typosquat-scan", "post-install", "exfil-trace", "vendor-diff"],
  },
  {
    id: "02",
    glyph: "β",
    titlePrefix: "cicd-",
    titleSuffix: "monitoring",
    body: "Inspects GitHub Actions and Jenkins workflows for unsafe step composition, suspicious build activity, and possible secret exposure in logs. Tracks who pushed what, when, and from where.",
    tools: ["gha-lint", "jenkins-audit", "log-redact", "runner-trust"],
  },
  {
    id: "03",
    glyph: "γ",
    titlePrefix: "access-",
    titleSuffix: "control",
    body: "Reviews IAM policies for over-privileged principals, MFA enforcement, stale service-account keys, and crossed account boundaries. Least privilege, restored — without a thirty-page ticket.",
    tools: ["iam-graph", "mfa-check", "key-age", "priv-esc"],
  },
  {
    id: "04",
    glyph: "δ",
    titlePrefix: "config-",
    titleSuffix: "audit",
    body: "Sweeps Dockerfiles, Kubernetes manifests, and Terraform with CIS Benchmark and Checkov-style rules. Catches the misconfiguration before the misconfiguration catches you.",
    tools: ["cis-bench", "checkov", "k8s-policy", "tf-plan"],
  },
  {
    id: "05",
    glyph: "ε",
    titlePrefix: "code-",
    titleSuffix: "analysis",
    body: "SAST-grade review for hardcoded secrets, injection paths, deserialization gadgets, and quietly insecure coding patterns. Reads your repo the way an attacker reads your repo.",
    tools: ["sast-core", "secret-grep", "injection", "taint-flow"],
  },
  {
    id: "06",
    glyph: "ζ",
    titlePrefix: "dependency-",
    titleSuffix: "security",
    body: "SCA across npm audit, PyPI safety, and SBOM-style review. CVE matching, transitive risk surfacing, and version drift — explained in language a release manager will actually read.",
    tools: ["cve-match", "npm-audit", "pypi-safety", "sbom"],
  },
];

export default function AgentsCarousel() {
  const [idx, setIdx] = useState(0);
  const trackRef = useRef<HTMLDivElement>(null);
  const railRef = useRef<HTMLDivElement>(null);
  const timerRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const total = agents.length;

  const go = useCallback(
    (n: number) => {
      const next = ((n % total) + total) % total;
      setIdx(next);
    },
    [total]
  );

  // Apply transform
  useEffect(() => {
    if (!trackRef.current) return;
    const card = trackRef.current.children[0] as HTMLElement;
    if (!card) return;
    const w = card.getBoundingClientRect().width;
    trackRef.current.style.transform = `translateX(${-idx * w}px)`;
  }, [idx]);

  // Recompute on resize
  useEffect(() => {
    const onResize = () => {
      if (!trackRef.current) return;
      const card = trackRef.current.children[0] as HTMLElement;
      if (!card) return;
      const w = card.getBoundingClientRect().width;
      trackRef.current.style.transform = `translateX(${-idx * w}px)`;
    };
    window.addEventListener("resize", onResize);
    return () => window.removeEventListener("resize", onResize);
  }, [idx]);

  // Auto-advance
  const startTimer = useCallback(() => {
    timerRef.current = setInterval(() => {
      setIdx((prev) => ((prev + 1) % total));
    }, 5200);
  }, [total]);

  const stopTimer = useCallback(() => {
    if (timerRef.current) clearInterval(timerRef.current);
  }, []);

  useEffect(() => {
    startTimer();
    return () => stopTimer();
  }, [startTimer, stopTimer]);

  const agent = agents[idx];

  return (
    <section id="agents" style={{ position: "relative" }}>
      <div
        style={{
          display: "flex",
          justifyContent: "space-between",
          alignItems: "center",
          padding: "32px 40px",
          borderBottom: "1px solid var(--line)",
          borderTop: "1px solid var(--line)",
        }}
      >
        <div
          style={{
            fontFamily: "var(--mono)",
            fontSize: "12px",
            letterSpacing: "0.16em",
            color: "var(--mute)",
          }}
        >
          <strong style={{ color: "var(--paper)", fontWeight: 500 }}>
            {String(idx + 1).padStart(2, "0")}
          </strong>{" "}
          &nbsp;/&nbsp; 06 &nbsp;·&nbsp;{" "}
          <span>{agent.titlePrefix + agent.titleSuffix}</span>
        </div>
        <div style={{ display: "flex" }}>
          <button
            onClick={() => go(idx - 1)}
            aria-label="previous"
            style={{
              width: "56px",
              height: "56px",
              border: "1px solid var(--line-2)",
              borderRight: "0",
              display: "grid",
              placeItems: "center",
              color: "var(--paper)",
              transition: "background 0.25s, color 0.25s, border-color 0.25s",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "var(--paper)";
              e.currentTarget.style.color = "var(--ink)";
              e.currentTarget.style.borderColor = "var(--paper)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "transparent";
              e.currentTarget.style.color = "var(--paper)";
              e.currentTarget.style.borderColor = "var(--line-2)";
            }}
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            >
              <path d="M15 6l-6 6 6 6" />
            </svg>
          </button>
          <button
            onClick={() => go(idx + 1)}
            aria-label="next"
            style={{
              width: "56px",
              height: "56px",
              border: "1px solid var(--line-2)",
              display: "grid",
              placeItems: "center",
              color: "var(--paper)",
              transition: "background 0.25s, color 0.25s, border-color 0.25s",
            }}
            onMouseEnter={(e) => {
              e.currentTarget.style.background = "var(--paper)";
              e.currentTarget.style.color = "var(--ink)";
              e.currentTarget.style.borderColor = "var(--paper)";
            }}
            onMouseLeave={(e) => {
              e.currentTarget.style.background = "transparent";
              e.currentTarget.style.color = "var(--paper)";
              e.currentTarget.style.borderColor = "var(--line-2)";
            }}
          >
            <svg
              width="16"
              height="16"
              viewBox="0 0 24 24"
              fill="none"
              stroke="currentColor"
              strokeWidth="1.5"
            >
              <path d="M9 6l6 6-6 6" />
            </svg>
          </button>
        </div>
      </div>

      <div
        ref={railRef}
        style={{
          display: "flex",
          overflow: "hidden",
          borderBottom: "1px solid var(--line)",
        }}
        onMouseEnter={stopTimer}
        onMouseLeave={startTimer}
      >
        <div
          ref={trackRef}
          style={{
            display: "flex",
            transition: "transform 0.8s cubic-bezier(.2,.7,.2,1)",
            willChange: "transform",
          }}
        >
          {agents.map((a, i) => (
            <article
              key={a.id}
              style={{
                flex: "0 0 50%",
                minWidth: "50%",
                padding: "60px",
                borderRight: "1px solid var(--line)",
                display: "grid",
                gridTemplateRows: "auto 1fr auto",
                gap: "40px",
                minHeight: "560px",
                position: "relative",
              }}
              className="agent-card-item"
            >
              <div
                style={{
                  display: "flex",
                  justifyContent: "space-between",
                  alignItems: "flex-start",
                }}
              >
                <div
                  style={{
                    fontFamily: "var(--mono)",
                    fontSize: "11px",
                    letterSpacing: "0.2em",
                    color: "var(--mute)",
                  }}
                >
                  SUBAGENT ·{" "}
                  <strong
                    style={{
                      color: "var(--brass-2)",
                      fontWeight: 500,
                    }}
                  >
                    {a.id} / 06
                  </strong>
                </div>
                <div
                  style={{
                    fontFamily: "var(--serif)",
                    fontSize: "64px",
                    lineHeight: 1,
                    fontStyle: "italic",
                    color: "var(--paper)",
                  }}
                >
                  {a.glyph}
                </div>
              </div>

              <div>
                <h3
                  style={{
                    fontFamily: "var(--serif)",
                    fontSize: "48px",
                    lineHeight: 1,
                    letterSpacing: "-0.02em",
                    fontWeight: 400,
                  }}
                >
                  {a.titlePrefix}
                  <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>
                    {a.titleSuffix}
                  </em>
                </h3>
                <p
                  style={{
                    marginTop: "24px",
                    fontSize: "15px",
                    lineHeight: 1.55,
                    color: "var(--mute)",
                    maxWidth: "440px",
                    fontWeight: 300,
                  }}
                >
                  {a.body}
                </p>
              </div>

              <div style={{ display: "flex", flexWrap: "wrap", gap: "8px" }}>
                {a.tools.map((tool) => (
                  <span
                    key={tool}
                    style={{
                      fontFamily: "var(--mono)",
                      fontSize: "10px",
                      letterSpacing: "0.12em",
                      textTransform: "uppercase",
                      padding: "6px 10px",
                      border: "1px solid var(--line-2)",
                      color: "var(--paper)",
                    }}
                  >
                    {tool}
                  </span>
                ))}
              </div>
            </article>
          ))}
        </div>
      </div>

      <style>{`
        @media (max-width: 980px) {
          .agent-card-item {
            flex: 0 0 100% !important;
            min-width: 100% !important;
            padding: 40px !important;
          }
        }
      `}</style>
    </section>
  );
}
