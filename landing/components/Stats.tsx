"use client";

import { useEffect, useRef } from "react";

const stats = [
  { value: 6, sup: null, italic: false, label: "Subagents · Coordinated" },
  { value: 42, sup: "k", italic: false, label: "Findings · Per Hour" },
  { value: 99.7, sup: "%", italic: true, label: "Mutating Tools · Filtered" },
  { value: 0, sup: "noise", italic: false, label: "Default Disposition" },
];

export default function Stats() {
  const numsRef = useRef<(HTMLSpanElement | null)[]>([]);

  useEffect(() => {
    const prefersReduced = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;

    async function init() {
      const gsapModule = await import("gsap");
      const { default: gsap } = gsapModule;
      const { ScrollTrigger } = await import("gsap/ScrollTrigger");
      gsap.registerPlugin(ScrollTrigger);

      numsRef.current.forEach((el, i) => {
        if (!el) return;
        const target = stats[i].value;

        if (prefersReduced) {
          el.textContent =
            target % 1 === 0 ? String(target) : target.toFixed(1);
          return;
        }

        ScrollTrigger.create({
          trigger: el,
          start: "top 92%",
          onEnter: () => {
            const obj = { v: 0 };
            gsap.to(obj, {
              v: target,
              duration: 1.6,
              ease: "power2.out",
              onUpdate: () => {
                if (!el) return;
                el.textContent =
                  target % 1 === 0
                    ? Math.round(obj.v).toString()
                    : obj.v.toFixed(1);
              },
            });
          },
        });
      });
    }

    init();
  }, []);

  return (
    <section
      style={{
        background: "var(--paper)",
        color: "var(--ink)",
        padding: "120px 0",
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
          § 04 · Receipts
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "repeat(4, 1fr)",
            marginTop: "48px",
            borderTop: "1px solid rgba(0,0,0,.12)",
          }}
          className="stats-grid"
        >
          {stats.map((s, i) => (
            <div
              key={i}
              style={{
                padding: "48px 32px",
                borderRight:
                  i < stats.length - 1 ? "1px solid rgba(0,0,0,.12)" : "none",
                borderBottom: "1px solid rgba(0,0,0,.12)",
              }}
            >
              <div
                style={{
                  fontFamily: "var(--serif)",
                  fontSize: "96px",
                  lineHeight: 0.95,
                  letterSpacing: "-0.03em",
                  fontWeight: 400,
                }}
              >
                {s.italic ? (
                  <em style={{ fontStyle: "italic", color: "var(--brass)" }}>
                    <span
                      ref={(el) => {
                        numsRef.current[i] = el;
                      }}
                    >
                      0
                    </span>
                  </em>
                ) : (
                  <span
                    ref={(el) => {
                      numsRef.current[i] = el;
                    }}
                  >
                    0
                  </span>
                )}
                {s.sup && (
                  <sup
                    style={{
                      fontSize: "32px",
                      fontStyle: "italic",
                      color: "var(--brass)",
                      verticalAlign: "top",
                      marginLeft: "4px",
                    }}
                  >
                    {s.sup}
                  </sup>
                )}
              </div>
              <div
                style={{
                  marginTop: "14px",
                  fontFamily: "var(--mono)",
                  fontSize: "10px",
                  letterSpacing: "0.2em",
                  textTransform: "uppercase",
                  color: "var(--mute-2)",
                }}
              >
                {s.label}
              </div>
            </div>
          ))}
        </div>
      </div>

      <style>{`
        @media (max-width: 980px) {
          .stats-grid {
            grid-template-columns: repeat(2, 1fr) !important;
          }
        }
      `}</style>
    </section>
  );
}
