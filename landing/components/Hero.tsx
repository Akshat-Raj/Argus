"use client";

import { useEffect, useRef } from "react";

export default function Hero() {
  const headlineRef = useRef<HTMLHeadingElement>(null);
  const gridRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const prefersReduced = window.matchMedia(
      "(prefers-reduced-motion: reduce)"
    ).matches;

    async function init() {
      const gsapModule = await import("gsap");
      const { default: gsap } = gsapModule;
      const { ScrollTrigger } = await import("gsap/ScrollTrigger");
      gsap.registerPlugin(ScrollTrigger);

      if (!prefersReduced && headlineRef.current) {
        const spans = headlineRef.current.querySelectorAll(".line span");
        gsap.set(spans, { yPercent: 110, opacity: 0 });
        gsap.to(spans, {
          yPercent: 0,
          opacity: 1,
          duration: 1.1,
          ease: "power3.out",
          stagger: 0.12,
          delay: 0.15,
        });
      }

      if (!prefersReduced && gridRef.current) {
        gsap.to(gridRef.current, {
          backgroundPosition: "0 -160px",
          ease: "none",
          scrollTrigger: {
            trigger: ".hero-section",
            start: "top top",
            end: "bottom top",
            scrub: true,
          },
        });
      }

      // Generic reveals
      document.querySelectorAll(".reveal").forEach((el) => {
        if (prefersReduced) {
          el.classList.add("in");
          return;
        }
        ScrollTrigger.create({
          trigger: el,
          start: "top 88%",
          onEnter: () => el.classList.add("in"),
        });
      });
    }

    init();
  }, []);

  return (
    <section
      className="hero-section"
      style={{
        position: "relative",
        minHeight: "100vh",
        padding: "160px 0 80px",
        display: "flex",
        flexDirection: "column",
        justifyContent: "space-between",
        overflow: "hidden",
      }}
    >
      <div
        ref={gridRef}
        style={{
          position: "absolute",
          inset: 0,
          pointerEvents: "none",
          opacity: 0.5,
          backgroundImage:
            "linear-gradient(to right, rgba(255,255,255,.03) 1px, transparent 1px), linear-gradient(to bottom, rgba(255,255,255,.03) 1px, transparent 1px)",
          backgroundSize: "80px 80px",
          maskImage:
            "radial-gradient(ellipse at center, #000 30%, transparent 75%)",
        }}
      />

      <div
        style={{
          position: "absolute",
          right: "40px",
          top: "50%",
          transform: "translateY(-50%)",
          writingMode: "vertical-rl",
          fontFamily: "var(--mono)",
          fontSize: "10px",
          letterSpacing: "0.4em",
          textTransform: "uppercase",
          color: "var(--mute)",
          display: "flex",
          alignItems: "center",
          gap: "18px",
        }}
      >
        <span
          className="hero-status-dot"
          style={{
            width: "6px",
            height: "6px",
            borderRadius: "50%",
            background: "var(--brass)",
            flexShrink: 0,
          }}
        />
        SYS · ORCHESTRATOR ONLINE · v0.4.2
      </div>

      <div
        style={{
          maxWidth: "1360px",
          margin: "0 auto",
          padding: "0 40px",
          width: "100%",
        }}
      >
        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-start",
            fontFamily: "var(--mono)",
            fontSize: "11px",
            letterSpacing: "0.18em",
            textTransform: "uppercase",
            color: "var(--mute)",
            marginBottom: "80px",
          }}
        >
          <div>
            EST. 2026
            <span
              style={{
                display: "block",
                color: "var(--paper)",
                marginTop: "6px",
                letterSpacing: "0.04em",
              }}
            >
              Software Supply Chain
            </span>
          </div>
          <div>
            VOL. I, NO. 01
            <span
              style={{
                display: "block",
                color: "var(--paper)",
                marginTop: "6px",
                letterSpacing: "0.04em",
              }}
            >
              The Quarterly Audit
            </span>
          </div>
          <div style={{ textAlign: "right" }}>
            CLASSIFIED
            <span
              style={{
                display: "block",
                color: "var(--paper)",
                marginTop: "6px",
                letterSpacing: "0.04em",
              }}
            >
              For DevSecOps Counsel
            </span>
          </div>
        </div>

        <h1
          ref={headlineRef}
          style={{
            fontFamily: "var(--serif)",
            fontWeight: 400,
            lineHeight: 0.95,
            letterSpacing: "-0.02em",
            fontSize: "clamp(64px, 10vw, 168px)",
            margin: "0 -2px",
          }}
        >
          <span className="line" style={{ display: "block", overflow: "hidden" }}>
            <span style={{ display: "inline-block" }}>Adversaries</span>
          </span>
          <span className="line" style={{ display: "block", overflow: "hidden" }}>
            <span style={{ display: "inline-block" }}>
              don&apos;t{" "}
              <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>
                knock.
              </em>
            </span>
          </span>
          <span className="line" style={{ display: "block", overflow: "hidden" }}>
            <span style={{ display: "inline-block" }}>Neither do we.</span>
          </span>
        </h1>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1.4fr 1fr",
            gap: "80px",
            alignItems: "end",
            marginTop: "60px",
            paddingTop: "40px",
            borderTop: "1px solid var(--line)",
          }}
          className="hero-tail"
        >
          <p
            className="reveal"
            style={{
              fontSize: "22px",
              lineHeight: 1.45,
              color: "var(--paper)",
              maxWidth: "560px",
              fontWeight: 300,
            }}
          >
            <strong
              style={{
                color: "var(--brass-2)",
                fontWeight: 500,
                fontStyle: "italic",
                fontFamily: "var(--serif)",
                fontSize: "24px",
              }}
            >
              LigmaFirewall
            </strong>{" "}
            is agentic security orchestration for the modern software supply
            chain — six specialized subagents auditing your CI/CD, IAM,
            infrastructure, code, and dependencies in concert. One orchestrator.
            No noise. No mercy.
          </p>
          <div
            className="reveal"
            style={{
              display: "flex",
              gap: "14px",
              alignItems: "center",
              justifyContent: "flex-end",
            }}
          >
            <a
              href="#demo"
              style={{
                fontSize: "13px",
                letterSpacing: "0.16em",
                textTransform: "uppercase",
                padding: "18px 28px",
                display: "inline-flex",
                alignItems: "center",
                gap: "14px",
                border: "1px solid var(--line-2)",
                color: "var(--paper)",
                transition: "all 0.3s cubic-bezier(.2,.7,.2,1)",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.borderColor = "var(--paper)";
                const arrow = e.currentTarget.querySelector(".arrow") as HTMLElement;
                if (arrow) arrow.style.transform = "translateX(6px)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.borderColor = "var(--line-2)";
                const arrow = e.currentTarget.querySelector(".arrow") as HTMLElement;
                if (arrow) arrow.style.transform = "translateX(0)";
              }}
            >
              Watch a run{" "}
              <span
                className="arrow"
                style={{
                  display: "inline-block",
                  transition: "transform 0.3s",
                }}
              >
                →
              </span>
            </a>
            <a
              href="/scan"
              style={{
                fontSize: "13px",
                letterSpacing: "0.16em",
                textTransform: "uppercase",
                padding: "18px 28px",
                display: "inline-flex",
                alignItems: "center",
                gap: "14px",
                background: "var(--paper)",
                color: "var(--ink)",
                transition: "all 0.3s cubic-bezier(.2,.7,.2,1)",
              }}
              onMouseEnter={(e) => {
                e.currentTarget.style.background = "var(--brass-2)";
                const arrow = e.currentTarget.querySelector(".arrow") as HTMLElement;
                if (arrow) arrow.style.transform = "translateX(6px)";
              }}
              onMouseLeave={(e) => {
                e.currentTarget.style.background = "var(--paper)";
                const arrow = e.currentTarget.querySelector(".arrow") as HTMLElement;
                if (arrow) arrow.style.transform = "translateX(0)";
              }}
            >
              Run a live scan{" "}
              <span
                className="arrow"
                style={{
                  display: "inline-block",
                  transition: "transform 0.3s",
                }}
              >
                →
              </span>
            </a>
          </div>
        </div>
      </div>

      <style>{`
        @media (max-width: 980px) {
          .hero-tail {
            grid-template-columns: 1fr !important;
            gap: 40px !important;
          }
          .hero-tail > div:last-child {
            justify-content: flex-start !important;
          }
        }
      `}</style>
    </section>
  );
}
