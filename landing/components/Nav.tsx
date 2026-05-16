"use client";

export default function Nav() {
  return (
    <nav
      style={{
        position: "fixed",
        top: 0,
        left: 0,
        right: 0,
        zIndex: 50,
        display: "flex",
        alignItems: "center",
        justifyContent: "space-between",
        padding: "20px 40px",
        backdropFilter: "blur(14px)",
        background:
          "linear-gradient(to bottom, rgba(10,10,10,.85), rgba(10,10,10,.55))",
        borderBottom: "1px solid rgba(255,255,255,.04)",
      }}
    >
      <a
        href="#"
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          fontFamily: "var(--serif)",
          fontSize: "22px",
          letterSpacing: "0.01em",
        }}
      >
        <span
          style={{
            width: "28px",
            height: "28px",
            border: "1px solid var(--paper)",
            position: "relative",
            display: "grid",
            placeItems: "center",
            flexShrink: 0,
          }}
        >
          <span
            style={{
              position: "absolute",
              inset: "4px",
              border: "1px solid var(--paper)",
            }}
          />
          <span
            style={{
              width: "4px",
              height: "4px",
              background: "var(--brass)",
              position: "relative",
              zIndex: 1,
            }}
          />
        </span>
        <span>
          Ligma
          <em style={{ fontStyle: "italic", color: "var(--brass-2)", fontWeight: 400 }}>
            Firewall
          </em>
        </span>
      </a>

      <div
        className="nav-links"
        style={{
          display: "flex",
          gap: "36px",
          fontSize: "13px",
          letterSpacing: "0.04em",
          textTransform: "uppercase",
          color: "var(--mute)",
          fontFamily: "var(--mono)",
        }}
      >
        {[
          ["Audits", "#audits"],
          ["Subagents", "#agents"],
          ["Architecture", "#architecture"],
          ["Live Run", "#demo"],
          ["Docs", "#docs"],
        ].map(([label, href]) => (
          <a
            key={href}
            href={href}
            style={{ transition: "color 0.25s" }}
            onMouseEnter={(e) =>
              (e.currentTarget.style.color = "var(--paper)")
            }
            onMouseLeave={(e) =>
              (e.currentTarget.style.color = "var(--mute)")
            }
          >
            {label}
          </a>
        ))}
      </div>

      <a
        href="/scan"
        style={{
          fontSize: "12px",
          letterSpacing: "0.14em",
          textTransform: "uppercase",
          padding: "10px 18px",
          border: "1px solid var(--paper)",
          color: "var(--paper)",
          transition: "background 0.25s, color 0.25s",
          fontFamily: "var(--mono)",
          display: "inline-flex",
          alignItems: "center",
          gap: "8px",
        }}
        onMouseEnter={(e) => {
          e.currentTarget.style.background = "var(--brass-2)";
          e.currentTarget.style.borderColor = "var(--brass-2)";
          e.currentTarget.style.color = "var(--ink)";
        }}
        onMouseLeave={(e) => {
          e.currentTarget.style.background = "transparent";
          e.currentTarget.style.borderColor = "var(--paper)";
          e.currentTarget.style.color = "var(--paper)";
        }}
      >
        <span style={{ width: "6px", height: "6px", borderRadius: "50%", background: "#9bb89b", display: "inline-block", animation: "blink 1.6s infinite" }} />
        Run a Scan →
      </a>

      <style>{`
        @media (max-width: 980px) {
          .nav-links { display: none !important; }
        }
      `}</style>
    </nav>
  );
}
