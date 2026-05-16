export default function Audits() {
  return (
    <section
      id="audits"
      style={{
        padding: "140px 0",
        borderTop: "1px solid var(--line)",
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
          § 01 · The Brief
        </div>

        <div
          style={{
            display: "grid",
            gridTemplateColumns: "1fr 2fr",
            gap: "80px",
            marginTop: "24px",
            alignItems: "end",
          }}
          className="audits-head"
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
            What we{" "}
            <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>
              audit.
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
            Six surfaces of attack. One coordinated investigation. Each subagent
            carries a focused system prompt and a small, deterministic toolset —
            local for development, MCP for production. Mutating tools are
            filtered out by default.
          </p>
        </div>
      </div>

      <style>{`
        @media (max-width: 980px) {
          .audits-head {
            grid-template-columns: 1fr !important;
            gap: 20px !important;
          }
        }
      `}</style>
    </section>
  );
}
