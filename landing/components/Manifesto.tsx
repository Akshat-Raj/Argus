export default function Manifesto() {
  return (
    <section style={{ padding: "160px 0", textAlign: "left" }}>
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
          § 05 · The Posture
        </div>

        <p
          className="reveal"
          style={{
            fontFamily: "var(--serif)",
            fontSize: "clamp(40px, 5vw, 72px)",
            lineHeight: 1.1,
            letterSpacing: "-0.02em",
            maxWidth: "1100px",
            fontWeight: 400,
            marginTop: "48px",
          }}
        >
          We do not{" "}
          <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>
            negotiate
          </em>{" "}
          with adversaries.
          <br />
          We do not{" "}
          <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>
            request
          </em>{" "}
          least privilege.
          <br />
          We do not{" "}
          <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>ask</em>{" "}
          dependencies to behave.
          <br />
          We{" "}
          <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>
            audit.
          </em>{" "}
          We{" "}
          <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>
            contain.
          </em>{" "}
          We{" "}
          <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>
            ship.
          </em>
        </p>

        <div
          className="reveal"
          style={{
            marginTop: "80px",
            display: "flex",
            justifyContent: "space-between",
            alignItems: "flex-end",
            fontFamily: "var(--mono)",
            fontSize: "11px",
            letterSpacing: "0.2em",
            textTransform: "uppercase",
            color: "var(--mute)",
          }}
        >
          <span>— Filed by the Orchestrator · agent.py</span>
          <em
            style={{
              fontFamily: "var(--serif)",
              fontStyle: "italic",
              fontSize: "18px",
              color: "var(--brass-2)",
              textTransform: "none",
              letterSpacing: 0,
            }}
          >
            &ldquo;When you&rsquo;re backed into a corner, be ruthless.&rdquo;
          </em>
        </div>
      </div>
    </section>
  );
}
