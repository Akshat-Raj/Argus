export default function Marquee() {
  const items = [
    ["Supply chain ", "integrity"],
    ["CI/CD ", "posture"],
    ["Access ", "control"],
    ["Configuration ", "drift"],
    ["Static ", "analysis"],
    ["Dependency ", "risk"],
    ["Typosquat ", "hunt"],
  ];

  const renderItems = () =>
    items.map(([plain, italic], i) => (
      <span
        key={i}
        style={{
          fontFamily: "var(--serif)",
          fontSize: "42px",
          letterSpacing: "-0.01em",
          color: "var(--paper)",
          display: "inline-flex",
          alignItems: "center",
          gap: "64px",
        }}
      >
        {plain}
        <em style={{ fontStyle: "italic", color: "var(--brass-2)" }}>
          {italic}
        </em>
        <span
          style={{
            width: "6px",
            height: "6px",
            background: "var(--brass)",
            borderRadius: "50%",
            display: "inline-block",
            flexShrink: 0,
          }}
        />
      </span>
    ));

  return (
    <div
      aria-hidden="true"
      style={{
        borderTop: "1px solid var(--line)",
        borderBottom: "1px solid var(--line)",
        padding: "32px 0",
        overflow: "hidden",
        background: "var(--ink-2)",
      }}
    >
      <div className="marquee-track" style={{ gap: "64px" }}>
        <div
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "64px",
            flexShrink: 0,
          }}
        >
          {renderItems()}
        </div>
        <div
          aria-hidden="true"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "64px",
            flexShrink: 0,
          }}
        >
          {renderItems()}
        </div>
      </div>
    </div>
  );
}
