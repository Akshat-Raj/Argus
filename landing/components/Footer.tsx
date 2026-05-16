"use client";

export default function Footer() {
  const cols = [
    {
      head: "Product",
      links: ["Orchestrator", "Subagents", "MCP Bridge", "Local Tools", "Changelog"],
    },
    {
      head: "Audits",
      links: ["Supply Chain", "CI/CD", "Access Control", "Config", "Code & Deps"],
    },
    {
      head: "Counsel",
      links: ["Documentation", "Threat Model", "Trust Center", "Security.txt", "Contact"],
    },
  ];

  return (
    <footer
      id="docs"
      style={{
        borderTop: "1px solid var(--line)",
        padding: "80px 0 40px",
        background: "var(--ink)",
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
            display: "grid",
            gridTemplateColumns: "2fr 1fr 1fr 1fr",
            gap: "60px",
          }}
          className="foot-grid"
        >
          <div>
            <a
              href="#"
              style={{
                display: "inline-flex",
                alignItems: "center",
                gap: "12px",
                fontFamily: "var(--serif)",
                fontSize: "28px",
                letterSpacing: "0.01em",
                marginBottom: "24px",
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
              Ligma
              <em
                style={{
                  fontStyle: "italic",
                  color: "var(--brass-2)",
                  fontWeight: 400,
                }}
              >
                Firewall
              </em>
            </a>
            <div
              style={{
                marginTop: "32px",
                fontFamily: "var(--serif)",
                fontSize: "36px",
                lineHeight: 1.1,
                fontStyle: "italic",
                letterSpacing: "-0.01em",
              }}
            >
              Ready when your
              <br />
              supply chain isn&apos;t.
              <br />
              <a
                href="#"
                style={{
                  color: "var(--brass-2)",
                  borderBottom: "1px solid var(--brass)",
                  paddingBottom: "2px",
                }}
              >
                Request access →
              </a>
            </div>
          </div>

          {cols.map((col) => (
            <div key={col.head}>
              <h4
                style={{
                  fontFamily: "var(--mono)",
                  fontSize: "11px",
                  letterSpacing: "0.2em",
                  textTransform: "uppercase",
                  color: "var(--mute)",
                  marginBottom: "18px",
                  fontWeight: 500,
                }}
              >
                {col.head}
              </h4>
              <ul
                style={{
                  listStyle: "none",
                  display: "flex",
                  flexDirection: "column",
                  gap: "10px",
                }}
              >
                {col.links.map((link) => (
                  <li key={link}>
                    <a
                      href="#"
                      style={{
                        fontSize: "14px",
                        color: "var(--paper)",
                        transition: "color 0.25s",
                      }}
                      onMouseEnter={(e) =>
                        (e.currentTarget.style.color = "var(--brass-2)")
                      }
                      onMouseLeave={(e) =>
                        (e.currentTarget.style.color = "var(--paper)")
                      }
                    >
                      {link}
                    </a>
                  </li>
                ))}
              </ul>
            </div>
          ))}
        </div>

        <div
          style={{
            display: "flex",
            justifyContent: "space-between",
            alignItems: "center",
            marginTop: "80px",
            paddingTop: "30px",
            borderTop: "1px solid var(--line)",
            fontFamily: "var(--mono)",
            fontSize: "11px",
            letterSpacing: "0.16em",
            textTransform: "uppercase",
            color: "var(--mute)",
          }}
        >
          <span>© 2026 LigmaFirewall · All audits reserved</span>
          <span>v0.4.2 · build a3f9c1 · NYC</span>
        </div>
      </div>

      <style>{`
        @media (max-width: 980px) {
          .foot-grid {
            grid-template-columns: 1fr 1fr !important;
            gap: 40px !important;
          }
        }
      `}</style>
    </footer>
  );
}
