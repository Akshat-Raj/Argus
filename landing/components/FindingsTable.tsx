const findings = [
  {
    id: "0001",
    agent: "supply-chain",
    finding: (
      <>
        Typosquat detected:{" "}
        <code
          style={{
            fontFamily: "var(--mono)",
            fontSize: "13px",
            background: "rgba(255,255,255,0.05)",
            padding: "1px 4px",
          }}
        >
          reqests
        </code>{" "}
        mimicking{" "}
        <code
          style={{
            fontFamily: "var(--mono)",
            fontSize: "13px",
            background: "rgba(255,255,255,0.05)",
            padding: "1px 4px",
          }}
        >
          requests
        </code>
      </>
    ),
    severity: "Critical",
    sevClass: "sev-crit",
    status: "Held",
    statusClass: "sev-high",
  },
  {
    id: "0002",
    agent: "cicd-monitoring",
    finding: "Workflow secret echoed to GHA log on failure path",
    severity: "High",
    sevClass: "sev-high",
    status: "Open",
    statusClass: "sev-high",
  },
  {
    id: "0003",
    agent: "access-control",
    finding: (
      <>
        Service-account key, age 412d, scope{" "}
        <code
          style={{
            fontFamily: "var(--mono)",
            fontSize: "13px",
            background: "rgba(255,255,255,0.05)",
            padding: "1px 4px",
          }}
        >
          *
        </code>
      </>
    ),
    severity: "High",
    sevClass: "sev-high",
    status: "Acked",
    statusClass: "sev-med",
  },
  {
    id: "0004",
    agent: "config-audit",
    finding: (
      <>
        Container running as UID&nbsp;0 in{" "}
        <code
          style={{
            fontFamily: "var(--mono)",
            fontSize: "13px",
            background: "rgba(255,255,255,0.05)",
            padding: "1px 4px",
          }}
        >
          prod-api
        </code>
      </>
    ),
    severity: "Medium",
    sevClass: "sev-med",
    status: "Open",
    statusClass: "sev-med",
  },
  {
    id: "0005",
    agent: "code-analysis",
    finding: (
      <>
        SQL string concatenation in{" "}
        <code
          style={{
            fontFamily: "var(--mono)",
            fontSize: "13px",
            background: "rgba(255,255,255,0.05)",
            padding: "1px 4px",
          }}
        >
          /billing/invoice.py:147
        </code>
      </>
    ),
    severity: "High",
    sevClass: "sev-high",
    status: "Open",
    statusClass: "sev-med",
  },
  {
    id: "0006",
    agent: "dependency-security",
    finding: "7 CVEs across 4 transitive deps · CVSS ≥ 7.4",
    severity: "High",
    sevClass: "sev-high",
    status: "Triage",
    statusClass: "sev-med",
  },
  {
    id: "0007",
    agent: "supply-chain",
    finding: "Outbound POST to unknown host on package import",
    severity: "Critical",
    sevClass: "sev-crit",
    status: "Held",
    statusClass: "sev-high",
  },
];

function sevColor(cls: string) {
  switch (cls) {
    case "sev-crit": return "#d99999";
    case "sev-high": return "var(--brass-2)";
    case "sev-med": return "var(--paper)";
    case "sev-low": return "var(--mute)";
    default: return "var(--paper)";
  }
}

export default function FindingsTable() {
  return (
    <div
      style={{
        maxWidth: "1360px",
        margin: "0 auto",
        padding: "0 40px",
        marginTop: "80px",
      }}
    >
      <div
        className="findings-table reveal"
        style={{
          display: "grid",
          gridTemplateColumns: "80px 200px 1fr 120px 100px",
          borderTop: "1px solid var(--line)",
        }}
      >
        {/* Header */}
        {["#", "Subagent", "Finding", "Severity", "Status"].map((h) => (
          <div
            key={h}
            style={{
              padding: "22px 16px",
              borderBottom: "1px solid var(--line)",
              fontFamily: "var(--mono)",
              fontSize: "11px",
              letterSpacing: "0.18em",
              textTransform: "uppercase",
              color: "var(--mute)",
              fontWeight: 400,
            }}
          >
            {h}
          </div>
        ))}

        {/* Rows */}
        {findings.map((row) => (
          <>
            <div
              key={`${row.id}-idx`}
              style={{
                padding: "22px 16px",
                borderBottom: "1px solid var(--line)",
                fontFamily: "var(--mono)",
                color: "var(--mute)",
                fontSize: "14px",
              }}
            >
              {row.id}
            </div>
            <div
              key={`${row.id}-agent`}
              style={{
                padding: "22px 16px",
                borderBottom: "1px solid var(--line)",
                fontFamily: "var(--mono)",
                fontSize: "12px",
                color: "var(--brass-2)",
                textTransform: "uppercase",
                letterSpacing: "0.12em",
              }}
              className="findings-agent"
            >
              {row.agent}
            </div>
            <div
              key={`${row.id}-finding`}
              style={{
                padding: "22px 16px",
                borderBottom: "1px solid var(--line)",
                fontFamily: "var(--serif)",
                fontSize: "18px",
                fontStyle: "italic",
                color: "var(--paper)",
              }}
            >
              {row.finding}
            </div>
            <div
              key={`${row.id}-sev`}
              style={{
                padding: "22px 16px",
                borderBottom: "1px solid var(--line)",
                fontFamily: "var(--mono)",
                fontSize: "11px",
                letterSpacing: "0.18em",
                textTransform: "uppercase",
                color: sevColor(row.sevClass),
              }}
            >
              {row.severity}
            </div>
            <div
              key={`${row.id}-status`}
              style={{
                padding: "22px 16px",
                borderBottom: "1px solid var(--line)",
                fontFamily: "var(--mono)",
                fontSize: "11px",
                letterSpacing: "0.18em",
                textTransform: "uppercase",
                color: sevColor(row.statusClass),
              }}
              className="findings-status"
            >
              {row.status}
            </div>
          </>
        ))}
      </div>

      <style>{`
        @media (max-width: 980px) {
          .findings-table {
            grid-template-columns: 60px 1fr 90px !important;
            font-size: 12px;
          }
          .findings-agent,
          .findings-status {
            display: none !important;
          }
        }
      `}</style>
    </div>
  );
}
