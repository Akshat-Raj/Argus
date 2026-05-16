"use client";

import { useMemo } from "react";

interface Finding {
  severity?: string;
  type?: string;
  package?: string;
  dependency_chain?: string;
  cve_id?: string;
  summary?: string;
  [key: string]: unknown;
}

interface ChainRow {
  nodes: string[];
  severity: string;
  label: string;
  cve?: string;
  isSupplyChain: boolean;
}

const SEV_COLOR: Record<string, string> = {
  CRITICAL: "#c08a8a",
  HIGH:     "#d4a76a",
  MEDIUM:   "#d4b483",
  LOW:      "#9bb89b",
  INFO:     "#8a8580",
};

const NODE_W = 130;
const NODE_H = 36;
const NODE_R = 6;
const ARROW_GAP = 36;
const ROW_H = 80;
const PAD_X = 24;
const PAD_Y = 20;

function nodeX(i: number) {
  return PAD_X + i * (NODE_W + ARROW_GAP);
}

function rowY(i: number) {
  return PAD_Y + i * ROW_H;
}

function truncate(s: string, n = 16) {
  return s.length > n ? s.slice(0, n - 1) + "…" : s;
}

function ChainRow({ row, y }: { row: ChainRow; y: number }) {
  const sevColor = SEV_COLOR[row.severity] ?? SEV_COLOR.INFO;
  const lastIdx = row.nodes.length - 1;

  return (
    <g>
      {/* Label left of row */}
      <text
        x={PAD_X}
        y={y - 6}
        fontSize={9}
        letterSpacing={1.4}
        style={{ textTransform: "uppercase" }}
        fill="var(--mute)"
        fontFamily="var(--mono)"
      >
        {row.label.slice(0, 40)}
        {row.cve ? `  ·  ${row.cve}` : ""}
      </text>

      {row.nodes.map((node, i) => {
        const x = nodeX(i);
        const cy = y + NODE_H / 2;
        const isFirst = i === 0;
        const isLast = i === lastIdx;
        const fill = isFirst ? "rgba(180,140,87,0.12)"
          : isLast ? (row.isSupplyChain ? "rgba(192,138,138,0.18)" : "rgba(192,138,138,0.12)")
          : "rgba(255,255,255,0.04)";
        const stroke = isFirst ? "var(--brass)" : isLast ? sevColor : "var(--line-2)";
        const textColor = isFirst ? "var(--brass-2)" : isLast ? sevColor : "var(--paper)";

        return (
          <g key={i}>
            {/* Arrow from previous node */}
            {i > 0 && (
              <g>
                <line
                  x1={nodeX(i - 1) + NODE_W + 2}
                  y1={cy}
                  x2={x - 2}
                  y2={cy}
                  stroke="var(--line-2)"
                  strokeWidth={1}
                />
                {/* Arrowhead */}
                <polygon
                  points={`${x - 2},${cy} ${x - 10},${cy - 4} ${x - 10},${cy + 4}`}
                  fill="var(--line-2)"
                />
              </g>
            )}

            {/* Node box */}
            <rect
              x={x}
              y={y}
              width={NODE_W}
              height={NODE_H}
              rx={NODE_R}
              ry={NODE_R}
              fill={fill}
              stroke={stroke}
              strokeWidth={isFirst || isLast ? 1.5 : 1}
            />

            {/* Supply chain skull on malicious node */}
            {isLast && row.isSupplyChain && (
              <text
                x={x + 10}
                y={y + NODE_H / 2 + 4}
                fontSize={12}
                fill={sevColor}
                fontFamily="var(--mono)"
              >
                ☠
              </text>
            )}

            {/* Node label */}
            <text
              x={x + NODE_W / 2 + (isLast && row.isSupplyChain ? 6 : 0)}
              y={y + NODE_H / 2 + 4}
              textAnchor="middle"
              fontSize={10}
              fontFamily="var(--mono)"
              fill={textColor}
            >
              {truncate(node, isLast && row.isSupplyChain ? 13 : 15)}
            </text>

            {/* Severity badge on last node */}
            {isLast && (
              <g>
                <rect
                  x={x + NODE_W - 2}
                  y={y - 8}
                  width={row.severity.length * 6 + 8}
                  height={14}
                  rx={3}
                  fill={sevColor}
                  opacity={0.85}
                />
                <text
                  x={x + NODE_W + (row.severity.length * 6 + 8) / 2 - 2}
                  y={y - 8 + 10}
                  textAnchor="middle"
                  fontSize={8}
                  fontFamily="var(--mono)"
                  fontWeight="600"
                  letterSpacing={0.8}
                  fill="var(--ink)"
                >
                  {row.severity}
                </text>
              </g>
            )}
          </g>
        );
      })}
    </g>
  );
}

export default function DependencyGraph({ findings }: { findings: Finding[] }) {
  const rows = useMemo<ChainRow[]>(() => {
    const out: ChainRow[] = [];
    const seen = new Set<string>();

    for (const f of findings) {
      const chain = f.dependency_chain as string | undefined;
      const isSupply =
        String(f.type ?? "").toLowerCase().includes("supply") ||
        String(f.type ?? "").toLowerCase().includes("typosquat") ||
        String(f.type ?? "").toLowerCase().includes("malicious") ||
        String(f.type ?? "").toLowerCase().includes("install") ||
        String(f.summary ?? "").toLowerCase().includes("install script") ||
        String(f.summary ?? "").toLowerCase().includes("exfil");

      if (!chain && !isSupply && !f.package) continue;

      let nodes: string[] = [];
      if (chain) {
        nodes = chain.split(/\s*→\s*/).map((n) => n.trim()).filter(Boolean);
      } else if (f.package) {
        nodes = ["your-app", String(f.package)];
      }
      if (nodes.length < 2) continue;

      const key = nodes.join("→");
      if (seen.has(key)) continue;
      seen.add(key);

      out.push({
        nodes,
        severity: f.severity ?? "LOW",
        label: String(f.type ?? f.package ?? "dependency"),
        cve: f.cve_id as string | undefined,
        isSupplyChain: isSupply,
      });
    }

    return out;
  }, [findings]);

  if (rows.length === 0) return null;

  const maxNodes = Math.max(...rows.map((r) => r.nodes.length));
  const svgW = PAD_X * 2 + maxNodes * NODE_W + (maxNodes - 1) * ARROW_GAP;
  const svgH = PAD_Y * 2 + rows.length * ROW_H;

  return (
    <div style={{ marginTop: "40px" }}>
      <div
        style={{
          display: "flex",
          alignItems: "center",
          gap: "12px",
          marginBottom: "16px",
        }}
      >
        <h2
          style={{
            fontFamily: "var(--serif)",
            fontWeight: 400,
            fontSize: "28px",
            letterSpacing: "-0.02em",
          }}
        >
          Dependency Graph
        </h2>
        <span
          style={{
            fontFamily: "var(--mono)",
            fontSize: "11px",
            color: "var(--mute)",
            letterSpacing: "0.1em",
          }}
        >
          {rows.length} chain{rows.length !== 1 ? "s" : ""}
        </span>
      </div>

      <div
        style={{
          border: "1px solid var(--line)",
          background: "var(--ink-2)",
          overflowX: "auto",
          padding: "24px 16px 16px",
        }}
      >
        {/* Legend */}
        <div
          style={{
            display: "flex",
            gap: "20px",
            marginBottom: "20px",
            fontFamily: "var(--mono)",
            fontSize: "10px",
            letterSpacing: "0.12em",
            textTransform: "uppercase",
            color: "var(--mute)",
          }}
        >
          {[
            { color: "var(--brass)", label: "Your App" },
            { color: "var(--line-2)", label: "Transitive" },
            { color: SEV_COLOR.HIGH, label: "Vulnerable / Malicious" },
          ].map(({ color, label }) => (
            <span key={label} style={{ display: "flex", alignItems: "center", gap: "6px" }}>
              <span
                style={{
                  width: "10px",
                  height: "10px",
                  borderRadius: "2px",
                  border: `1.5px solid ${color}`,
                  display: "inline-block",
                }}
              />
              {label}
            </span>
          ))}
        </div>

        <svg
          width="100%"
          viewBox={`0 0 ${svgW} ${svgH}`}
          style={{ display: "block", minWidth: `${Math.min(svgW, 480)}px` }}
          xmlns="http://www.w3.org/2000/svg"
        >
          {rows.map((row, i) => (
            <ChainRow key={i} row={row} y={rowY(i)} />
          ))}
        </svg>
      </div>
    </div>
  );
}
