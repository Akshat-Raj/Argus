# Handoff: LigmaFirewall — Marketing Landing Page

## Overview

A single-page marketing landing site for **LigmaFirewall**, an agentic security orchestration platform for software supply chain audits. The page introduces the product, the six specialized AI subagents that power it, and a sample orchestrator run — designed to feel like an editorial dossier rather than a typical SaaS landing page.

The aesthetic is **monochrome + restrained brass accent**, inspired by the visual gravitas of the *Suits* TV series: deep blacks, warm off-whites, generous whitespace, an editorial display serif paired with a tight grotesk and a structured monospace, plus a single warm gold accent used sparingly.

## About the Design Files

The HTML file in this bundle (`Landing Page.html`) is a **design reference created in HTML** — a working prototype that demonstrates the intended look, motion, and structure. It is not production code to ship verbatim.

The implementation task is to **recreate this design in the target codebase's existing environment** (React/Next.js, Vue/Nuxt, Astro, SvelteKit, etc.) using its established patterns, component primitives, and animation libraries. If no environment exists yet, **Next.js (App Router) + Tailwind + Framer Motion + GSAP/ScrollTrigger** is a natural fit and is recommended.

## Fidelity

**High-fidelity (hifi).** Final colors, typography, spacing, and motion are intended to be reproduced as-is. Hex values, font choices, easings, and animation durations in this README are authoritative.

## Page Structure (Top → Bottom)

1. **Sticky Nav** — Logo, nav links, request-access CTA
2. **Hero** — Editorial dossier meta row, kinetic 3-line display headline, lede + dual CTAs, vertical status flag
3. **Marquee** — Infinite-scroll list of audit categories
4. **Section Intro: Audits** — § 01 · The Brief, sets up the carousel
5. **Subagents Carousel** — Horizontal carousel showing 6 specialized subagents, 2 cards visible at a time, prev/next + auto-advance
6. **Architecture** (light/paper section) — § 02 · The Counsel. Orchestrator → 6 subagents diagram with drawn-on SVG connector lines
7. **Live Terminal Demo** — § 03 · The Run. Type-on terminal transcript of an orchestrator run, followed by a findings table
8. **Stats** (light/paper section) — § 04 · Receipts. Four animated number tickers
9. **Manifesto** — § 05 · The Posture. Large-scale italic editorial statement with sign-off
10. **Footer** — 4-col link grid + closing CTA

---

## Design Tokens

### Colors

```
--ink         #0a0a0a   /* page background, near-black */
--ink-2       #141414   /* marquee bg, terminal body */
--ink-3       #1c1c1c   /* terminal title bar */
--line        #262626   /* dividers on dark */
--line-2      #2e2e2e   /* button borders, tool chips */
--paper       #f5f3ee   /* warm off-white (foreground on dark, bg on light sections) */
--paper-2     #ebe7df   /* secondary paper tone (architecture diagram bg, subagent cards) */
--mute        #8a8580   /* muted text on dark */
--mute-2      #6a655e   /* muted text on light */
--brass       #b08d57   /* primary accent — restrained gold */
--brass-2     #d4b483   /* lighter brass, used for italic display words */
```

**Selection:** background `--brass`, text `--ink`.

### Typography

| Role | Family | Weight | Notes |
|---|---|---|---|
| Display / editorial | **Instrument Serif** | 400 (regular + italic) | Google Fonts. Used for h1–h3, manifesto, marquee items, agent card titles. Italics carry the brass color. |
| UI / body | **Inter Tight** | 300, 400, 500, 600, 700 | Google Fonts. Default for paragraphs, navigation, buttons. |
| Mono / system | **JetBrains Mono** | 400, 500 | Google Fonts. Eyebrows, terminal, finding IDs, subagent IDs, code references. |

**Type scale (representative):**
- Hero h1: `clamp(64px, 10vw, 168px)`, line-height `0.95`, letter-spacing `-0.02em`
- Section h2: `clamp(48px, 6vw, 88px)`, line-height `1`, letter-spacing `-0.02em`
- Manifesto: `clamp(40px, 5vw, 72px)`, line-height `1.1`
- Agent card h3: `48px` serif, italic accent in brass
- Body lede: `22px` weight 300 (hero) / `18px` weight 300 (sections)
- Eyebrows: `11px` mono, letter-spacing `0.22em`, uppercase, mute
- Stat numbers: `96px` Instrument Serif, italic accent
- Body small: `14–15px` Inter Tight

**Motif:** italicized words in display copy take `--brass-2`. Use sparingly — at most one or two per phrase (e.g. "We do not *negotiate*").

### Spacing

- Section vertical padding: `140px` top/bottom (desktop), tightens on mobile
- Container max-width: `1360px`, gutter `40px` (desktop), `24px` (mobile breakpoint < 980px)
- Card padding: `60px` (agent cards), `48px 32px` (stats), `28px` (terminal body)
- Section head grid: `1fr 2fr` two-col with `80px` gap (h2 left, lede right)

### Borders / Lines

- Hairline rule: `1px solid #262626` on dark, `1px solid rgba(0,0,0,0.12)` on paper
- Brass rule (decorative): `linear-gradient(to right, transparent, var(--brass), transparent)`
- No border-radius anywhere — the design is intentionally **all square corners** (editorial / dossier feel).

### Motion

- Library on prototype: **GSAP 3.12.5 + ScrollTrigger** (CDN)
- Recommended in app: keep GSAP/ScrollTrigger for scroll work; Framer Motion is fine for component-level state transitions.
- Hero headline reveal: `yPercent: 110 → 0`, `opacity: 0 → 1`, `duration: 1.1s`, `ease: power3.out`, stagger `0.12s`, delay `0.15s`
- Generic reveals: opacity + translateY(24px), `0.9s`, easing `cubic-bezier(.2,.7,.2,1)`, triggered at `top 88%` viewport
- Number tickers: `1.6s`, `power2.out`
- Architecture SVG paths: stroke-dashoffset draw-on, `1.2s` per path, `0.08s` stagger, `power2.out`
- Carousel slide: `transform: translateX(...)`, `0.8s`, `cubic-bezier(.2,.7,.2,1)`. Auto-advance every `5.2s`, paused on hover.
- Marquee: pure CSS keyframe `translateX(0 → -50%)`, `50s linear infinite`. Track is duplicated for seamless loop.
- Terminal type-on: per-line delay `60–210ms` (random within range), triggered on scroll-into-view at `top 75%`. Line-by-line append, not character-by-character.
- Hero grid parallax: `background-position: 0 → -160px` scrubbed with scroll across the hero section.
- Cursor blink: `1s infinite` opacity 50% midpoint.
- Pulse dot (orchestrator status): same blink, `1.6s` infinite.

---

## Screens / Views

> Single-page site. All sections share the dark `--ink` background except **Architecture** and **Stats**, which invert to `--paper` for editorial rhythm.

### 1. Nav (sticky)

- **Position:** `position: fixed`, top, full-width, `z-index: 50`
- **Background:** `linear-gradient(to bottom, rgba(10,10,10,.85), rgba(10,10,10,.55))` + `backdrop-filter: blur(14px)`
- **Bottom border:** `1px solid rgba(255,255,255,.04)`
- **Padding:** `20px 40px`
- **Layout:** Flex space-between — brand left, nav links center, CTA right
- **Brand:** 28×28px square mark (nested squares with a 4×4 brass dot center) + serif wordmark `Ligma` + italic brass `Firewall`
- **Nav links:** `13px` mono, uppercase, letter-spacing `.04em`, color `--mute`, hover `--paper`. 36px gap. Items: Audits / Subagents / Architecture / Live Run / Docs
- **CTA:** "Request Access →" — `12px` uppercase, `1px` paper border, `10px 18px` padding. Hover inverts (paper bg, ink text).

### 2. Hero

- **Min-height:** `100vh`. Padding `160px 0 80px`.
- **Background grid:** Two perpendicular `1px` lines at `80px` cadence, opacity `0.5`, faded by a radial mask. Drifts on scroll.
- **Vertical status flag (right edge):** `writing-mode: vertical-rl`, `10px` mono, letter-spacing `.4em`. Text: `SYS · ORCHESTRATOR ONLINE · v0.4.2`. Brass dot above blinks.
- **Meta row** (above headline, mono `11px` letter-spacing `.22em`, uppercase, mute, with paper-colored sub-line):
  - Left: `EST. 2026 / Software Supply Chain`
  - Center: `VOL. I, NO. 01 / The Quarterly Audit`
  - Right (text-align right): `CLASSIFIED / For DevSecOps Counsel`
- **Headline (3 lines, each in its own overflow-hidden mask for the reveal):**
  - Line 1: `Adversaries`
  - Line 2: `don't ` + italic brass `knock.`
  - Line 3: `Neither do we.`
- **Tail row:** Two-col grid `1.4fr 1fr`, `80px` gap, `60px` margin-top, `40px` padding-top above `1px` rule:
  - Left: lede `22px` weight 300 — opens with bold italic serif `LigmaFirewall` at `24px`. Copy:
    > **LigmaFirewall** is agentic security orchestration for the modern software supply chain — six specialized subagents auditing your CI/CD, IAM, infrastructure, code, and dependencies in concert. One orchestrator. No noise. No mercy.
  - Right (text-align right): two CTAs, `14px` gap.
    - Ghost: "Watch a run →" (1px line-2 border, hover paper border)
    - Primary: "Open the brief →" (paper bg, ink text, hover brass-2 bg)
    - CTA arrow translates `+6px` on hover, `0.3s`

### 3. Marquee

- **Track:** Two duplicated `.marquee-item` divs side-by-side translating `0 → -50%` over `50s`.
- **Background:** `--ink-2`. Border-top + border-bottom: `1px --line`.
- **Padding:** `32px 0`.
- **Items:** `42px` Instrument Serif. Pattern: `Word noun · Word italic-brass · 6×6 brass dot ·` repeated.
- Phrases (in order): Supply chain *integrity* · CI/CD *posture* · Access *control* · Configuration *drift* · Static *analysis* · Dependency *risk* · Typosquat *hunt*

### 4. Section Intro: Audits

- Standard section template: eyebrow `§ 01 · The Brief`, then two-col head with h2 `What we audit.` (italic *audit*) and a `lede`.
- Lede: about six surfaces, one investigation, focused tools, mutating tools filtered by default.

### 5. Subagents Carousel

- **Above rail (controls bar):** flex space-between, padding `32px 40px`, border-bottom `1px --line`.
  - Left: counter `01 / 06 · supply-chain` — current index (mono `12px`, paper) + total + dot + agent name (mono, mute)
  - Right: prev/next buttons. Each `56×56px`, `1px --line-2` border (no border between them — the right edge of prev is the left edge of next). 16×16 chevron SVGs. Hover: invert to paper bg/ink.
- **Rail:** flex, overflow hidden, top + bottom `1px --line`.
- **Track:** flex, transitions `transform 0.8s cubic-bezier(.2,.7,.2,1)`.
- **Card:** `flex: 0 0 50%` (2 visible at a time on desktop, 1 on mobile via the `< 980px` breakpoint). Padding `60px`. Right border `1px --line` between cards. Min-height `560px`. Internal grid `auto 1fr auto` rows, `40px` gap.
- **Card content:**
  - Top row: mono ID `SUBAGENT · 01 / 06` (current bold in `--brass-2`) on the left, `64px` Instrument Serif italic Greek glyph (α β γ δ ε ζ) on the right.
  - Title: `48px` Instrument Serif. Format `prefix-italic` where the second word is italic + brass-2 (e.g. `supply-` + italic brass-2 `chain`).
  - Body: `15px` weight 300, `--mute`, max-width `440px`.
  - Tools row: chips, mono `10px` uppercase letter-spacing `.12em`, `1px --line-2` border, `6px 10px` padding, `8px` gap.
- **Auto-advance:** every 5.2s; paused on hover via mouseenter.
- **Six subagents:**

| # | Glyph | Title | Body | Tool chips |
|---|---|---|---|---|
| 01 | α | supply-*chain* | Hunts typosquats, malicious post-install hooks, import-time secret harvesting, and outbound exfil patterns in vendored or installed packages. The first line of defense before anything reaches your build. | typosquat-scan · post-install · exfil-trace · vendor-diff |
| 02 | β | cicd-*monitoring* | Inspects GitHub Actions and Jenkins workflows for unsafe step composition, suspicious build activity, and possible secret exposure in logs. Tracks who pushed what, when, and from where. | gha-lint · jenkins-audit · log-redact · runner-trust |
| 03 | γ | access-*control* | Reviews IAM policies for over-privileged principals, MFA enforcement, stale service-account keys, and crossed account boundaries. Least privilege, restored — without a thirty-page ticket. | iam-graph · mfa-check · key-age · priv-esc |
| 04 | δ | config-*audit* | Sweeps Dockerfiles, Kubernetes manifests, and Terraform with CIS Benchmark and Checkov-style rules. Catches the misconfiguration before the misconfiguration catches you. | cis-bench · checkov · k8s-policy · tf-plan |
| 05 | ε | code-*analysis* | SAST-grade review for hardcoded secrets, injection paths, deserialization gadgets, and quietly insecure coding patterns. Reads your repo the way an attacker reads your repo. | sast-core · secret-grep · injection · taint-flow |
| 06 | ζ | dependency-*security* | SCA across npm audit, PyPI safety, and SBOM-style review. CVE matching, transitive risk surfacing, and version drift — explained in language a release manager will actually read. | cve-match · npm-audit · pypi-safety · sbom |

### 6. Architecture (paper section)

- **Background:** `--paper`. Body text → `--ink` and `--mute-2`.
- Eyebrow `§ 02 · The Counsel`. h2 `One orchestrator. Six specialists.` (italic *orchestrator.*).
- Lede references `agent.py`, `tools/`, `tools/mcp.py` as inline mono code chips (`13px`, `rgba(0,0,0,.06)` bg, `2px 8px` padding).
- **Diagram block:**
  - Container: `1px solid rgba(0,0,0,.12)`, `--paper-2` bg, `60px` padding, four 14×14 corner brackets (absolute, two-side borders only) at each corner.
  - **Orchestrator pill** (centered, `width: fit-content`, top): `18px 40px` padding, `1px solid --ink`, ink fill, paper text, mono `12px` uppercase letter-spacing `.18em`. Leads with an 8×8 brass blinking dot. Text: `DeepAgents Orchestrator · agent.py`.
  - **Connector lines** (height `80px`): one SVG with `viewBox="0 0 1200 80"`, `preserveAspectRatio="none"`. Six paths from `(600, 0)` down through `(600, 30)` then horizontally to each subagent's x-center at `30`, then down to `80`. Stroke `--ink`, width `1`, dasharray `3 4`, fill none. On enter: each path's full length is set as `strokeDasharray`/`Offset`, then animated `to: 0` with stagger.
  - **Subagent grid:** 6-col grid, `1px` gap on `--ink` background (creates hairline grid). Each cell `--paper-2` bg, hover `--paper`. Cell content: small brass mono ID (`α · 01`), `22px` serif name with italic suffix, then mono-style description in `--mute-2` aligned to bottom via `margin-top: auto`.

### 7. Live Terminal Demo

- Eyebrow `§ 03 · The Run`. h2 `A briefing in real time.`
- **Terminal block:**
  - Outer: `1px --line` border, `--ink-2` bg, `40px` margin-top.
  - **Title bar:** `14px 20px` padding, border-bottom `1px --line`, `--ink-3` bg. Three 10×10 lights (red `#7a3a3a`, amber `#7a6a3a`, green `#3a7a4a`). Center: `ligma-firewall · orchestrator.run()` mono `11px` mute uppercase letter-spacing `.18em`. Right: live UTC clock (`HH:MM:SS UTC`) updated every second.
  - **Body:** `28px` padding, min-height `440px`, mono `13px` line-height `1.7`. Lines append on scroll-into-view (top 75%). Each line: prefix span (`prompt` brass-2 / `mute` / `ok` greenish #9bb89b / `warn` brass-2 / `err` reddish #c08a8a) + optional command span in paper. Trailing line ends with a blinking 8×14 brass-2 cursor block.
  - **Transcript content:** orchestrator boot → parallel dispatch tree → 7 finding flags (⚑) per subagent → reconciliation summary → report path → fresh prompt with cursor. Full lines listed in the source HTML; preserve verbatim.
- **Findings table** (margin-top `80px`):
  - 5-col grid `80px 200px 1fr 120px 100px`, hairline rules between rows (`1px --line`).
  - Header row: mono `11px` uppercase mute. Cells: `22px 16px` padding.
  - Columns: `#` (mono mute), `Subagent` (mono brass-2 uppercase letter-spacing `.12em`), `Finding` (`18px` Instrument Serif italic, with inline mono `13px` code chips), `Severity`, `Status`. Severity classes: `sev-crit` (#d99), `sev-high` (brass-2), `sev-med` (paper), `sev-low` (mute).
  - 7 rows mirroring the terminal flags. Use the exact rows from the source.
  - Mobile: hides `Subagent` and `Status` columns; collapses to `60px 1fr 90px`.

### 8. Stats (paper section)

- Eyebrow `§ 04 · Receipts` (eyebrow rule recolored to brass on the inverted bg).
- 4-col grid, `1px` rules forming a tic-tac-toe; outer top + each cell border-right + border-bottom `1px rgba(0,0,0,.12)` (last cell's right border removed).
- Each cell: `48px 32px` padding.
- **Number style:** `96px` Instrument Serif, line-height `0.95`, letter-spacing `-.03em`. Italic numbers use `--brass`. Optional `<sup>` (`32px`, italic, brass, `top` aligned, `4px` left margin).
- Numbers tween from `0 → target` on scroll-into-view.

| Cell | Value | sup | Label |
|---|---|---|---|
| 1 | `6` | — | Subagents · Coordinated |
| 2 | `42` | `k` | Findings · Per Hour |
| 3 | *italic* `99.7` | `%` | Mutating Tools · Filtered |
| 4 | `0` | `noise` | Default Disposition |

### 9. Manifesto

- Padding `160px 0`, dark bg.
- Eyebrow `§ 05 · The Posture`.
- Statement: 4-line italic display block, `clamp(40px,5vw,72px)`. Italic + brass-2 on the verbs:
  > We do not *negotiate* with adversaries.  
  > We do not *request* least privilege.  
  > We do not *ask* dependencies to behave.  
  > We *audit.* We *contain.* We *ship.*
- Sign-off row: flex space-between, mono `11px` mute (left) and serif italic `18px` brass-2 (right):
  - Left: `— Filed by the Orchestrator · agent.py`
  - Right: `"When you're backed into a corner, be ruthless."`

### 10. Footer

- Border-top `1px --line`. Padding `80px 0 40px`.
- 4-col grid `2fr 1fr 1fr 1fr`, `60px` gap.
- **Col 1:** Brand wordmark at `28px` + closing CTA: `36px` Instrument Serif italic — "Ready when your supply chain isn't." with brass-2 link "Request access →" underlined `1px brass`.
- **Cols 2–4:** Section header (mono `11px` uppercase mute) + 5-item list. Anchors `14px` paper, hover brass-2.
  - Product: Orchestrator / Subagents / MCP Bridge / Local Tools / Changelog
  - Audits: Supply Chain / CI/CD / Access Control / Config / Code & Deps
  - Counsel: Documentation / Threat Model / Trust Center / Security.txt / Contact
- **Bottom strip:** margin-top `80px`, padding-top `30px`, border-top `1px --line`. Flex space-between, mono `11px` mute uppercase letter-spacing `.16em`.
  - Left: `© 2026 LigmaFirewall · All audits reserved`
  - Right: `v0.4.2 · build a3f9c1 · NYC`

---

## Interactions & Behavior

| Surface | Behavior |
|---|---|
| Nav links | Anchor scroll to in-page sections (`#audits`, `#agents`, `#architecture`, `#demo`, `#docs`). |
| Hero CTAs | Primary opens application/access flow; ghost scrolls to `#demo`. Both translate the arrow `+6px` on hover. |
| Hero headline | One-shot kinetic mask reveal on load. Do NOT replay on each route visit unless re-mounting. |
| Marquee | Pure CSS infinite loop. Pausable on hover is optional; the prototype runs continuously. |
| Subagents carousel | Auto-advances every 5.2s. Manual prev/next overrides timer. Pause on hover. Window resize recomputes the per-card width from `getBoundingClientRect()` and snaps to current index. |
| Architecture diagram | SVG connector lines draw on when the diagram enters viewport. Subagent cells have a paper hover state. |
| Terminal | Begins typing on scroll-into-view (`top 75%`). One-shot — does not replay. Live UTC clock in the title bar updates every second. |
| Stats | Number tickers tween on scroll-into-view. One-shot. |
| Reveals | Generic `.reveal` elements fade-up at `top 88%`. One-shot. |
| Hero grid | Background-position scrubbed with scroll for parallax. |
| Mobile (< 980px) | Nav links hide; container gutter shrinks to 24px; carousel cards become full-width; subagent grid in architecture goes 2-col; findings table collapses to 3 columns; stats collapse to 2 columns; footer to 2 columns; section heads stack. |

## State Management

The page is largely stateless. The implementation needs:

- `currentAgentIndex: number (0–5)` for the carousel
- A timer ref for auto-advance (clear on unmount + on hover)
- A `hasRunTerminal: boolean` to prevent re-typing on re-entering the trigger zone (or use ScrollTrigger's `once: true`)
- Resize listener to re-snap carousel translation

No data fetching, no forms, no auth. The "Request Access" CTAs can be wired to a contact form, mailto, or a calendar link as the team prefers.

## Assets

- **Fonts:** Google Fonts — Instrument Serif (ital@0;1), Inter Tight (300–700), JetBrains Mono (400, 500). Self-host for production if perf matters.
- **Logo mark:** Drawn in CSS — 28×28 outer 1px square + 4px-inset 1px square + 4×4 brass center dot. No image asset.
- **Icons:** Two inline SVG chevrons in the carousel nav (`<path d="M15 6l-6 6 6 6"/>` and mirror). All other glyphs are typographic (Greek letters α–ζ, the ⚑ flag, hairline dots).
- **No raster imagery** in the design. The architecture diagram is a single inline SVG of stroked dashed paths.

## Files

- `Landing Page.html` — the full prototype. All HTML, CSS, and JS inline (no external code). Uses GSAP + ScrollTrigger from cdnjs. Reference this for exact copy, animation timings, and SVG paths.

## Implementation Notes

- **Componentize for the target framework.** Suggested split:
  - `<Nav />`
  - `<Hero />`
  - `<Marquee />`
  - `<SectionHead eyebrow title lede />` (reused 5×)
  - `<AgentsCarousel agents={...} />`
  - `<AgentCard agent={...} />`
  - `<Architecture />`
  - `<Terminal lines={...} />`
  - `<FindingsTable rows={...} />`
  - `<Stats stats={...} />`
  - `<Manifesto />`
  - `<Footer />`
- **Animation library decision:** keep GSAP + ScrollTrigger for the terminal type-on, the SVG path draw-on, the parallax scrub, and the number tickers — these are all idiomatic GSAP. Use Framer Motion (or CSS) for the carousel slide and hover transitions. The hero headline reveal can be done in either.
- **Accessibility:** add `prefers-reduced-motion` guards that disable the type-on animation, marquee, parallax, and headline reveal — show final state immediately. Provide focus styles on nav links, CTAs, carousel buttons (currently relying on default browser outlines — replace with a 1px brass outline).
- **Square corners are intentional.** Do not add `border-radius` anywhere.
- **Italic + brass is the hero motif.** Use it sparingly (one or two words per phrase) and never on UI labels or buttons — only on display copy.
- **Copywriting voice:** terse, editorial, slightly noir. Numbered sections (`§ 01`) and "The Brief / The Counsel / The Run / Receipts / The Posture" labels are part of the brand voice — keep them.
- **Avoid** adding gradient flourishes, decorative SVG illustrations, color saturation, drop shadows, or glassmorphic panels. The restraint is the design.
