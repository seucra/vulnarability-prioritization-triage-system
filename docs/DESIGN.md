# Design System & UI/UX Specification
## Vulnerability Prioritization & Triage System (VTS)

**Document Classification**: Authoritative Frontend Visual & Interaction Design Specification  
**Design Paradigm**: Dense Professional Security Workstation / Analytical Data Triage  
**Repository Identifier**: `seucra/vulnarability-prioritization-triage-system`  
**Core Stylesheet**: `frontend/css/styles.css` (869 lines of custom CSS tokens and responsive rules)  

---

## 1. Visual Design Philosophy

The VTS user interface is designed specifically for technical cybersecurity triage operations. Unlike generic dashboard templates or consumer web apps, cybersecurity analysts require **high information density, rapid visual parsing of risk indicators, instantaneous filter feedback, and persistent contextual state**.

### Core Design Principles
1. **Data Density without Clutter**: Maximize readable screen space to display complex vulnerability metadata (CVE IDs, weakness types, CVSS vectors, EPSS probabilities, KEV status) in compact tabular grids.
2. **Strict Semantic Color Architecture**: Color is reserved exclusively for functional meaning (severity tiers, threat status, attribution direction). Neutral slate-blue backgrounds prevent eye fatigue during prolonged analysis sessions.
3. **Dual-Font Typography Hierarchy**: A clean geometric sans-serif (`Inter`) handles navigational structure and descriptive copy, while a high-legibility monospace typeface (`JetBrains Mono`) renders all technical identifiers, metrics, and code payloads.
4. **Context Preservation via Slide-Over Drawers**: Opening a vulnerability's deep technical details does not navigate the user away from their search query; an off-canvas slide-over drawer displays joined CWE/CPE taxonomy while maintaining the analyst's queue position.

---

## 2. Design Tokens and Theming: The Tonalspot Palette

The interface implements a custom CSS custom properties architecture based on the **Tonalspot Light Theme**:

```css
:root {
  /* Surface & Base Colors */
  --bg-base: #f9f9fe;              /* Soft cool tinted white base */
  --bg-surface: #ffffff;           /* Clean card and drawer surface */
  --bg-surface-elevated: #f0f3fa;  /* Subtle elevated component background */
  --bg-muted: #e4e8f2;             /* Table headers and input fills */

  /* Primary Brand Tones (Slate Blue / Steel) */
  --primary: #45608a;              /* Core brand action and focused borders */
  --primary-hover: #344c70;        /* Hover action state */
  --primary-light: #e8eef8;        /* Soft active tab and selection tint */
  --primary-text: #1b283d;         /* High-contrast brand heading text */

  /* Secondary & Tertiary Tones */
  --secondary: #576579;            /* Secondary metadata and subtle icons */
  --tertiary: #665882;             /* Deep plum-slate for administrative badges */
  --tertiary-light: #f1edf8;       /* Subtle tertiary tint */

  /* Neutral Typography Scales */
  --text-primary: #191c21;         /* WCAG AAA dark slate for body copy */
  --text-secondary: #434751;       /* WCAG AA muted metadata text */
  --text-muted: #737782;           /* Subtle labels and disabled copy */

  /* Borders & Dividers */
  --border-subtle: #e1e3ec;        /* Card and grid line dividers */
  --border-strong: #c4c7d4;        /* Input borders and active tab lines */

  /* Severity & Risk Palette (WCAG AA Compliant) */
  --sev-critical-bg: #fee8e8;
  --sev-critical-text: #b91c1c;    /* Deep crimson for CVSS 9.0–10.0 */
  --sev-high-bg: #fff1e5;
  --sev-high-text: #c2410c;        /* Deep amber for CVSS 7.0–8.9 */
  --sev-medium-bg: #fef9c3;
  --sev-medium-text: #854d0e;      /* Deep gold for CVSS 4.0–6.9 */
  --sev-low-bg: #ecfdf5;
  --sev-low-text: #047857;         /* Deep emerald for CVSS 0.1–3.9 */

  /* CISA KEV Active Weaponization Indicator */
  --kev-active-bg: #fdf2f8;
  --kev-active-border: #f472b6;
  --kev-active-text: #be185d;      /* Vibrant rose badge for confirmed KEV */

  /* SHAP Attribution Directional Tones */
  --shap-positive: #ef4444;        /* Red: Increases estimated risk */
  --shap-negative: #3b82f6;        /* Blue: Suppresses estimated risk */
}
```

---

## 3. Typography Architecture

VTS utilizes a dual-font structure loaded via Google Fonts with local fallback stacks:

| Typography Role | Font Family | Weight Variants | Typical Use Cases |
|---|---|---|---|
| **User Interface & Copy** | `Inter`, -apple-system, sans-serif | 400 (Regular), 500 (Medium), 600 (Semi-Bold), 700 (Bold) | Header navigation, button labels, modal copy, form labels, disclaimer notices. |
| **Technical Data & Metrics** | `JetBrains Mono`, monospace | 400 (Regular), 500 (Medium), 600 (Semi-Bold) | CVE IDs (`CVE-2021-44228`), CWE codes (`CWE-502`), CVSS base scores (`9.8`), EPSS percentiles (`0.9998`), vector strings, JSON payloads. |

### Font Hierarchy Scale
- **Display Heading (`h1`)**: 28px / Line-Height: 34px / Weight: 700 / Inter (`--primary-text`)
- **Section Heading (`h2`)**: 20px / Line-Height: 26px / Weight: 600 / Inter
- **Card Subheading (`h3`)**: 16px / Line-Height: 22px / Weight: 600 / Inter
- **Body Regular**: 14px / Line-Height: 20px / Weight: 400 / Inter (`--text-primary`)
- **Metadata Small**: 12px / Line-Height: 16px / Weight: 500 / Inter (`--text-secondary`)
- **Technical Mono**: 13px / Line-Height: 18px / Weight: 500 / JetBrains Mono

---

## 4. Component Hierarchy and Layout Specifications

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                          STICKY NAVBAR (64px)                           │
│  [VTS Logo]   Explorer   Predict   Prioritize   Batch Triage   Provenance │
│                                      [Role Badge: ANALYST]  [Sign Out]  │
└─────────────────────────────────────────────────────────────────────────┘
┌─────────────────────────────────────────────────────────────────────────┐
│                   MAIN CONTAINER (Max-Width: 1440px)                    │
│                                                                         │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    VIEW HEADER & FILTER BAR                       │  │
│  │  [Search Keyword...] [Vendor Filter] [CWE] [CVSS Slider] [Filter] │  │
│  └───────────────────────────────────────────────────────────────────┘  │
│                                                                         │
│  ┌──────────────────────────────────────┐  ┌─────────────────────────┐  │
│  │          PRIMARY DATA GRID           │  │   SLIDE-OVER DRAWER     │  │
│  │  CVE ID     Published  CVSS   EPSS   │  │   (Context Details)     │  │
│  │  CVE-2021-  2021-12    10.0   0.975  │  │   Joined CWE Taxonomy   │  │
│  │  CVE-2023-  2023-04     7.5   0.021  │  │   CPE Configurations    │  │
│  │  CVE-2024-  2024-01     9.8   0.450  │  │   Full CVSS v3.1 Vector │  │
│  │  (Pagination: Page 1 of 18,328)      │  │   [Export Briefing PDF] │  │
│  └──────────────────────────────────────┘  └─────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

### 4.1 Sticky Navigation Header (`navbar.js`)
- Fixed at the top viewport boundary (`height: 64px`, `z-index: 100`).
- Provides active route highlighting with an illuminated bottom border (`2px solid var(--primary)`).
- Dynamically renders role badges (`ANALYST` in slate blue, `RESEARCHER` in emerald, `ADMIN` in deep purple).
- Unauthenticated sessions render a modal trigger button (`Sign In / Register`).

### 4.2 Slide-Over Detail Drawer (`#detail-modal-container`)
- Implemented as an off-canvas panel sliding from the right screen edge (`width: 580px`, transition: `300ms cubic-bezier(0.16, 1, 0.3, 1)`).
- Triggered by clicking any row in the Explorer or Batch Triage views.
- Deep-joins child tables in real time to display:
  - CWE hierarchical descriptions and weakness classes.
  - CPE platform applicability list with collapsible vendor/product cards.
  - EPSS percentile gauges and historical prediction boundary badges.
  - Printable vulnerability briefing button formatting clean CSS print layouts.

### 4.3 Data-Dense Tabular Views
- Table container enforces `overflow-x: auto` with sticky table headers (`background: var(--bg-muted)`).
- Row hover states illuminate subtle slate backgrounds (`var(--bg-surface-elevated)`).
- Numeric columns (CVSS, EPSS) right-align in monospace font to facilitate vertical visual comparison.

### 4.4 Interactive SHAP Attribution Visualizer (`predict_view.js`)
- Computes and renders local feature attributions $\phi_i$ as horizontal divergent bar charts.
- Red bars (`var(--shap-positive)`) extend rightward from the center axis, representing features that increase estimated severity or exploitation probability.
- Blue bars (`var(--shap-negative)`) extend leftward, representing features that suppress the estimate.
- Feature labels render in monospace with explicit contribution values ($\phi = +0.8212$).

### 4.5 Batch Triage Queue Workflow (`batch_triage_view.js`)
- Multi-line textarea accepts raw paste from security scanners (supports comma, space, or newline-separated CVE IDs up to 100 items).
- Instant validation identifies valid CVE formats, detects unknown IDs, and displays warning badges.
- Triage controls allow per-item or bulk asset criticality overrides ($0.25, 0.50, 0.75, 1.00$).
- Deterministic queue sorting displays Mode 1 Rank, Mode 2 Rank, and a color-coded Rank Shift indicator ($\Delta = \text{Rank}_{\text{nonlin}} - \text{Rank}_{\text{lin}}$).
- One-click CSV and JSON export buttons download the complete prioritized schedule.

---

## 5. Accessibility & Responsive Specifications

1. **Contrast Compliance (WCAG 2.1 AA)**:
   - All body text against `--bg-base` achieves a minimum contrast ratio of **7.2:1** (exceeding the 4.5:1 requirement).
   - Severity badges use dark foreground text over light pastel backgrounds (e.g., `#b91c1c` on `#fee8e8` achieves **5.8:1** contrast).
2. **Focus States & Keyboard Navigation**:
   - All interactive controls (buttons, inputs, sliders, table rows) feature an explicit outline: `2px solid var(--primary); outline-offset: 2px`.
   - Modals and slide-over drawers capture focus and allow dismissal via the `Escape` key.
3. **Responsive Breakpoints**:
   - **Desktop Large ($\ge 1440\text{px}$)**: Full grid container, persistent drawer overlay.
   - **Tablet / Small Laptop ($1024\text{px} - 1439\text{px}$)**: Fluid table columns; slide-over drawer expands to `65%` width.
   - **Mobile Viewport ($< 768\text{px}$)**: Navbar collapses into vertical mobile menu; slide-over drawer occupies `100vw`; table transforms into horizontally scrollable card view.

---

## 6. Print Stylesheet Architecture

VTS includes a dedicated print media stylesheet (`@media print` in `styles.css`) for generating physical executive briefing sheets:
- Strips interactive navigation bars, buttons, and form inputs.
- Forces all background colors to white and text colors to high-contrast black (`#000000`).
- Inserts official academic branding headers and pagination markers (`Page X of Y`).
- Expands table widths to 100% with solid hairline borders (`1px solid #000`).
