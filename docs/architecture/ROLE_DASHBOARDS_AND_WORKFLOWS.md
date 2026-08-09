# WDL-3 — Role-Specific Dashboards & Workflows Architecture

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Phase**: `Phase WDL-3 — Role-Specific Dashboards & Workflows`

---

## 1. Overview

Phase WDL-3 transforms the application's single generic dashboard into three distinct role-tailored dashboards and operational workflows while maintaining a unified, modular SPA shell structure.

The design strictly separates operational vulnerability triage, academic research model evaluation, and application/system administration without duplicating code or creating unrelated sub-applications.

---

## 2. Dashboard Architecture

The frontend uses a single router shell (`dashboard_view.js`) that inspects the authenticated user state (`state.getState().currentUser`) and dynamically renders the corresponding role component:

```text
                       [ dashboard_view.js ]
                                 │
         ┌───────────────────────┼───────────────────────┐
         ▼                       ▼                       ▼
[ analyst_dashboard.js ] [ researcher_dashboard.js ] [ admin_dashboard.js ]
```

### Components

1. **`analyst_dashboard.js`**:
   - **Target Audience**: Security Analysts / Triage Engineers.
   - **Key Focus**: Operational triage, active threat discovery, KEV catalog highlights, recent CVE triage history (`localStorage`).
   - **4-Step Guided Workflow**:
     1. Explore & Filter (`#explorer`)
     2. Predict Risk (`#predict`)
     3. Asset Prioritization (`#prioritize`)
     4. Explain Features (`#explain`)

2. **`researcher_dashboard.js`**:
   - **Target Audience**: Academic Researchers & Data Scientists.
   - **Key Focus**: Temporal dataset partitions, machine learning benchmarks, SHAP explainability, dataset provenance.
   - **Benchmark Metrics Matrix**:
     - EXP-A1 Pre-Scoring CVSS Regressor ($MAE = 0.9750$)
     - EXP-B2 Publication-Time KEV Classifier ($PR\text{-}AUC = 0.02884$, $8.96\times$ Precision Uplift over Random Baseline)
     - EXP-B1 Retrospective Leakage Finding (Strict feature boundary enforcement)
     - EXP-C1 Prioritization Surface Formulation (Mode 1 Linear vs Mode 2 Surface)

3. **`admin_dashboard.js`**:
   - **Target Audience**: System Administrators & Demonstration Managers.
   - **Key Focus**: User account management, role distribution, system availability monitoring.
   - **Data Source**: `GET /api/v1/auth/users`.

---

## 3. Data Sources & Real Data Enforcement

All metrics shown on dashboards are sourced directly from authoritative backend APIs or established research dataset manifests:

| Metric Category | Data Source | Sourced Value |
| :--- | :--- | :--- |
| **Dataset Scale** | `GET /api/v1/provenance` | 366,547 Canonical CVEs |
| **Active KEV Threats** | `GET /api/v1/vulnerabilities?is_kev=true` | 1,647 CISA KEV CVEs |
| **EPSS Snapshot** | `GET /api/v1/provenance` | 348,900 Records (2026-07-16) |
| **User Directory & Roles** | `GET /api/v1/auth/users` | Real-time SQLite user list |
| **Temporal Partitions** | Research Protocol (Phase 2 & 3) | Train (208k), Val (71k), Test (86k) |

---

## 4. Access Control & Authorization Enforcement

Role differences are backed by server-enforced FastAPI authorization dependencies (`require_roles`):

- **Analyst Role**: Has full access to operational endpoints (`/predict`, `/prioritize`, `/explain`). Restricted from `/auth/users`.
- **Researcher Role**: Has access to model inspection endpoints (`/predict`, `/explain`, `/provenance`). **Strictly forbidden** from `/prioritize` (Server returns HTTP 403 Forbidden).
- **Admin Role**: Full access to all endpoints, user management, and active status toggles.

---

## 5. Client-Side Recent History (localStorage)

Security Analysts benefit from a lightweight, client-side triage history (`wdl_recent_cves`). Whenever an analyst inspects a vulnerability detail drawer, the CVE ID, score, and timestamp are persisted locally in `localStorage` without exposing sensitive authentication tokens or credentials.
