Listed directory vulnarability-prioritization-triage-system
Listed directory backend
Listed directory app
Listed directory api
Listed directory v1
Listed directory frontend
Listed directory css
Listed directory js
Listed directory components
Listed directory docs
Listed directory architecture
Listed directory research
Listed directory tests
Listed directory scripts
Listed directory src
Listed directory ingestion
Listed directory data
Listed directory experiments
Listed directory phase3
Viewed README.md:1-118
Viewed main.py:1-60
Viewed config.py:1-34
Viewed router.py:1-16
Searched for "auth|login|session|jwt|token|role"
Viewed login.html:1-68
Viewed register.html:1-97
Viewed script.js:1-145
Viewed vulnerabilities.py:1-67
Viewed predict.py:1-49
Viewed prioritize.py:1-25
Viewed explain.py:1-57
Viewed provenance.py:1-22
Viewed test_backend_api.py:1-162
Viewed test_etl_invariants.py:1-164

# WDL Completion Audit

## 1. Current Architecture

The system operates as a unified research prototype and decision-support web application. The backend layer consists of a **FastAPI** application serving both REST API endpoints (`/api/v1/...`) and mounting a single-page application (SPA) static frontend from the `frontend/` directory.

Data access is powered by an in-memory **DuckDB** query engine reading frozen Parquet files stored in `data/processed/*.parquet` in read-only mode. Machine learning inference and model explainability rely on reconstructed **XGBoost** models (`exp_a1` regressor and `exp_b2` classifier) serialized with `joblib` and `shap` TreeExplainer models.

```text
+-----------------------------------------------------------------------------------+
|                                 BROWSER CLIENT                                    |
|  Light Theme SPA (HTML5 / Vanilla ES Modules / CSS Tokens / Chart.js / SVG)        |
+-----------------------------------------------------------------------------------+
       |                                                               |
       | Static File Delivery                                          | REST API Calls
       v                                                               v
+-----------------------------------------------------------------------------------+
|                                 FASTAPI BACKEND                                   |
|  (backend/app/main.py — Uvicorn Server at http://localhost:8000)                  |
|                                                                                   |
|  +---------------------------+   +---------------------------------------------+  |
|  | Static Files Middleware   |   | API Router (/api/v1)                        |  |
|  | Serves frontend/ index    |   | - /vulnerabilities  - /predict/cvss         |  |
|  +---------------------------+   | - /predict/kev      - /prioritize           |  |
|                                  | - /explain/cvss     - /explain/kev          |  |
|                                  | - /provenance       - /health               |  |
|                                  +---------------------------------------------+  |
|                                                         |                         |
|                                                         v                         |
|                                  +---------------------------------------------+  |
|                                  | Service Layer & ML Inference                |  |
|                                  | - vulnerability_service (DuckDB Query)      |  |
|                                  | - inference_service     (XGBoost Models)    |  |
|                                  | - scoring_service       (Mode 1 & Mode 2)   |  |
|                                  | - explanation_service   (SHAP TreeExplainer)|  |
|                                  | - provenance_service    (Freeze Manifest)   |  |
|                                  +---------------------------------------------+  |
+-----------------------------------------------------------------------------------+
                                           |
                    +----------------------+----------------------+
                    |                                             |
                    v                                             v
+---------------------------------------+     +-------------------------------------+
|        FROZEN PARQUET DATASET         |     |      SERIALIZED MODEL ARTIFACTS     |
| (data/processed/*.parquet — 366k CVEs) |     | (data/experiments/phase3/a1 & b2)   |
| - vulnerabilities.parquet             |     | - model.xgb (XGBoost Regressor/Clf) |
| - epss.parquet (348.9k dated 07-16)   |     | - vectorizer.joblib (TF-IDF)        |
| - kev.parquet (1,647 catalog CVEs)    |     | - feature_names.json                |
| - cve_cwe.parquet & cve_cpe.parquet   |     +-------------------------------------+
+---------------------------------------+
```

---

## 2. Current Repository Structure

```text
vulnarability-prioritization-triage-system/
├── backend/                         # FastAPI Backend Application Package
│   └── app/
│       ├── main.py                  # Entrypoint, CORS, Static Files Mount, Error Handlers
│       ├── config.py                # Pydantic Settings, Base Paths, Research Constants
│       ├── api/
│       │   ├── router.py            # API Router Assembly
│       │   └── v1/
│       │       ├── vulnerabilities.py # GET /vulnerabilities & GET /vulnerabilities/{cve_id}
│       │       ├── predict.py         # POST /predict/cvss & POST /predict/kev
│       │       ├── prioritize.py      # POST /prioritize (Mode 1 Linear vs Mode 2 Surface)
│       │       ├── explain.py         # POST /explain/cvss & POST /explain/kev (SHAP)
│       │       └── provenance.py      # GET /provenance
│       ├── core/
│       │   ├── database.py          # DuckDB Read-Only Query Engine over Parquet
│       │   └── exceptions.py        # HTTP Exception Types
│       ├── schemas/                 # Pydantic Request/Response Validation Models
│       │   ├── vulnerability.py     # Search and Detail Schemas
│       │   ├── prediction.py        # Inference & Boundary Validation Schemas
│       │   ├── prioritization.py    # Dual-Mode Scoring Schemas
│       │   ├── explanation.py       # SHAP Feature Attribution Schemas
│       │   └── provenance.py       # Research Provenance & Dataset Freeze Schemas
│       └── services/                # Backend Business & ML Logic
│           ├── vulnerability_service.py # DuckDB Query Execution
│           ├── inference_service.py     # Frozen XGBoost Model Inference
│           ├── scoring_service.py       # Mode 1 Linear & Mode 2 Surface Formulation
│           ├── explanation_service.py   # SHAP TreeExplainer Calculation
│           └── provenance_service.py    # Freeze Manifest & Experiment Benchmark Reporting
├── frontend/                        # Web Frontend Application Shell
│   ├── index.html                   # SPA HTML Shell (Main Application UI)
│   ├── login.html                   # Legacy static HTML file (Detached prototype)
│   ├── register.html                # Legacy static HTML file (Detached prototype)
│   ├── script.js                    # Legacy localStorage auth helper (Detached prototype)
│   ├── style.css                    # Legacy CSS stylesheet (Detached prototype)
│   ├── css/
│   │   └── styles.css               # Complete SPA Light Theme CSS (Design Tokens from schemes.md)
│   └── js/
│       ├── config.js                # API Base URL & Frontend Constants
│       ├── api.js                   # Centralized Fetch API Client Layer
│       ├── state.js                 # Central Reactive State Store
│       ├── app.js                   # SPA Entrypoint & Tab Router Initialization
│       └── components/
│           ├── navbar.js            # Top Header & Navigation Switcher Component
│           ├── explorer.js          # Triage Table, Search & Filter Accordion Component
│           ├── detail_modal.js      # Vulnerability Detail Analyst Drawer & EPSS Snapshot Callout
│           ├── prediction_view.js   # EXP-A1 CVSS & EXP-B2 Publication-Time KEV Forms
│           ├── prioritization_view.js # Controlled Asset Tier Slider & Dual-Mode Scoring
│           ├── explanation_view.js  # SHAP Feature Contribution Waterfall Component
│           └── provenance_view.js   # Academic Research Provenance & Freeze Manifest
├── data/                            # Research & Processed Data Storage
│   ├── raw/                         # Frozen Raw Datasets (NVD, EPSS, KEV, Vendor)
│   ├── processed/                   # Deterministic Parquet Files (366,547 Canonical CVEs)
│   └── experiments/
│       └── phase3/                  # Reconstructed Model Binaries & SHAP Data
│           ├── exp_a1/              # EXP-A1 XGBoost Regressor, Vectorizer, Feature Names
│           ├── exp_b2/              # EXP-B2 XGBoost Classifier, Vectorizer, Feature Names
│           └── shap/                # Pre-computed SHAP Summary Arrays
├── docs/                            # Project Documentation
│   ├── architecture/
│   │   ├── API.md                   # OpenAPI Endpoint Specifications
│   │   └── PHASE_4_BACKEND_ARCHITECTURE.md # Backend System Architecture Document
│   └── research/                    # Phase 0–3 Research Reports & Manifests
├── scripts/                         # Research & ETL Scripts
│   ├── build_processed_data.py       # Canonical ETL Pipeline Script
│   ├── compare_rebuilds.py          # Deterministic Rebuild Verification
│   ├── fingerprint_processed_data.py# Parquet Hashing & Fingerprinting
│   ├── verify_raw_data.py           # Raw Dataset Verification Script
│   └── experiments/
│       └── serialize_phase3_models.py # Deterministic Model Reconstruction & Serialization
├── src/                             # Ingestion Pipeline Source Code
│   └── ingestion/                   # Raw Schemas & Parser Modules (nvd, epss, kev, cpe, cwe)
├── tests/                           # Automated Test Suite
│   ├── test_backend_api.py          # 9 REST API & Boundary Invariant Tests
│   └── test_etl_invariants.py       # 15 Deterministic Data Invariant Tests
├── README.md                        # Project Overview Readme
└── schemes.md                       # Design System Color Palette Reference
```

---

## 3. Existing Frontend

- **Framework**: Built using **Vanilla JavaScript (ES Modules)**, standard **HTML5**, and **Vanilla CSS** with custom CSS properties / design tokens. Zero frontend framework dependencies (React, Vue, or Svelte are not used).
- **Routing**: Single-Page Application (SPA) tab routing controlled in `frontend/js/app.js` and `frontend/js/state.js`. Views are rendered dynamically into `<section>` tags (`#view-explorer`, `#view-predict`, `#view-prioritize`, `#view-explain`, `#view-provenance`) toggled via navbar tab clicks.
- **Pages / Views**:
  1. `Triage Explorer` (`components/explorer.js`): High-density triage table with multi-parameter search (free text `q`, `cve_id`, `cwe_id`, `vendor`, `product`, `min_cvss`, `max_cvss`, `is_kev`, `min_epss`, `publication_year`), pagination, status badges, and detail drawer trigger.
  2. `Vulnerability Detail Drawer` (`components/detail_modal.js`): Analyst drawer displaying official NVD CVSS score, CVSS vector, CWE taxonomy, CPE applicability, vendor statements, KEV details, and **separately exposed current EPSS snapshot (`2026-07-16`)** with explicit non-historical warning callouts.
  3. `Predictive Analysis Workspace` (`components/prediction_view.js`): Forms for pre-scoring EXP-A1 CVSS estimation and EXP-B2 publication-time KEV risk prediction.
  4. `Prioritization Sandbox` (`components/prioritization_view.js`): Controlled Asset Criticality Tier slider ($A \in [0.25, 1.00]$: Tiers 1–4) comparing Mode 1 Linear ($S_{\text{linear}}$) vs Mode 2 Nonlinear ($S_{\text{nonlinear}}$) prioritization scores.
  5. `SHAP Explainability View` (`components/explanation_view.js`): Visual feature attribution waterfall / horizontal bar charts for A1 and B2 predictions using real backend SHAP responses.
  6. `Research Provenance View` (`components/provenance_view.js`): Dataset freeze manifest, record counts, temporal partitions, Phase 3 experiment benchmarks, and research limitations.
- **State Management**: Reactive state store in `frontend/js/state.js` using a listener pub-sub pattern (`state.subscribe(listener)`).
- **API Client**: Centralized `ApiClient` class in `frontend/js/api.js` consuming `/api/v1/...` endpoints.
- **Styling**: Light Theme design system in `frontend/css/styles.css` derived from `schemes.md` (`--bg-base: #f9f9fe`, `--bg-surface: #ffffff`, `--primary: #45608a`, `--text-main: #2f323a`, `--error: #a83836`).
- **Responsive Behavior**: Flexbox and CSS Grid layout rules adapt desktop multi-column workspaces to single-column cards on smaller viewports.
- **Authentication State**: **CURRENTLY UNCONNECTED**. Legacy static prototype files (`login.html`, `register.html`, `script.js`) exist in `frontend/` but operate strictly via detached `localStorage` (`users`, `currentUser`) and are **not integrated** into the active SPA (`index.html`). The active SPA currently operates completely unauthenticated.

---

## 4. Existing Backend

- **Framework**: **FastAPI** running on Python 3.14 with `pydantic` v2 schema validation and `pydantic-settings` configuration management.
- **Endpoints**:
  - `GET /health`: System health and dataset freeze metadata.
  - `GET /api/v1/vulnerabilities`: Paginated search & multi-parameter filtering across 366,547 canonical CVEs.
  - `GET /api/v1/vulnerabilities/{cve_id}`: Complete vulnerability record details with isolated EPSS snapshot metadata.
  - `POST /api/v1/predict/cvss`: Pre-scoring CVSS v3.1 estimation (EXP-A1 XGBoost Regressor).
  - `POST /api/v1/predict/kev`: Publication-time KEV risk prediction (EXP-B2 XGBoost Classifier). Strictly rejects post-publication EPSS/CVSS inputs with HTTP 422.
  - `POST /api/v1/prioritize`: Dual-mode prioritization scoring (Mode 1 Linear vs Mode 2 Nonlinear surface across Tiers 1–4).
  - `POST /api/v1/explain/cvss` & `POST /api/v1/explain/kev`: Local SHAP TreeExplainer feature attributions.
  - `GET /api/v1/provenance`: System provenance, dataset freeze manifest, temporal partitions, and experiment benchmarks.
- **Services**:
  - `vulnerability_service.py`: Queries DuckDB over `data/processed/*.parquet`.
  - `inference_service.py`: Executes vectorization and XGBoost inference for A1 & B2 models.
  - `scoring_service.py`: Computes $S_{\text{linear}}$ and $S_{\text{nonlinear}}$ prioritization scores.
  - `explanation_service.py`: Generates SHAP feature contribution values.
  - `provenance_service.py`: Assembles academic freeze manifest and experiment metrics.
- **Data Access**: `backend/app/core/database.py` utilizes **DuckDB** in read-only mode over `data/processed/*.parquet`.
- **Authentication & Authorization**: **NONE**. All API endpoints are currently unauthenticated public endpoints. No JWT middleware, HTTP basic auth, API key check, session store, or RBAC authorization dependencies exist in the backend.
- **Error Handling**: Custom `ValueError` exception handler returning HTTP 422 Unprocessable Entity, standard Pydantic validation error responses, and HTTP 404 for unknown CVE IDs.
- **CORS**: Enabled via `CORSMiddleware` with `allow_origins=["*"]`.

---

## 5. Existing Research Integration

The research layer is directly integrated into the application via deterministic Parquet dataset queries and serialized XGBoost model binaries:

1. **Frozen Dataset Integration**:
   - `data/processed/vulnerabilities.parquet`: Contains 366,547 canonical CVEs (2002–2026).
   - `data/processed/epss.parquet`: Contains 348,900 static EPSS score records dated `2026-07-16T12:03:48Z` (Model `v2026.06.15`).
   - `data/processed/kev.parquet`: Contains 1,647 CISA Known Exploited Vulnerabilities catalog entries.
   - `data/processed/cve_cwe.parquet` & `cve_cpe.parquet`: Normalized child tables for CWE weaknesses and CPE applicability nodes.
2. **Model Integration**:
   - Reconstructed model binaries under `data/experiments/phase3/exp_a1/` and `exp_b2/` (`model.xgb`, `vectorizer.joblib`, `feature_names.json`).
   - Models were serialized from the exact Phase 3 TRAIN + VALIDATION partition (`publication_year <= 2024`, random seed 42) and verified against Phase 3 test predictions with **0.00000000 error match**.
3. **Publication-Time Boundary Invariant**:
   - Backend `KEVPredictionRequest` explicitly validates that no post-publication features (`epss`, `cvss_v31_base_score`, `cvss_v31_vector`) are accepted, enforcing temporal non-leakage.
4. **Scoring Surface Integration**:
   - Mode 1: Transparent Linear Baseline ($S_{\text{linear}} = 0.25 x_1 + 0.25 x_2 + 0.25 x_3 + 0.25 x_4$).
   - Mode 2: Nonlinear Interactive Surface ($S_{\text{nonlinear}} = x_4 [1 - (1 - x_1)^{1 + 1.0 x_3} (1 - x_2)^{1 + 1.5 x_3}]$).

---

## 6. Existing Testing

The repository contains **24 automated tests** across two pytest files in `tests/`:

1. **`tests/test_backend_api.py` (9 Tests)**:
   - `test_health_check`: Verifies system health status, repository identity, and dataset freeze date.
   - `test_vulnerability_search`: Tests multi-parameter pagination and filtering on `/api/v1/vulnerabilities`.
   - `test_vulnerability_detail_and_epss_separation`: Verifies CVE detail retrieval and strictly checks the EPSS snapshot separation invariant (`is_historical_prediction_input == False`).
   - `test_predict_cvss_estimation`: Tests EXP-A1 CVSS regression output and authoritative score comparison.
   - `test_predict_kev_publication_time_valid`: Tests valid EXP-B2 publication-time KEV probability prediction.
   - `test_predict_kev_rejects_epss_and_cvss_boundary_violation`: Verifies that passing prohibited post-publication fields (`epss`, `cvss_v31_base_score`) produces an **HTTP 422 error**.
   - `test_prioritization_scoring_modes`: Verifies mathematical correctness of Mode 1 Linear and Mode 2 Nonlinear prioritization formulas across Asset Criticality Tiers.
   - `test_shap_explanations`: Verifies SHAP TreeExplainer feature attributions and causal disclaimer presence.
   - `test_research_provenance`: Verifies `/api/v1/provenance` endpoint metrics and research limitations.

2. **`tests/test_etl_invariants.py` (15 Tests)**:
   - Verifies 15 data engineering invariants: canonical CVE row uniqueness, exact 366,547 CVE cardinality, SHA-256 raw file integrity, 348,900 EPSS rows, 1,647 KEV rows, score bounds $[0, 1]$ and $[0, 10]$, foreign key integrity, multi-CWE preservation, Parquet roundtrip readability, publication year parsing, EPSS metadata consistency (`v2026.06.15`), and CVSS v4 score preservation (29,964 scores).

All **24 / 24 automated tests pass cleanly**.

---

## 7. Existing Documentation

### Existing Documentation Files:
- [docs/architecture/API.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/architecture/API.md): Complete OpenAPI REST API endpoint specifications.
- [docs/architecture/PHASE_4_BACKEND_ARCHITECTURE.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/architecture/PHASE_4_BACKEND_ARCHITECTURE.md): Phase 4 backend system architecture document.
- [docs/research/DATA_MANIFEST.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/DATA_MANIFEST.md): Raw dataset provenance and SHA-256 checksums.
- [docs/research/PROCESSED_DATA_SCHEMA.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/PROCESSED_DATA_SCHEMA.md): Schema definitions for processed Parquet files.
- [docs/research/PHASE_0_DATA_AUDIT.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/PHASE_0_DATA_AUDIT.md) through [PHASE_3_RESULTS.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/PHASE_3_RESULTS.md): Full academic research reports covering Phase 0 raw data audit, Phase 1 ETL, Phase 2 protocol, and Phase 3 experiment execution.
- [README.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/README.md): High-level root README (contains obsolete references).

### Missing Documentation required for Web Design Lab:
- Comprehensive User Manual / Analyst Guide.
- System Software & Hardware Requirements Specification.
- System Architecture Overview (incorporating WDL frontend & auth).
- Complete End-to-End Installation & Setup Instructions.
- Role-Based Access Control (RBAC) Specification.
- Public Demonstration Deployment Documentation (`vuln-triage.seucra.tech`).

---

## 8. Existing Deployment

- **Local Running State**: The FastAPI application runs via Uvicorn (`PYTHONPATH=. .venv/bin/uvicorn backend.app.main:app --port 8000`), serving the backend API under `/api/v1` and mounting `frontend/` as static files under `/`.
- **Docker Configuration**: **MISSING**. No `Dockerfile` or `docker-compose.yml` exists in the repository.
- **Reverse Proxy / Tunnel Configuration**: **MISSING**. Cloudflare Tunnel (`cloudflared`) configuration files or scripts are not present in the workspace.
- **Domain Configuration**: Target production domains (`vuln-triage.seucra.tech` for frontend and `vuln-triage-api.seucra.tech` for backend) are specified in the prompt but not yet configured in local environment files.

---

## 9. Web Design Lab Requirement Matrix

| Requirement | Status | Evidence | Gap | Priority |
|---|---|---|---|---|
| Functional roles | MISSING | No role state in `frontend/js/state.js` or backend API endpoints | Security Analyst, Researcher, Administrator roles not defined or enforced | HIGH |
| Register | PARTIAL | `frontend/register.html` exists as a detached legacy static file using `localStorage` | Not integrated into main SPA (`index.html`), no role selection, no backend endpoint | HIGH |
| Login | PARTIAL | `frontend/login.html` exists as a detached legacy static file using `localStorage` | Not integrated into main SPA (`index.html`), no backend authentication API | HIGH |
| Logout | PARTIAL | `frontend/script.js` has legacy `logout()` clearing `localStorage` | Not wired into main SPA navbar or reactive session state | HIGH |
| Role-based access | MISSING | No RBAC middleware in FastAPI or route guards in SPA router | All tabs and API endpoints are unrestricted | HIGH |
| Landing page | MISSING | SPA opens directly into Triage Explorer view (`index.html`) | No dedicated public Landing Page with project objectives, research basis, and launch button | HIGH |
| Navigation | PARTIAL | `frontend/js/components/navbar.js` provides basic tab switching | Does not include Landing Page, About, Profile, Role badge, or Logout button | HIGH |
| About / Project | MISSING | No About view in `frontend/js/components/` | No view detailing research motivation, algorithms, datasets, limitations, and author info | MEDIUM |
| Documentation | PARTIAL | `docs/architecture/` and `docs/research/` exist; in-app views missing | No in-app User Manual, SRS, Setup Guide, or API doc view for users | MEDIUM |
| Error states | PARTIAL | Basic error banners in `explorer.js` and `prediction_view.js` | Missing dedicated states for Backend Unavailable, 404 CVE Not Found, Empty Search, and Invalid Inputs | MEDIUM |
| Responsive design | PARTIAL | Flexbox and basic CSS grid in `frontend/css/styles.css` | Untested on mobile/tablet viewports; drawer overflow on small screens | MEDIUM |
| Dashboard KPIs | MISSING | No top-level dashboard overview card grid | Missing aggregate KPI cards (Total CVEs, KEV Count, Critical Count, EPSS High Risk Count) | MEDIUM |
| Search/recent history | MISSING | Search params stored only in volatile memory state | No search history dropdown or recent CVE lookup history tracking | LOW |
| Export | MISSING | No export buttons in table or detail drawer | No CSV/JSON export functionality for triage results or vulnerability records | MEDIUM |
| Printable report | MISSING | No print styles or export report handler | No printable PDF/A4 triage summary report layout | MEDIUM |
| Feedback/contact | MISSING | No contact or feedback component | No feedback form or contact modal | LOW |
| FAQ | MISSING | No FAQ documentation section | No expandable FAQ accordion for research scoring and dataset questions | LOW |
| Accessibility | PARTIAL | Semantic HTML tags and readable contrast in CSS | Missing ARIA attributes (`aria-expanded`, `aria-modal`), keyboard focus traps, and screen reader labels | MEDIUM |
| Frontend deployment | MISSING | App runs locally on `http://localhost:8000` | Cloudflare Tunnel / domain setup for `vuln-triage.seucra.tech` missing | HIGH |
| Backend deployment | MISSING | Backend runs locally on port 8000 | Production configuration and deployment docs for `vuln-triage-api.seucra.tech` missing | HIGH |
| Demo flow | PARTIAL | Individual tabs exist in SPA | Structured role-based demonstration flow (Landing -> Register -> Login -> Role Dashboard -> Demo Flow -> Logout) missing | HIGH |

---

## 10. Conflicts / Obsolete Decisions

1. **`README.md` File Discrepancies**:
   - Root `README.md` lists Streamlit as the visualization layer, Pandas/PyArrow as the storage stack, and directories like `dashboard/` and `models/`.
   - *Actual Codebase*: The application uses a Vanilla JS SPA frontend (`frontend/`), FastAPI backend (`backend/`), DuckDB query engine over Parquet (`data/processed/*.parquet`), and serialized XGBoost binaries in `data/experiments/phase3/`.
2. **Legacy Detached Prototype Files**:
   - `frontend/login.html`, `frontend/register.html`, `frontend/script.js`, and `frontend/style.css` exist in `frontend/`. They store mock users in browser `localStorage` and operate as detached multi-page HTML forms.
   - *Actual Codebase*: Main application operates as an SPA (`frontend/index.html` + `frontend/js/app.js`). The legacy prototype files are not linked to `index.html` or the FastAPI backend.
3. **Unauthenticated Backend Assumptions**:
   - Earlier prototype phases assumed auth was out of scope.
   - *Actual Codebase*: All 7 REST API routes under `/api/v1/` are public and unauthenticated.
4. **Single-Role Explorer View vs Role-Based Dashboards**:
   - The current UI launches directly into the Triage Explorer table without a landing page, role selection, or role-specific dashboards.

---

## 11. Proposed Final Information Architecture

The application will be restructured into a cohesive Single-Page Application with role-based view routing and public landing pages.

```text
+---------------------------------------------------------------------------------------------------+
|                                 APPLICATION ROUTES & NAVIGATION                                   |
+---------------------------------------------------------------------------------------------------+
|  PUBLIC ROUTES (No Login Required)                                                                |
|  - /#landing       : Public Landing Page (Title, Problem, Features, Research Basis, Launch Button) |
|  - /#about         : Research & Project Details (Motivation, Datasets, Limitations, Authors)      |
|  - /#docs          : Integrated Documentation (User Manual, System Architecture, API Spec)        |
|  - /#login         : Demonstration Login Form (Role Selector + Credentials)                       |
|  - /#register      : Demonstration User Registration Form (Name, Email, Password, Desired Role)   |
+---------------------------------------------------------------------------------------------------+
|  PROTECTED ROLE-BASED ROUTES (Session Required)                                                  |
|                                                                                                   |
|  [Security Analyst Role]                                                                          |
|  - /#dashboard     : Security Analyst Dashboard (KPIs, Active KEV Alerts, Quick Triage Actions)   |
|  - /#explorer      : Vulnerability Triage Explorer (Search, Filters, High-Density Table, Detail)  |
|  - /#predict       : Predictive Workspace (EXP-A1 CVSS Estimation & EXP-B2 Publication KEV Risk)  |
|  - /#prioritize    : Prioritization Sandbox (Asset Tier Slider $A \in [0.25, 1.00]$, Dual-Mode)   |
|  - /#explain       : SHAP Explainability (Local TreeExplainer Feature Attributions & Disclaimers) |
|  - /#profile       : User Profile & Session Metadata                                              |
|                                                                                                   |
|  [Researcher Role]                                                                                |
|  - /#dashboard     : Researcher Dashboard (Experiment Benchmark Comparison, Dataset Metrics)      |
|  - /#provenance    : Research Provenance (Dataset Freeze Manifest, Temporal Discipline, Limitations)|
|  - /#explain       : SHAP Model Explainability Inspection                                         |
|  - /#explorer      : Read-Only Vulnerability & Feature Explorer                                   |
|  - /#profile       : User Profile & Session Metadata                                              |
|                                                                                                   |
|  [Administrator Role]                                                                             |
|  - /#dashboard     : System Admin Dashboard (System Health, Data Freeze Status, Session Monitor)   |
|  - /#admin-users   : User & Role Management Demo Panel                                            |
|  - /#provenance    : System & Dataset Provenance Audit                                            |
|  - /#profile       : User Profile & Session Metadata                                              |
+---------------------------------------------------------------------------------------------------+
```

---

## 12. Proposed Authentication / Authorization Architecture

To fulfill the Web Design Lab requirements without altering backend research logic or over-engineering enterprise security:

1. **Lightweight Token / Session Architecture**:
   - Introduce an `auth_service` and `auth` router in FastAPI (`/api/v1/auth/register`, `/api/v1/auth/login`, `/api/v1/auth/me`).
   - Authentication will issue a signed **JWT or Session Token** containing `user_id`, `email`, `name`, and `role` (`analyst`, `researcher`, `admin`).
   - Store user accounts in an in-memory/JSON store for demonstration purposes (pre-seeded with demo accounts for each role).
2. **Server-Side Role-Based Authorization (RBAC)**:
   - Implement a FastAPI dependency `get_current_user` and `require_roles(["analyst", "admin"])`.
   - Protect sensitive endpoints (e.g. `/predict/*`, `/prioritize`, `/admin/*`) with server-side role validation.
3. **Frontend Session & Route Guard Integration**:
   - Update `frontend/js/state.js` to store `currentUser`, `authToken`, and `currentRole`.
   - Update `frontend/js/api.js` to automatically inject `Authorization: Bearer <token>` headers.
   - SPA Router in `frontend/js/app.js` will enforce client-side navigation guards: redirecting unauthenticated users to `/#login` and hiding navbar options not permitted for the user's role.

---

## 13. Proposed Implementation Phases

### Phase WDL-1: Information Architecture & SPA Shell Restructuring
- **Objective**: Establish the unified multi-view SPA navigation shell, public landing page, about view, and integrated documentation layout.
- **Affected Files**: `frontend/index.html`, `frontend/css/styles.css`, `frontend/js/app.js`, `frontend/js/state.js`, `frontend/js/components/navbar.js`, `frontend/js/components/landing_view.js` (new), `frontend/js/components/about_view.js` (new), `frontend/js/components/docs_view.js` (new).
- **Dependencies**: None.
- **Expected Result**: Clean top-level SPA navigation supporting Landing Page, About, Docs, Explorer, Predict, Prioritize, Explain, and Provenance.
- **Verification Method**: Browser navigation check across public pages and SPA tabs.

### Phase WDL-2: Demonstration Authentication & Server-Side RBAC
- **Objective**: Build demonstration authentication (Register, Login, Logout) and server-side/client-side Role-Based Access Control for `Security Analyst`, `Researcher`, and `Administrator`.
- **Affected Files**:
  - Backend: `backend/app/schemas/auth.py` (new), `backend/app/services/auth_service.py` (new), `backend/app/api/v1/auth.py` (new), `backend/app/api/router.py`, `backend/app/core/security.py` (new).
  - Frontend: `frontend/js/api.js`, `frontend/js/state.js`, `frontend/js/components/auth_view.js` (new), `frontend/js/components/navbar.js`, `frontend/js/app.js`.
- **Dependencies**: Phase WDL-1.
- **Expected Result**: Full auth flow (Register -> Login -> Role Assignment -> Protected Route Guarding -> Token Persistence -> Logout).
- **Verification Method**: Pytest endpoint tests for `/api/v1/auth/*` and browser auth flow testing across 3 roles.

### Phase WDL-3: Role-Specific Dashboards & Admin Panel
- **Objective**: Implement distinct dashboard landing views tailored to each role (Security Analyst Dashboard, Researcher Dashboard, Administrator System Dashboard).
- **Affected Files**: `frontend/js/components/dashboard_view.js` (new), `frontend/js/components/admin_view.js` (new), `frontend/js/state.js`, `frontend/js/app.js`.
- **Dependencies**: Phase WDL-2.
- **Expected Result**: Role-specific dashboard layouts displaying relevant KPIs, quick actions, and admin management controls upon login.
- **Verification Method**: Logging in as Analyst, Researcher, and Admin to verify distinct UI views and role-restricted features.

### Phase WDL-4: Application Error States & Supporting Features
- **Objective**: Implement comprehensive application states (Backend Offline, Loading, 404 CVE Not Found, Empty Search, Invalid Input, 422 Errors), CSV/JSON data export, search history tracking, and printable triage reports.
- **Affected Files**: `frontend/js/components/explorer.js`, `frontend/js/components/detail_modal.js`, `frontend/js/components/prediction_view.js`, `frontend/css/styles.css`, `frontend/js/utils/export.js` (new).
- **Dependencies**: Phase WDL-1, WDL-3.
- **Expected Result**: Friendly user error recovery, one-click CSV/JSON dataset export, printable A4 vulnerability summary reports, and search history dropdowns.
- **Verification Method**: Simulating backend errors, triggering invalid inputs, clicking export buttons, and printing vulnerability report views.

### Phase WDL-5: Responsive Design, Accessibility & Visual Polish
- **Objective**: Audit and polish responsive layout across Mobile, Tablet, Laptop, and Desktop viewports, enforce WCAG contrast guidelines, keyboard focus traps, and ARIA labels.
- **Affected Files**: `frontend/css/styles.css`, `frontend/index.html`, `frontend/js/components/*.js`.
- **Dependencies**: Phase WDL-4.
- **Expected Result**: Fully responsive layout across viewports with 100% keyboard accessibility and clean visual transitions.
- **Verification Method**: Browser viewport resizing, keyboard tab navigation testing, and DevTools accessibility audit.

### Phase WDL-6: Public Demonstration Deployment & Documentation Finalization
- **Objective**: Create Docker configuration, Cloudflare Tunnel / reverse proxy instructions for `vuln-triage.seucra.tech` and `vuln-triage-api.seucra.tech`, and compile the complete documentation suite (User Manual, SRS, Setup, Architecture, Limitations).
- **Affected Files**: `Dockerfile` (new), `docker-compose.yml` (new), `docs/USER_MANUAL.md` (new), `docs/SYSTEM_REQUIREMENTS.md` (new), `docs/DEPLOYMENT.md` (new), `README.md` (updated).
- **Dependencies**: Phase WDL-1 through WDL-5.
- **Expected Result**: Production-ready deployment artifacts, clear deployment guide, updated root README, and comprehensive user documentation.
- **Verification Method**: Building Docker container, executing end-to-end integration tests, and validating documentation completeness.

---

## 14. Dependency / Risk Analysis

1. **Research Data Integrity Risk**:
   - *Risk*: Introducing user management or UI modifications could accidentally alter frozen Parquet files, raw datasets, or Phase 3 model binaries.
   - *Mitigation*: Data files in `data/processed/*.parquet` and model binaries in `data/experiments/phase3/` must remain read-only. DuckDB query engine maintains strict read-only connections.
2. **Authentication Complexity Risk**:
   - *Risk*: Over-engineering user authentication with complex database dependencies (e.g. PostgreSQL, Alembic migrations) would bloat the research prototype.
   - *Mitigation*: Implement demonstration-level authentication using an in-memory/JSON user store with pre-seeded role credentials and lightweight JWT tokens.
3. **Temporal Feature Boundary Leakage Risk**:
   - *Risk*: Adding new UI inputs or forms could accidentally pass post-publication features (EPSS, CVSS vector) into the EXP-B2 publication-time prediction endpoint.
   - *Mitigation*: Preserve strict backend validation in `KEVPredictionRequest` rejecting post-publication fields with HTTP 422.
4. **Browser Compatibility & Storage Scope**:
   - *Risk*: Reliance on detached legacy HTML files (`login.html`) breaks single-page state flow.
   - *Mitigation*: Migrate all auth forms directly into SPA modular components inside `frontend/js/components/auth_view.js` and maintain token state in `frontend/js/state.js`.

---

## 15. Recommended Implementation Order

The recommended sequence for executing the implementation work is:

1. **Phase WDL-1**: SPA Shell Restructuring & Public Pages (Landing, About, Docs Views).
2. **Phase WDL-2**: Demonstration Authentication Backend & Server/Client RBAC.
3. **Phase WDL-3**: Role-Specific Dashboards (Analyst, Researcher, Admin Views).
4. **Phase WDL-4**: Error Handling, Search History, Exports & Printable Reports.
5. **Phase WDL-5**: Responsive Design & Accessibility Polish.
6. **Phase WDL-6**: Deployment Artifacts (Docker, Tunnel Specs) & System Documentation.

---

## 16. STOP CONDITIONS

During the Web Design Lab implementation phase, the following components **MUST NOT BE TOUCHED OR MODIFIED**:

> [!CAUTION]
> **IMMUTABLE RESEARCH & DATA COMPONENTS**
> 1. **Frozen Datasets**: Do NOT modify, rewrite, re-extract, or clean `data/processed/*.parquet` or raw files in `data/raw/`.
> 2. **ETL Scripts**: Do NOT alter `scripts/build_processed_data.py`, `src/ingestion/`, or data schemas.
> 3. **Phase 3 Research Methodology**: Do NOT modify temporal split boundaries (Train: 2002–2022, Val: 2023–2024, Test: 2025–2026), target definitions, feature construction, or hyperparameter configurations.
> 4. **Serialized Model Binaries**: Do NOT retrain or re-serialize XGBoost models in `data/experiments/phase3/`.
> 5. **Prioritization Scoring Formulations**: Do NOT change Mode 1 ($S_{\text{linear}}$) or Mode 2 ($S_{\text{nonlinear}}$) scoring formulas in `backend/app/services/scoring_service.py`.
> 6. **Temporal Feature Boundary**: Do NOT remove the strict backend HTTP 422 rejection of post-publication features on `/api/v1/predict/kev`.