# FINAL REPOSITORY STATE REPORT

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Audit Date**: August 23, 2026  
**Scope**: Complete ground-truth repository audit covering architecture, datasets, machine learning models, REST API, RBAC, frontend SPA, tests, CI/CD pipeline, and public deployment topology.

---

## 1. Current Directory / File Architecture

The repository is structured as a decoupled Python/FastAPI backend and a vanilla JavaScript (ES Modules) Single Page Application (SPA) frontend:

```text
vulnarability-prioritization-triage-system/
├── .github/
│   └── workflows/
│       └── deploy_frontend.yml         # GitHub Actions CI & Pages deployment
├── backend/
│   └── app/
│       ├── main.py                     # FastAPI entrypoint & static file server
│       ├── config.py                   # Environment settings, CORS, research constants
│       ├── api/
│       │   ├── router.py               # Central APIRouter assembly
│       │   ├── deps.py                 # RBAC dependencies (get_current_user, require_role)
│       │   └── v1/                     # Auth, vulnerabilities, predict, prioritize, explain, provenance
│       ├── core/
│       │   ├── database.py             # DuckDB parquet query manager
│       │   ├── auth_db.py              # SQLite user account persistence
│       │   ├── security.py             # PBKDF2 hashing & HMAC-SHA256 JWT tokens
│       │   └── exceptions.py           # Core exceptions (e.g. ModelNotLoadedException)
│       ├── schemas/                    # Pydantic request/response schemas
│       └── services/                   # Auth, vulnerability, inference, scoring, explanation, provenance
├── frontend/
│   ├── index.html                      # SPA entrypoint DOM shell
│   ├── CNAME                           # GitHub Pages custom domain (vuln-triage.seucra.tech)
│   ├── css/
│   │   └── styles.css                  # CSS design system & responsive rules
│   └── js/
│       ├── config.js                   # Environment-aware API domain resolution
│       ├── state.js                    # Reactive AppState with synchronous localStorage hydration
│       ├── api.js                      # REST ApiClient with Bearer token injection
│       ├── app.js                      # Hash router, route guards, session verification
│       └── components/                 # 19 UI view controllers & role dashboards
├── data/
│   ├── raw/                            # Frozen raw feeds (nvd, cpe, epss, kev, vendor)
│   ├── processed/                      # Normalized Parquet files (vulnerabilities, cve_cwe, etc.)
│   ├── experiments/                    # Phase 2 metrics & Phase 3 ML artifacts (exp_a1, exp_b2, shap)
│   └── auth_users.sqlite               # Persistent SQLite database for user accounts
├── docs/
│   ├── research/                       # Phase 0-3 reports, data manifests, schemas, profiles
│   ├── architecture/                   # Phase 4 architecture, auth/RBAC, role dashboards, API specs
│   ├── DEPLOYMENT.md                   # Deployment architecture guide
│   └── functionality-audit.md          # Web application audit documentation
├── scripts/                            # ETL, verification, dataset characterization, and ML training scripts
├── src/                                # Ingestion module (nvd, cpe, epss, kev, vendor parsers)
├── tasks/                              # Task breakdown files (e.g. phase0.md)
├── tests/                              # Automated Pytest suite (test_auth_rbac, test_backend_api, test_etl_invariants)
├── toRead/                             # Academic paper drafts & viva preparation guides
└── SKILL-frontend-design.md            # Frontend visual design guidelines
```

---

## 2. Research / Data Pipeline

- **Ingestion (`src/ingestion/`)**: Parsers for NVD JSON feeds ([nvd.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/src/ingestion/nvd.py)), CPE dictionary ([cpe.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/src/ingestion/cpe.py)), EPSS CSV snapshots ([epss.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/src/ingestion/epss.py)), CISA KEV catalog ([kev.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/src/ingestion/kev.py)), and vendor security advisories ([vendor.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/src/ingestion/vendor.py)).
- **Build Pipeline ([scripts/build_processed_data.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/scripts/build_processed_data.py))**: Generates 6 normalized Apache Parquet tables under `data/processed/`:
  1. `vulnerabilities.parquet`: **366,547 total CVEs** (2002–2026 dataset freeze: 2026-07-26).
  2. `cve_cwe.parquet`: Mappings from CVEs to Weakness Enumeration IDs.
  3. `cve_cpe.parquet`: Affected product mappings.
  4. `epss.parquet`: EPSS probability scores (Snapshot date: `2026-07-16T12:03:48Z`).
  5. `kev.parquet`: CISA Known Exploited Vulnerabilities catalog entries.
  6. `vendor_statements.parquet`: Vendor patch/advisory statements.
- **Reproducibility & Verification**: Fingerprinted using SHA-256 via [scripts/fingerprint_processed_data.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/scripts/fingerprint_processed_data.py) and verified by `tests/test_etl_invariants.py`.

---

## 3. Research Phase Status (Phases 0–3)

- **Phase 0 (Data Audit & Feasibility)**: Complete. Documented in [PHASE_0_DATA_AUDIT.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/PHASE_0_DATA_AUDIT.md).
- **Phase 1 (ETL & Schema Standardization)**: Complete. Documented in [PHASE_1_ETL_REPORT.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/PHASE_1_ETL_REPORT.md).
- **Phase 2 (Dataset Characterization & Profiling)**: Complete. Documented in [PHASE_2_DATA_PROFILE.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/PHASE_2_DATA_PROFILE.md) and [PHASE_2_EXPERIMENTAL_PROTOCOL.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/PHASE_2_EXPERIMENTAL_PROTOCOL.md). Metrics serialized to `data/experiments/phase2_metrics.json`.
- **Phase 3 (Machine Learning & Scoring Surface)**: Complete. Documented in [PHASE_3_EXPERIMENT_REPORT.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/PHASE_3_EXPERIMENT_REPORT.md) and [PHASE_3_RESULTS.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/PHASE_3_RESULTS.md).

---

## 4. Phase 4 Backend Status

- Fully implemented using **FastAPI** running on **Uvicorn** (`http://127.0.0.1:5002`).
- Entrypoint at [backend/app/main.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/main.py).
- Features dynamic CORS configuration ([config.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/config.py)), DuckDB Parquet querying ([database.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/core/database.py)), SQLite user store ([auth_db.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/core/auth_db.py)), and HTTP `no-cache` middleware for static frontend assets.
- Serves interactive OpenAPI documentation at `/api/v1/docs` and `/api/v1/openapi.json`.

---

## 5. Frontend / UI Status

- **Technology**: Single Page Application built with native HTML5, JavaScript (ES Modules), and CSS variables. Frameworkless.
- **Routing**: Hash-based client router ([frontend/js/app.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/app.js)).
- **State Management**: Centralized reactive state ([frontend/js/state.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/state.js)) with synchronous `localStorage` hydration (`wdl_auth_token` and `wdl_user`).
- **Responsive Layout**: Hardened for mobile devices across 320px, 375px, 390px, 430px, 768px, 1024px, and 1440px viewports with a collapsible hamburger navigation menu ([navbar.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/components/navbar.js)) and overflow protection.
- **Supporting Features**: Includes PDF/JSON triage report printing (`@media print`), data export (CSV/JSON), integrated API documentation ([docs_view.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/components/docs_view.js)), FAQ ([faq_view.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/components/faq_view.js)), and Contact/Feedback workspace ([contact_view.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/components/contact_view.js)).

---

## 6. Authentication and RBAC Status

- **Database**: SQLite database at `data/auth_users.sqlite` managed by [auth_db.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/core/auth_db.py).
- **Password Security**: PBKDF2 with SHA-256 (100,000 iterations) and 16-byte random salts.
- **Tokens**: Signed HMAC-SHA256 JWT access tokens.
- **RBAC Roles**:
  - `analyst`: Access to triage explorer, prioritization calculator, export tools.
  - `researcher`: Access to ML inference predictions, SHAP feature attributions, research provenance, dataset metrics.
  - `admin`: Full system administrative access, user account management (enable/disable users), global metrics.
- **Dependencies**: `get_current_user` and `require_role(...)` in [backend/app/api/deps.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/api/deps.py).

---

## 7. Dashboard / Role Workflows

- **Shared Shell ([dashboard_view.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/components/dashboard_view.js))**: Evaluates active user context and routes to specific role dashboards:
  1. **Security Analyst Dashboard ([analyst_dashboard.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/components/analyst_dashboard.js))**: Triage queue metrics, high-risk CVE focus list, quick prioritization shortcut, export tools.
  2. **Researcher Dashboard ([researcher_dashboard.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/components/researcher_dashboard.js))**: Model performance benchmarks (EXP-A1 MAE, EXP-B2 ROC-AUC), feature attribution insights, model version manifests.
  3. **Administrator Dashboard ([admin_dashboard.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/components/admin_dashboard.js))**: Account statistics, active user table, administrative account status toggle (enable/disable), system engine health status.

---

## 8. API Endpoints Currently Implemented

| Method | Path | Access | Summary |
|---|---|---|---|
| `POST` | `/api/v1/auth/register` | Public | Register new `analyst` or `researcher` account |
| `POST` | `/api/v1/auth/login` | Public | Authenticate user and issue JWT bearer token |
| `GET` | `/api/v1/auth/me` | Bearer Token | Fetch active authenticated user context |
| `POST` | `/api/v1/auth/logout` | Bearer Token | Invalidates session token context |
| `GET` | `/api/v1/auth/admin/users` | Bearer (`admin`) | List all registered user accounts |
| `PATCH` | `/api/v1/auth/admin/users/{user_id}/status` | Bearer (`admin`) | Enable or disable a user account |
| `GET` | `/api/v1/vulnerabilities` | Public | Search/filter 366,547 CVEs with pagination & sorting |
| `GET` | `/api/v1/vulnerabilities/{cve_id}` | Public | Retrieve detailed record for a specific CVE |
| `POST` | `/api/v1/predict/cvss` | Bearer Token | Estimate CVSS v3.1 base score using EXP-A1 XGBoost |
| `POST` | `/api/v1/predict/kev` | Bearer Token | Predict publication-time KEV listing using EXP-B2 |
| `POST` | `/api/v1/prioritize` | Bearer Token | Compute Mode 1 Linear & Mode 2 Nonlinear scores |
| `POST` | `/api/v1/explain/cvss` | Bearer Token | Compute SHAP feature attributions for EXP-A1 model |
| `POST` | `/api/v1/explain/kev` | Bearer Token | Compute SHAP feature attributions for EXP-B2 model |
| `GET` | `/api/v1/provenance` | Public | Fetch dataset freeze dates, EPSS snapshot metadata, file SHA-256 hashes |
| `GET` | `/health` | Public | Backend engine health check |

---

## 9. Models and Inference Artifacts

Located under `data/experiments/phase3/`:
- **EXP-A1 (CVSS Regressor)**:
  - Artifacts: `model.xgb`, `vectorizer.joblib`, `feature_names.json`, `metrics.json`
  - Purpose: Pre-scoring estimation of CVSS v3.1 base scores from text descriptions and CWEs before formal NVD scoring.
  - Metrics: Test MAE = 0.8921, RMSE = 1.1843, $R^2$ = 0.5842.
- **EXP-B2 (KEV Classifier - Text + Meta + EPSS)**:
  - Artifacts: `model.xgb`, `vectorizer.joblib`, `feature_names.json`, `metrics.json`
  - Purpose: Publication-time prediction of CISA KEV catalog inclusion.
  - Metrics: Test ROC-AUC = 0.9412, PR-AUC = 0.3845, F1 = 0.4120.
- **EXP-B1 & EXP-C1**: Metrics and simulation rankings serialized (`metrics.json`, `simulation_rankings.parquet`).
- **Inference Service ([inference_service.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/services/inference_service.py))**: Handles TF-IDF vectorization, feature assembly, model execution, and handles missing binaries by raising `ModelNotLoadedException` (HTTP 503).

---

## 10. Prioritization / Scoring Implementation

Implemented in [backend/app/services/scoring_service.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/services/scoring_service.py) and [prioritization_view.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/components/prioritization_view.js):

- **Mode 1 — Transparent Linear Baseline**:
  $$\text{Priority}_{\text{linear}} = 0.25 \cdot x_1 + 0.25 \cdot x_2 + 0.25 \cdot x_3 + 0.25 \cdot x_4$$
- **Mode 2 — Nonlinear Interactive Surface**:
  $$\text{Priority}_{\text{nonlinear}} = x_4 \cdot \left[ 1 - (1 - x_1)^{1 + 1.0 \cdot x_3} \cdot (1 - x_2)^{1 + 1.5 \cdot x_3} \right]$$
  where:
  - $x_1$: Authoritative CVSS v3.1 Base Score normalized ($\frac{\text{CVSS}}{10.0}$)
  - $x_2$: EPSS Snapshot Probability ($0.0 - 1.0$)
  - $x_3$: CISA KEV Catalog Presence ($1.0$ if listed, $0.0$ if unlisted)
  - $x_4$: Asset Criticality Tier ($0.25$ Low, $0.50$ Medium, $0.75$ High, $1.00$ Critical)
  - $\alpha = 1.0$, $\beta = 1.5$: KEV multiplier interaction weights.

---

## 11. SHAP / Explainability Implementation

Implemented in [backend/app/services/explanation_service.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/services/explanation_service.py) and [explanation_view.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/components/explanation_view.js):
- Uses `shap.TreeExplainer` on the frozen XGBoost model binaries.
- Converts input vulnerability description text and CWE list into TF-IDF and categorical features, computes raw SHAP margin values, and returns top positive and negative feature attributions.

---

## 12. Testing Status & Test Results

**Status**: **100% PASSING**.

Executed command:
```bash
.venv/bin/python -m pytest tests/test_auth_rbac.py tests/test_backend_api.py tests/test_etl_invariants.py
```
**Results**:
- `tests/test_auth_rbac.py`: **16 passed**
- `tests/test_backend_api.py`: **8 passed**
- `tests/test_etl_invariants.py`: **15 passed**
- **Total**: **39 passed** in 22.14s (0 failures, 6 deprecation/UBJSON warnings).

---

## 13. Deployment Configuration

- **Frontend Hosting**: **GitHub Pages** static site hosting.
- **Backend Hosting**: Local FastAPI Uvicorn process bound to `127.0.0.1:5002` exposed publicly via a **Cloudflare Tunnel**.

---

## 14. GitHub Pages Configuration

- Configured via repository file [frontend/CNAME](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/CNAME) (`vuln-triage.seucra.tech`).
- Built and published automatically by GitHub Actions workflow [.github/workflows/deploy_frontend.yml](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/.github/workflows/deploy_frontend.yml) on pushes to `main`. Only the `./frontend` directory is published.

---

## 15. Cloudflare Tunnel / API Configuration

- Production API Domain: `https://vuln-triage-api.seucra.tech`
- Target: Local FastAPI server listening on `http://localhost:5002`.
- CORS Configuration ([config.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/config.py)): Explicitly permits origin `https://vuln-triage.seucra.tech` with `allow_credentials=True`.

---

## 16. Current Production / Public URLs

- **Frontend SPA**: `https://vuln-triage.seucra.tech`
- **Backend API Base**: `https://vuln-triage-api.seucra.tech`
- **Backend Health Check**: `https://vuln-triage-api.seucra.tech/health` (returns HTTP 200 `healthy`)
- **OpenAPI Interactive Documentation**: `https://vuln-triage-api.seucra.tech/api/v1/docs`

---

## 17. Current Limitations

1. **Static Dataset Freeze**: Parquet datasets represent a static historical snapshot frozen as of `2026-07-26` (EPSS snapshot date `2026-07-16`). Live real-time NVD API polling is not executed at runtime.
2. **Single Host Backend**: Backend API requires an active local Uvicorn process and Cloudflare Tunnel daemon running on the host machine.
3. **SQLite User Store**: User accounts are stored in a local SQLite file (`data/auth_users.sqlite`) without multi-region database replication.

---

## 18. Features That Are Explicitly NOT Implemented

1. **Real-time Live NVD Polling**: Real-time webhook ingestion or dynamic live sync from NVD/EPSS APIs.
2. **Third-Party OAuth / SSO**: No Google, GitHub, or SAML SSO integration.
3. **Database Write-Back for CVEs**: The vulnerability dataset (`vulnerabilities.parquet`) is strictly read-only.
4. **Cloud Container Hosting (AWS/GCP/Kubernetes)**: Backend is intentionally hosted via local Uvicorn + Cloudflare Tunnel rather than AWS ECS, GCP Cloud Run, or Kubernetes.

---

## 19. Items Existing Only as Documentation / Planned Scope

- **Advanced Multi-Tenancy Enterprise RBAC**: Fine-grained departmental permissions beyond `analyst`, `researcher`, and `admin`.
- **Dynamic Model Retraining Pipeline**: Automated CI pipeline for re-fitting XGBoost models on new NVD releases.

---

## 20. Stale or Inconsistent Items in Repository

1. **FastAPI Port Inconsistency in Early Docs**: Early Phase 4 documentation ([PHASE_4_BACKEND_ARCHITECTURE.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/architecture/PHASE_4_BACKEND_ARCHITECTURE.md)) referenced port `8000`. The actual implemented backend port is **`5002`** (configured in [config.js](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/frontend/js/config.js) and [config.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/config.py)).
2. **Deprecated Pip Cache in CI Workflow**: Original workflow tried to use `cache: 'pip'` without a `requirements.txt` or `pyproject.toml`. Fixed in commit `60b56db` by removing `cache: 'pip'`.
3. **Unused Dependencies in Early Docs**: Mention of Redis / Celery in early design brainstorming docs. Current implementation uses lightweight DuckDB, SQLite, and in-memory FastAPI services without external message queues.

---

## AUDIT SUMMARY SECTIONS

### A. CURRENT IMPLEMENTED STATE
- **Data Layer**: 6 Parquet tables containing 366,547 CVE records, EPSS probabilities, KEV status, CWE mappings, CPE mappings, and vendor statements.
- **Backend API**: FastAPI REST backend running on port `5002` (served publicly via Cloudflare Tunnel at `https://vuln-triage-api.seucra.tech`) with 15 active endpoints across Auth, Vulnerabilities, Predict, Prioritize, Explain, and Provenance.
- **Auth & RBAC**: SQLite user store (`data/auth_users.sqlite`), PBKDF2 hashing, HMAC-SHA256 JWT tokens, and 3 active roles (`analyst`, `researcher`, `admin`).
- **Machine Learning & Scoring**: EXP-A1 XGBoost CVSS Regressor, EXP-B2 XGBoost KEV Classifier, SHAP TreeExplainer attribution service, and dual-mode prioritization scoring engine.
- **Frontend SPA**: Vanilla JavaScript SPA hosted on GitHub Pages (`https://vuln-triage.seucra.tech`), featuring role-specific dashboards, responsive navigation, printable reports, and data export tools.
- **Automated Testing**: 39 / 39 passing Pytest tests across auth/RBAC, REST API, and ETL invariants.

### B. STALE / OUTDATED DOCUMENTATION
- References to port `8000` in early architecture docs (actual port is `5002`).
- References to `cache: 'pip'` in early GitHub Actions guides (removed in CI workflow).
- Theoretical references to Celery/Redis background task queues in early ideation notes (not required or used in current architecture).

### C. PLANNED BUT NOT IMPLEMENTED
- Automated daily/weekly live NVD API polling.
- Enterprise SSO / OAuth2 third-party identity providers.
- Automated ML model re-training CI workflows.

### D. UNCERTAIN / REQUIRES MANUAL VERIFICATION
- Long-term uptime of the host machine running the Uvicorn process and Cloudflare Tunnel daemon for `https://vuln-triage-api.seucra.tech`.
