# System Architecture Specification
## Vulnerability Prioritization & Triage System (VTS)

**Document Classification**: Authoritative System Architecture & Deployment Specification  
**Repository Identifier**: `seucra/vulnarability-prioritization-triage-system`  
**System Version**: `1.0.0` (FastAPI, DuckDB Columnar Engine, SQLite RBAC, Vanilla ES Modules SPA)  
**Deployment Topology**: Hybrid Static Edge (GitHub Pages) + VPS Daemon (Cloudflare Tunnel)  

---

## 1. Architectural Overview & Mental Model

The Vulnerability Prioritization & Triage System (VTS) implements a decoupled, high-performance analytical architecture designed to serve machine learning inference, complex multi-attribute scoring, and analytical queries across **366,547 canonical CVE records** without the operational complexity or latency of traditional external relational database servers.

```text
┌────────────────────────────────────────────────────────────────────────┐
│                        CLIENT PRESENTATION LAYER                       │
│  Vanilla JavaScript (ES Modules) │ CSS Custom Tokens │ Responsive Grid │
│  ├── Navbar (Role-Aware Navigation & Authentication State)             │
│  ├── Vulnerability Explorer (Paginated DuckDB Scans, 366k CVEs)        │
│  ├── ML Prediction View (EXP-A1 Regressor & EXP-B2 Classifier)         │
│  ├── Prioritization View (Linear vs Nonlinear Dual-Mode Simulator)     │
│  ├── Batch Triage Queue View (WDL-7 Multi-CVE Workflow, CSV Export)    │
│  ├── Research Provenance View (Dataset Hashes & Benchmark Metrics)     │
│  ├── Slide-Over Detail Drawer (Deep Vulnerability Inspection)          │
│  └── Admin User Management View (Privileged User Provisioning)         │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │ HTTPS / REST / Bearer JWT
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         FASTAPI BACKEND LAYER                          │
│  Port 5002 │ Uvicorn Daemon │ Python 3.14 │ OpenAPI Documentation       │
│  ├── Middleware: CORS, Cache-Control (No-Cache), Exception Handlers    │
│  ├── Security & RBAC: PBKDF2-HMAC-SHA256, PyJWT HS256 Token Engine     │
│  ├── API v1 Router (/api/v1):                                          │
│  │   ├── /auth: Register, Login, Me, Users (Admin only)                │
│  │   ├── /vulnerabilities: List, Search, Detail, Summary Metrics       │
│  │   ├── /predict: /cvss (EXP-A1), /kev (EXP-B2, Boundary Guard)       │
│  │   ├── /prioritize: Single CVE & Batch Queue Prioritization          │
│  │   ├── /explain: /cvss, /kev (TreeExplainer SHAP Attributions)       │
│  │   └── /provenance: Freeze Manifests, Hashes, Experiment Metrics     │
│  └── Service Layer:                                                    │
│      ├── InferenceService (TF-IDF Vectorization, XGBoost Inferences)   │
│      ├── ScoringService (Deterministic Closed-Form Mode 1 & 2 Math)    │
│      ├── ExplanationService (SHAP TreeExplainer Cache & Attribution)   │
│      ├── VulnerabilityService (Parametric SQL Query Builder)           │
│      └── AuthService (SQLite User Store CRUD & Role Enforcement)       │
└───────────────────┬───────────────────────────────┬────────────────────┘
                    │                               │
                    ▼                               ▼
┌───────────────────────────────────────┐   ┌────────────────────────────┐
│      ANALYTICAL DATA ENGINE           │   │      AUTH & USER STORE     │
│  DuckDB Columnar Query Engine         │   │  SQLite (data/auth_users)  │
│  6 Snappy-Compressed Parquet Tables   │   │  Roles: Analyst,           │
│  366,547 Canonical CVE Records        │   │         Researcher, Admin  │
│  (Total Disk Size: 94.48 MB)          │   │  PBKDF2-HMAC-SHA256        │
└───────────────────────────────────────┘   └────────────────────────────┘
```

---

## 2. Analytical Data Layer: DuckDB & Apache Parquet

### 2.1 The Zero-Copy Columnar Engine
Traditional web applications utilize client-server database architectures (e.g., PostgreSQL, MySQL, MongoDB). In VTS, this pattern was rejected:
1. **Analytical Query Patterns**: Triage queries scan large subsets of the 366,547 CVEs across specific columns (e.g., CVSS score distribution, KEV boolean flag, vendor substring) rather than updating individual records.
2. **Immutability of Research Data**: The research dataset was frozen on `2026-07-26`. Storing it in an active relational database introduces the risk of accidental mutation.
3. **Performance**: In-process DuckDB queries execute zero-copy scans directly on Snappy-compressed Parquet files in `data/processed/`, utilizing vectorized SIMD instructions.
4. **Zero Overhead**: Zero database daemon configuration, zero network socket overhead, and instant portability across development, CI, and server deployment.

### 2.2 Parquet Dataset Inventory (`data/processed/`)

| Table Name | File Name | Canonical Record Count | Disk Size | Primary Entity / Join Key | Binary SHA-256 Checksum |
|---|---|---|---|---|---|
| **Vulnerabilities** | `vulnerabilities.parquet` | **366,547** | 53.44 MB | Canonical CVE Record (`cve_id`) | `bd54d9fce55fa97388102c1c0db7df05c6f02c5828f6f0dfcba19780dc0008ae` |
| **Weaknesses** | `cve_cwe.parquet` | **430,273** | 2.91 MB | CVE-to-CWE Mapping (`cve_id`, `cwe_id`) | `6e8700c6ab6fb2cbdaa608e7b63681eaa4977cf251a136805d81fe9dc8fc1d44` |
| **Platform Matches** | `cve_cpe.parquet` | **3,133,450** | 33.91 MB | Platform Configurations (`cve_id`, `cpe_uri`) | `8ae41b32fcedf3529c7ad644a2a8b395e306f73c7209cee13f34e54fea9da026` |
| **EPSS Snapshot** | `epss.parquet` | **348,900** | 3.87 MB | Daily EPSS Telemetry (`cve_id`) | `be976efc624c2fb25aaf55ccaf5ca7d420a28082ac328a3746bcb28aa422e7bc` |
| **CISA KEV** | `kev.parquet` | **1,647** | 0.24 MB | Confirmed Exploitation (`cve_id`) | `cddd4b66170c4ade28b4d25ec906efdb6fac96dfd703bccfd2925becabe8f99f` |
| **Vendor Statements**| `vendor_statements.parquet` | **1,486** | 0.11 MB | Vendor Responses (`cve_id`, `organization`) | `85daaa54175e8bfb4d257f28132a45754d1c52926413631276caa5786f345f52` |
| **Total** | — | **4,282,303** | **94.48 MB** | — | — |

---

## 3. Backend Service Architecture (FastAPI)

The backend (`backend/app/`) is organized into modular decoupled layers:

### 3.1 Service Layer Implementations
1. **`VulnerabilityService` (`vulnerability_service.py`)**:
   - Manages DuckDB connection pool.
   - Builds parameterized SQL queries filtering across 12 distinct criteria with SQL injection protection.
   - Executes deep relational joins combining CWE weakness descriptions and CPE platform trees on demand.
2. **`InferenceService` (`inference_service.py`)**:
   - Loads serialized XGBoost models (`model.xgb`) and TF-IDF vectorizers (`vectorizer.joblib`) into persistent memory upon server startup.
   - Executes sublinear TF-IDF transformation and tabular feature assembly.
   - Implements model execution with exception handling: raises `ModelNotLoadedException` (HTTP 503) if model binaries are missing.
3. **`ScoringService` (`scoring_service.py`)**:
   - Implements analytical closed-form equations for Mode 1 Linear and Mode 2 Nonlinear surfaces.
   - Manages batch queue scoring (up to 100 CVEs), auto-joining metadata from DuckDB and applying analyst overrides.
   - Computes rank displacement ($\Delta \text{Rank}$) and score shifts.
4. **`ExplanationService` (`explanation_service.py`)**:
   - Initializes `shap.TreeExplainer` on the XGBoost regressor and classifier boosters.
   - Computes local Shapley values $\phi_i$ in exact polynomial time.
   - Injects mandatory causal disclaimer notices into all explanation payloads.
5. **`AuthService` (`auth_service.py`)**:
   - Manages SQLite database transactions (`data/auth_users.sqlite`).
   - Implements PBKDF2 password verification and JWT issuance.

### 3.2 Temporal Boundary Guard
To enforce scientific validity, `backend/app/schemas/prediction.py` implements a Pydantic model validator on `KEVPredictionRequest`:
```python
@model_validator(mode="after")
def validate_publication_time_boundary(self):
    prohibited = [f for f in ["epss", "epss_score", "epss_percentile", 
                              "cvss_v31_base_score", "cvss_vector"] 
                  if getattr(self, f, None) is not None]
    if prohibited:
        raise ValueError(
            f"Strict Publication-Time Feature Boundary Violation! "
            f"The following post-publication fields are excluded from EXP-B2: {prohibited}."
        )
    return self
```
Attempted injection of future threat telemetry triggers an HTTP 422 Unprocessable Entity error, preventing accidental data leakage at the API perimeter.

---

## 4. Authentication & Role-Based Access Control (RBAC)

The security subsystem is implemented in `backend/app/core/security.py` and `backend/app/core/auth_db.py`:

### 4.1 Cryptographic Standards
- **Password Hashing**: PBKDF2-HMAC-SHA256 with **600,000 hash iterations** (meeting OWASP 2026 password storage standards). Salt is generated cryptographically using 16-byte random tokens (`secrets.token_hex(16)`).
- **Token Signing**: JSON Web Tokens (JWT) signed with the HMAC-SHA256 (`HS256`) algorithm using a server-side secret key. Token payload encodes `sub` (username), `role`, and `exp` (24-hour expiration).

### 4.2 Role Hierarchy & Endpoint Access Matrix

| REST Endpoint URL | HTTP Method | Public | Analyst Role | Researcher Role | Admin Role | Access Policy Rationale |
|---|---|---|---|---|---|---|
| `/health` | `GET` | ✅ | ✅ | ✅ | ✅ | Unauthenticated system liveness probe |
| `/api/v1/auth/register` | `POST` | ✅ | ✅ | ✅ | ✅ | Public self-service user registration |
| `/api/v1/auth/login` | `POST` | ✅ | ✅ | ✅ | ✅ | Public credential exchange for JWT |
| `/api/v1/auth/me` | `GET` | ❌ | ✅ | ✅ | ✅ | Profile and session verification |
| `/api/v1/auth/users` | `GET` | ❌ | ❌ (403) | ❌ (403) | ✅ (200) | Privileged directory (Least Privilege) |
| `/api/v1/vulnerabilities`| `GET` | ✅ | ✅ | ✅ | ✅ | Public vulnerability search |
| `/api/v1/vulnerabilities/{id}`| `GET`| ✅ | ✅ | ✅ | ✅ | Public vulnerability inspection |
| `/api/v1/predict/cvss` | `POST` | ❌ | ✅ | ✅ | ✅ | Authenticated inference service |
| `/api/v1/predict/kev` | `POST` | ❌ | ✅ | ✅ | ✅ | Authenticated inference service |
| `/api/v1/prioritize` | `POST` | ❌ | ✅ (200) | ❌ (403) | ✅ (200) | Operational triage role restricted |
| `/api/v1/prioritize/batch`| `POST` | ❌ | ✅ (200) | ❌ (403) | ✅ (200) | Operational triage role restricted |
| `/api/v1/explain/cvss` | `POST` | ❌ | ✅ | ✅ | ✅ | Authenticated interpretability |
| `/api/v1/explain/kev` | `POST` | ❌ | ✅ | ✅ | ✅ | Authenticated interpretability |
| `/api/v1/provenance` | `GET` | ✅ | ✅ | ✅ | ✅ | Public academic audit transparency |

---

## 5. Deployment Topology

VTS implements a hybrid deployment architecture balancing zero-maintenance static hosting with a secure, self-hosted analytical backend:

```text
       [End Users & Security Analysts]
                     │
       ┌─────────────┴─────────────┐
       ▼                           ▼
[GitHub Pages / Cloudflare]    [Cloudflare Edge Network]
  Static Frontend SPA Assets       (HTTPS Reverse Proxy)
  (HTML, CSS Tokens, JS ES6)               │
  https://seucra.github.io/                ▼ (Cloudflare Tunnel: cloudflared)
                               [Origin Server: VPS Linux]
                               ├── FastAPI Application (Port 5002)
                               ├── DuckDB Engine & Parquet Datasets
                               ├── Serialized XGBoost Binaries
                               └── SQLite RBAC User Database
```

### 5.1 Public Endpoints
- **Frontend SPA**: Hosted on GitHub Pages via automated workflow (`.github/workflows/deploy_frontend.yml`).
- **Backend API**: Hosted on a persistent Linux VPS instance running Uvicorn on internal port `5002`.
- **Cloudflare Tunnel**: `cloudflared` daemon proxies incoming traffic from `https://vuln-triage-api.seucra.tech` to `http://localhost:5002`, eliminating the need to expose open inbound firewall ports.

### 5.2 Graceful Fallback Modes
When the backend API is offline or unauthenticated:
- The frontend renders an informative status toast notifying the user.
- The **Provenance View** remains fully functional via embedded client metadata.
- Authentication modals guide the analyst to sign in or review pre-seeded credentials.

---

## 6. Automated Testing Architecture

The codebase is protected by a two-tier automated verification architecture:

### 6.1 Pytest Suite (`tests/` — 46 Tests)
Executed via `.venv/bin/python -m pytest tests/ -v`:
- `test_etl_invariants.py` (15 tests): Asserts primary key uniqueness, record cardinalities, foreign key integrity, score ranges, and rebuild reproducibility.
- `test_backend_api.py` (9 tests): Validates REST routes, query parameter handling, DuckDB responses, and HTTP 422 boundary guards.
- `test_auth_rbac.py` (15 tests): Verifies password hashing, token issuance, session context, and least-privilege role boundaries.
- `test_batch_triage.py` (7 tests): Validates multi-CVE parsing, analyst overrides, 100-item limits, deterministic sorting, and RBAC enforcement.

### 6.2 Professor Verification Suite (`scripts/professor_test_suite.py` — 15 Tests)
Executed via `PYTHONPATH=. .venv/bin/python scripts/professor_test_suite.py`:
- Performs live end-to-end integration testing across health, auth, database search, inference, mathematical exactness, SHAP outputs, and batch triage workflows.
- Verification status: **15/15 passed at 100%**.
