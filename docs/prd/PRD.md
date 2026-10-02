# Product Requirements Document (PRD)
## Vulnerability Prioritization & Triage System (VTS)

**Project Category**: Academic Research Prototype & Public Demonstration Platform  
**Academic Setting**: B.Tech Computer Engineering Capstone / Web Design Lab (WDL)  
**Repository Identifier**: `seucra/vulnarability-prioritization-triage-system`  
**System Version**: `1.0.0` (FastAPI Backend, Vanilla ES Modules SPA, DuckDB Engine, SQLite RBAC)  
**Document Status**: Authoritative Product Requirements Specification  

---

## 1. Executive Summary & Vision

The **Vulnerability Prioritization & Triage System (VTS)** is an academic research platform and decision-support web application designed to evaluate and demonstrate risk-based vulnerability triage under realistic information availability constraints.

Modern cybersecurity operations are overwhelmed by vulnerability disclosure volume. The National Vulnerability Database (NVD) catalogs over 366,000 Common Vulnerabilities and Exposures (CVEs), yet empirical evidence confirms that fewer than 2% of disclosed flaws are ever exploited in the wild. Conventional triage relies heavily on Common Vulnerability Scoring System (CVSS) Base Scores, which measure intrinsic technical severity rather than dynamic operational risk. This misalignment causes severe alert fatigue and misallocates scarce remediation resources.

VTS provides an auditable, scientifically grounded solution:
1. **Disclosure-Time Severity Estimation (EXP-A1)**: Pre-scores CVSS v3.1 base scores at publication time using natural language text and weakness taxonomy, bridging the multi-week delay before official NVD scoring.
2. **Publication-Time Exploitation Forecasting (EXP-B2)**: Forecasts eventual CISA Known Exploited Vulnerabilities (KEV) inclusion under strict temporal boundaries without post-publication telemetry leakage.
3. **Multi-Criteria Contextual Prioritization (EXP-C1)**: Combines technical severity, threat likelihood, confirmed weaponization, and controlled asset criticality through a nonlinear interactive surface ($S_{\text{nonlinear}}$) that eliminates the rigid priority ceilings of linear additive models.
4. **Local Feature Attribution**: Employs tree-based Shapley Additive Explanations (SHAP) to provide transparent feature-level attributions for analyst inspection.
5. **Auditable Demonstration Interface**: Provides role-governed web workflows for Security Analysts, Academic Researchers, and Administrators.

---

## 2. Target Personas & Stakeholder Workflows

The system defines three core operational personas mapped to Role-Based Access Control (RBAC) tiers:

### 2.1 Persona 1: Security Triage Analyst (`analyst` role)
- **Role & Context**: Frontline SOC/Vulnerability Management engineer tasked with reviewing daily scan alerts and prioritizing patch deployment tickets under strict maintenance windows.
- **Pain Points**: Overwhelmed by thousands of "High" and "Critical" CVSS alerts; inability to distinguish theoretical severity from active weaponization; rigid corporate SLAs forcing remediation of harmless flaws.
- **System Workflows**:
  - Search and filter canonical CVE records across vendor, product, CWE, and CVSS facets.
  - Execute pre-scoring CVSS estimation and KEV threat prediction on newly disclosed zero-day advisories.
  - Utilize the **Batch Triage Queue (WDL-7)**: paste lists of up to 100 CVEs, configure asset criticality tiers, evaluate rank shifts between linear and nonlinear scoring, and export triage action plans to CSV or JSON.

### 2.2 Persona 2: Academic Researcher / Security Auditor (`researcher` role)
- **Role & Context**: Computer engineering researcher, university evaluator, or compliance auditor evaluating methodology, model performance, and data provenance.
- **Pain Points**: Lack of reproducibility in published vulnerability research; opaque black-box machine learning models; unverified claims of "work reduction" without supporting data.
- **System Workflows**:
  - Inspect the **Research Provenance Dashboard**: verify dataset freeze dates (`2026-07-26`), EPSS snapshot timestamps (`2026-07-16`), table record counts, and SHA-256 binary checksums.
  - Review exact Phase 3 model evaluation benchmarks (EXP-A1 MAE, EXP-B2 PR-AUC, EXP-B1 leakage inflation factor).
  - Inspect TreeExplainer SHAP attribution distributions to examine model behavior and verify causal disclaimer guards.

### 2.3 Persona 3: System Administrator (`admin` role)
- **Role & Context**: Lead security engineer maintaining system infrastructure, database integrity, and user credentials.
- **Pain Points**: Unauthorized access to internal triage policies; privilege escalation risks; user account management overhead.
- **System Workflows**:
  - Authenticate via PBKDF2-HMAC-SHA256 credentials to obtain administrative JWT tokens.
  - Access the privileged User Management directory (`GET /api/v1/auth/users`) to inspect, activate, or disable analyst/researcher accounts.
  - Verify backend health status and system telemetry via `/health`.

---

## 3. Scope Boundaries: In-Scope vs. Out-of-Scope

### 3.1 In-Scope Capabilities
- **Canonical Dataset Foundation**: Processing 366,547 unique CVEs, 430,273 CWE mappings, 3,133,450 CPE nodes, 348,900 EPSS scores, and 1,647 CISA KEV entries into normalized, immutable Snappy-compressed Parquet tables.
- **Machine Learning Inference**: Serving serialized XGBoost regression (`EXP-A1`) and classification (`EXP-B2`) models via native UBJSON deserialization in Python 3.14.
- **Strict Boundary Enforcement**: Server-side Pydantic schema validation intercepting and rejecting post-publication telemetry (EPSS, CVSS vectors) during publication-time inference with HTTP 422.
- **Dual-Mode Prioritization Math**: Closed-form computation of Mode 1 (Linear Equal Weights) and Mode 2 (Nonlinear Interactive Surface) across four asset criticality tiers ($0.25, 0.50, 0.75, 1.00$).
- **Local Interpretability**: Generating exact TreeExplainer SHAP attributions for model predictions.
- **Interactive Single Page Application (SPA)**: Pure vanilla JavaScript (ES modules) client without external framework dependencies.

### 3.2 Out-of-Scope Capabilities
- **Real-Time Continuous Feed Synchronization**: VTS operates on an audited, frozen research snapshot (July 2026). Automated background polling of live NVD 2.0 streaming feeds is deferred to future work.
- **Enterprise CMDB Integration**: Asset criticality is evaluated across controlled synthetic tiers rather than live enterprise Configuration Management Databases.
- **Offensive Exploitation & Weaponization**: The system is strictly defensive; it contains zero exploit code, payload generators, or automated attack simulation tools.
- **Production-Grade Enterprise Infrastructure**: The demonstration deployment runs on a single VPS host exposed via Cloudflare Tunnel; it lacks distributed Kubernetes orchestration, multi-region failover, or enterprise secret vaults (e.g., HashiCorp Vault).

---

## 4. Functional Requirements Specification (WDL-1 to WDL-7)

### WDL-1: Canonical Vulnerability Data Ingestion & Storage
- **FR-1.1**: The system shall ingest raw yearly JSON archives from NVD (2002–2026), CPE platform dictionaries, CISA KEV catalog CSVs, FIRST EPSS score CSVs, and vendor XML responses.
- **FR-1.2**: The ETL pipeline shall output six normalized, Snappy-compressed Parquet files under `data/processed/`.
- **FR-1.3**: Primary key uniqueness (`cve_id` for vulnerabilities, EPSS, and KEV) and foreign key referential integrity shall be strictly enforced and verified by automated tests.
- **FR-1.4**: Zero-copy SQL analytical queries over the Parquet datasets shall be executed via an embedded DuckDB engine.

### WDL-2: Interactive Vulnerability Explorer & Search
- **FR-2.1**: The system shall provide a paginated web interface supporting full-text keyword search across 366,547 vulnerability descriptions.
- **FR-2.2**: The interface shall support multi-parameter filtering: CVE ID substring, CWE identifier, CPE vendor, CPE product, publication year range, CVSS score range ($[0.0, 10.0]$), EPSS probability range ($[0.0, 1.0]$), and binary CISA KEV listing status.
- **FR-2.3**: Clicking any vulnerability record shall open a responsive slide-over detail drawer displaying joined CWE weakness taxonomy, affected CPE configurations, EPSS metadata, and authoritative CVSS vector strings.

### WDL-3: Pre-Scoring CVSS v3.1 Regression Service (EXP-A1)
- **FR-3.1**: The backend shall expose `POST /api/v1/predict/cvss` to estimate CVSS v3.1 Base Scores from natural language descriptions and weakness metadata.
- **FR-3.2**: The feature pipeline shall extract 500 sublinear TF-IDF unigram/bigram tokens, top-20 CWE one-hot indicators, and CPE platform counts.
- **FR-3.3**: The service shall achieve a benchmark Test MAE of $\le 0.9750$ CVSS points on prospective 2025–2026 test disclosures.
- **FR-3.4**: All prediction responses shall include an explicit academic disclaimer stating that estimates are non-authoritative heuristics that do not replace formal NVD analyst scoring.

### WDL-4: Publication-Time Threat Exploitation Prediction (EXP-B2)
- **FR-4.1**: The backend shall expose `POST /api/v1/predict/kev` to forecast the probability of future CISA KEV inclusion using disclosure-time metadata.
- **FR-4.2**: The service shall enforce a strict publication-time boundary: any request payload containing `epss`, `epss_score`, `epss_percentile`, `cvss_v31_base_score`, or `cvss_vector` shall be rejected with HTTP 422 Unprocessable Entity.
- **FR-4.3**: Predictions shall be categorized into qualitative threat tiers: `HIGH_RISK` ($\hat{p} \ge 0.537$), `ELEVATED_RISK` ($0.20 \le \hat{p} < 0.537$), and `LOW_RISK` ($\hat{p} < 0.20$).

### WDL-5: Dual-Mode Multi-Criteria Prioritization Engine (EXP-C1)
- **FR-5.1**: The backend shall expose `POST /api/v1/prioritize` to compute priority scores under Mode 1 (Linear Equal Weights) and Mode 2 (Nonlinear Interactive Surface).
- **FR-5.2**: Mode 1 shall implement:
  $$S_{\text{linear}} = 0.25 \cdot x_1 + 0.25 \cdot x_2 + 0.25 \cdot x_3 + 0.25 \cdot x_4$$
- **FR-5.3**: Mode 2 shall implement:
  $$S_{\text{nonlinear}} = x_4 \cdot \left[ 1 - \left(1 - x_1\right)^{1 + \alpha x_3} \cdot \left(1 - x_2\right)^{1 + \beta x_3} \right]$$
  with interaction parameters $\alpha = 1.0$ (KEV severity multiplier) and $\beta = 1.5$ (KEV threat multiplier).
- **FR-5.4**: The system shall support four asset criticality tiers: Tier 1 Low ($0.25$), Tier 2 Medium ($0.50$), Tier 3 High ($0.75$), and Tier 4 Critical Infrastructure ($1.00$).

### WDL-6: Explainability & Local Feature Attribution (SHAP)
- **FR-6.1**: The backend shall expose `POST /api/v1/explain/cvss` and `POST /api/v1/explain/kev` to generate exact TreeExplainer Shapley feature attributions.
- **FR-6.2**: The frontend shall render horizontal bar charts distinguishing positive attributions (increasing estimated risk) from negative attributions (decreasing estimated risk).
- **FR-6.3**: Every explanation output shall prominently display a causal disclaimer stating that feature attributions represent statistical predictive associations within tree ensembles and do not establish physical software exploit causality.

### WDL-7: Multi-CVE Batch Triage Queue Workflow
- **FR-7.1**: The backend shall expose `POST /api/v1/prioritize/batch` to process lists of up to 100 CVE IDs simultaneously.
- **FR-7.2**: The engine shall auto-populate CVSS, EPSS, and KEV metadata from DuckDB, apply analyst-specified asset tier overrides, compute Mode 1 and Mode 2 scores, and rank the triage queue deterministically.
- **FR-7.3**: The interface shall compute score shift metrics ($\Delta = S_{\text{nonlinear}} - S_{\text{linear}}$) and queue rank displacement.
- **FR-7.4**: Analysts shall be able to export the prioritized triage queue to standard CSV and JSON formats.

---

## 5. Non-Functional Requirements (NFRs)

| NFR Dimension | Requirement Statement | Verification Method |
|---|---|---|
| **Query Latency** | DuckDB SQL queries over 366,547 records shall complete with p95 latency $< 50\text{ ms}$ under local execution. | Automated benchmark in `tests/test_backend_api.py`. |
| **Inference Speed** | Single-vulnerability XGBoost inference and TF-IDF transformation shall execute in $< 20\text{ ms}$. | End-to-end timing in `scripts/professor_test_suite.py`. |
| **Test Coverage** | The repository shall maintain 100% pass rate across all unit, integration, and invariant test suites. | Pytest suite: 46/46 passed; Professor suite: 15/15 passed. |
| **Reproducibility** | Clean rebuilds of processed Parquet data from raw sources shall yield zero logical row differences. | Deterministic rebuild check in `scripts/compare_rebuilds.py`. |
| **Authentication** | Passwords shall be hashed using PBKDF2-HMAC-SHA256 with 600,000 iterations; JWT tokens shall use HS256 signatures with 24-hour expiration. | Cryptographic verification in `tests/test_auth_rbac.py`. |
| **Accessibility & UX** | Web interface colors shall meet WCAG AA contrast standards ($\ge 4.5:1$ ratio); layout shall be fully responsive across mobile, tablet, and 1440px desktop. | Design audit in `docs/design/DESIGN.md`. |

---

## 6. Acceptance Criteria

1. **Data Invariants**: All 15 invariant tests in `tests/test_etl_invariants.py` pass without warning or error.
2. **Model Accuracy Bounds**:
   - EXP-A1 XGBoost Test MAE $\le 0.980$ CVSS points.
   - EXP-B2 XGBoost Test PR-AUC $\ge 0.025$ with Precision@500 $\ge 6.0\%$.
   - EXP-B1 Leakage model confirms $\ge 10\times$ PR-AUC inflation over EXP-B2.
3. **Security Boundaries**: Unauthenticated access to `/api/v1/predict/*` and `/api/v1/prioritize` returns HTTP 401; non-admin access to `/api/v1/auth/users` returns HTTP 403; post-publication feature injection into `/api/v1/predict/kev` returns HTTP 422.
4. **Demonstration Integrity**: The full application daemon runs cleanly via `run.sh` and serves both REST API endpoints and static SPA views without runtime build steps.
