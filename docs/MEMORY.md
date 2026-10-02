# Project Memory & Institutional Knowledge Base
## Vulnerability Prioritization & Triage System (VTS)

**Document Classification**: Authoritative Project Chronology, Decision Rationale, and Ground-Truth Memory  
**Repository Identifier**: `seucra/vulnarability-prioritization-triage-system`  
**Dataset Freeze Date**: `2026-07-26` | **EPSS Snapshot Date**: `2026-07-16T12:03:48Z`  
**Current Baseline State**: Phase 4 Complete (Audited October 2026)  

---

## 1. Project Mental Model & Core Narrative

The Vulnerability Prioritization & Triage System (VTS) was conceived and developed as a **research-oriented system first and web application second**. 

The fundamental intellectual progression governing the project is:
```text
Research Question
       ↓
Methodological Boundary
       ↓
Information Availability Constraint
       ↓
Temporal Experiment Design
       ↓
Empirical Machine Learning Models
       ↓
Evaluation & Leakage Audit
       ↓
Multi-Criteria Prioritization Simulation
       ↓
Explainability & Provenance
       ↓
Application Layer Delivery
```

The web dashboard is the interactive delivery vehicle that allows evaluators and security analysts to inspect, query, and test the underlying scientific models. It is **not** merely a web design exercise.

---

## 2. Chronological Project History & Key Decisions

### 2.1 The Initial Prototype and Decision to Rebuild
The initial incarnation of the project featured a React/TypeScript frontend, a basic FastAPI backend, and pre-trained models. However, an internal methodological audit revealed critical scientific deficiencies:
1. **Flawed Explainability**: The early system used a heuristic Leave-One-Out unigram perturbation technique. This failed to account for unigram+bigram feature interactions, produced misleading phrase attributions, and was methodologically inferior to cooperative game-theoretic Shapley values.
2. **Data Leakage Risks**: Early training pipelines did not enforce strict disclosure-time feature boundaries, risking accidental inclusion of retrospective threat telemetry.
3. **Reproducibility Gaps**: Data transformations were not deterministically auditable.

**The Guiding Decision**: Preserve the overarching vision (multi-signal vulnerability prioritization), but **rebuild the entire underlying research, data engineering, and machine learning pipeline from scratch** to ensure that every numerical claim was mathematically defensible before an academic examination committee.

### 2.2 Phase 0: Raw Data Verification
Before writing ETL scripts or training algorithms, the project established a dedicated raw-data verification phase (`scripts/verify_raw_data.py`). The guiding principle was: *research results cannot be defended if the integrity of the underlying source files cannot first be proven*. Phase 0 verified file existence, checksums, and compression formats across NVD yearly archives (2002–2026), CPE tarballs, CISA KEV CSVs, and FIRST EPSS snapshots.

### 2.3 Phase 1: Deterministic ETL & The Canonicalization Discovery
Phase 1 established `scripts/build_processed_data.py`, transforming raw files into six normalized Parquet tables (`data/processed/`).
- **The Discovery**: Independent clean rebuilds initially produced differing SHA-256 binary file hashes despite containing logically identical records.
- **The Root Cause**: Child tables (such as `cve_cpe.parquet`, containing 3.1 million rows) contained duplicate partial keys (same `cve_id` and `cpe_uri`). Sorting solely by partial keys allowed identical rows to be serialized in non-deterministic row order.
- **The Resolution**: `scripts/fingerprint_processed_data.py` was enhanced to enforce an all-column canonicalization routine: sorting columns alphabetically, sorting all rows across every column, standardizing NULL values, formatting floats deterministically, and computing SHA-256 over raw canonical byte streams. Subsequent clean rebuilds verified **0 differing rows**, proving bit-for-bit pipeline reproducibility.

### 2.4 Dataset Freeze
On `2026-07-26`, the processed Parquet tables were formally declared an **immutable research artifact**. Application services and subsequent experiments were granted read-only access to prevent accidental data contamination.

### 2.5 Phase 2: Data Profiling & Characterization
Phase 2 evaluated population distributions across the 366,547 canonical CVEs:
- Established that CVSS v3.1 covers **62.12%** of CVEs (227,694 records), with a mean score of 7.032.
- Established that CISA KEV contains **1,647 cataloged vulnerabilities** (**0.4493% base rate**; ~1 in 222).
- Measured the median KEV addition delay at **285.2 days** (~0.78 years), proving that relying solely on KEV creates a 9-month vulnerability window.

### 2.6 Phase 3: Experimental Execution & The Leakage Audit
Phase 3 implemented and executed the four core empirical experiments:
- `EXP-A1`: Pre-scoring CVSS v3.1 estimation (XGBoost Test MAE = 0.9750 vs. Ridge 1.0954).
- `EXP-B2`: Publication-time KEV forecasting under strict temporal constraints (XGBoost Test PR-AUC = 0.02884, 8.96× uplift over random).
- `EXP-B1`: Retrospective sensitivity audit proving that access to a future EPSS snapshot inflates Test PR-AUC to 0.33153 (an **11.49× artificial performance inflation**).
- `EXP-C1`: Multi-criteria simulation proving that non-linear surfaces disrupt linear priority ceilings (Top-100 Jaccard overlap = 0.005).

### 2.7 Phase 4: Application Layer, RBAC, Testing & Demonstration
Phase 4 operationalized the research findings:
- Replaced the heavy React build with a lightweight, high-performance vanilla JavaScript Single Page Application.
- Implemented DuckDB for zero-copy analytical queries over Parquet.
- Built a secure SQLite user registry with PBKDF2-HMAC-SHA256 password hashing and JWT RBAC (`analyst`, `researcher`, `admin`).
- Developed the multi-CVE Batch Triage Queue workflow (WDL-7).
- Authored and verified 46 automated pytests and 15 professor verification tests passing at 100%.

---

## 3. Rationale for Major Architectural & Research Decisions

| Decision Area | Chosen Approach in VTS | Alternative Rejected | Documented Engineering Rationale |
|---|---|---|---|
| **Explainability Engine** | `shap.TreeExplainer` on XGBoost | Leave-One-Out unigram perturbation | Unigram perturbation ignored bigram feature interactions and lacked theoretical foundation. `TreeExplainer` computes exact polynomial-time Shapley values from cooperative game theory. |
| **Data Engine & Storage** | Apache Parquet + In-Process DuckDB | Client-Server RDBMS (PostgreSQL / MySQL) | Research data is frozen and read-only. DuckDB executes zero-copy analytical SQL scans directly over Parquet in $<50\text{ ms}$ with zero server daemon maintenance. |
| **Frontend Architecture** | Pure Vanilla JavaScript (ES Modules) | React / Vue / Angular with Webpack | Eliminates complex build pipelines, dependency rot, and compilation latency. Pure ES6 modules provide instantaneous hot-reloading, native browser execution, and high data density. |
| **Temporal Split Protocol** | Chronological Split (Train $\le$2022, Val 23–24, Test 25–26) | Random 80/20 Train/Test Split | In time-series security events, random splitting causes look-ahead leakage, predicting historical CVEs with future data. Strict chronological splitting mirrors real-world operational inference. |
| **Threat Prediction Target** | CISA KEV Catalog Listing | Exploit-DB or Metasploit modules | Exploit-DB contains unverified academic PoCs that are never weaponized. CISA KEV represents verified, authoritative ground truth of in-the-wild exploitation in production networks. |
| **Prioritization Formulation** | Nonlinear Interactive Surface ($S_{\text{nonlinear}}$) | Simple Weighted Linear Sum ($S_{\text{linear}}$) | Linear addition forces binary flags ($0.25 \cdot \mathbb{I}_{\text{KEV}}$) to act as rigid priority ceilings, crowding top queues. The multiplicative surface allows high-severity non-KEV flaws in critical assets to enter top queues. |

---

## 4. Authoritative Research Ground Truth Fact Sheet

### 4.1 Frozen Dataset Inventory (`data/processed/`)
- **Total Record Count**: `4,282,303` rows across 6 Parquet tables
- **Total Disk Size**: `94.48 MB` (Snappy-compressed)
- **Dataset Freeze Date**: `2026-07-26`
- **EPSS Snapshot Date**: `2026-07-16T12:03:48Z` (Model `v2026.06.15`)

| Table Name | File Name | Record Count | Disk Size | Canonical Primary Entity | Binary SHA-256 Checksum |
|---|---|---|---|---|---|
| **Vulnerabilities** | `vulnerabilities.parquet` | **366,547** | 53.44 MB | Canonical CVE Record (`cve_id`) | `bd54d9fce55fa97388102c1c0db7df05c6f02c5828f6f0dfcba19780dc0008ae` |
| **Weaknesses** | `cve_cwe.parquet` | **430,273** | 2.91 MB | CVE-to-CWE Mapping (`cve_id`, `cwe_id`) | `6e8700c6ab6fb2cbdaa608e7b63681eaa4977cf251a136805d81fe9dc8fc1d44` |
| **Platform Matches** | `cve_cpe.parquet` | **3,133,450** | 33.91 MB | Platform Configurations (`cve_id`, `cpe_uri`) | `8ae41b32fcedf3529c7ad644a2a8b395e306f73c7209cee13f34e54fea9da026` |
| **EPSS Snapshot** | `epss.parquet` | **348,900** | 3.87 MB | Daily EPSS Telemetry (`cve_id`) | `be976efc624c2fb25aaf55ccaf5ca7d420a28082ac328a3746bcb28aa422e7bc` |
| **CISA KEV** | `kev.parquet` | **1,647** | 0.24 MB | Confirmed Exploitation (`cve_id`) | `cddd4b66170c4ade28b4d25ec906efdb6fac96dfd703bccfd2925becabe8f99f` |
| **Vendor Statements**| `vendor_statements.parquet` | **1,486** | 0.11 MB | Vendor Responses (`cve_id`, `organization`) | `85daaa54175e8bfb4d257f28132a45754d1c52926413631276caa5786f345f52` |

### 4.2 Exact Experimental Results Summary

| Experiment ID | Task Description | Features Available | Primary Metric | Baseline Performance | XGBoost Model Performance | Confirmed Relative Uplift |
|---|---|---|---|---|---|---|
| **EXP-A1** | Disclosure-Time CVSS v3.1 Estimation | Text (500 TF-IDF) + CWE + CPE (531 total) | **MAE** (Lower is better) | 1.0954 CVSS points (Ridge Baseline) | **0.9750 CVSS points** (XGBoost Regressor) | **-10.99% Error Reduction** ($\Delta = -0.1204$) |
| **EXP-B2** | Publication-Time KEV Exploitation Prediction | Publication-time text + metadata (No EPSS) | **PR-AUC** (Higher is better) | 0.02077 (Logistic Reg Baseline) | **0.02884** (XGBoost Classifier) | **+38.85% Uplift** (**8.96× vs. Random 0.00322**) |
| **EXP-B1** | Retrospective Snapshot Leakage Audit | Pub-time features + July 2026 EPSS snapshot | **PR-AUC** (Retrospective) | 0.29481 (Logistic Regression) | **0.33153** (XGBoost Classifier) | **11.49× Artificial Leakage Inflation** |
| **EXP-C1** | Multi-Criteria Prioritization Simulation | CVSS v3.1 + EPSS + KEV + Asset Criticality | **Top-100 Jaccard Overlap** | Linear Additive Baseline ($S_{\text{linear}}$) | Nonlinear Surface ($S_{\text{nonlinear}}$) | **0.005 Overlap (0.5% agreement)** (Disrupts ceiling) |

### 4.3 Provenance Resolution of the 0.3845 PR-AUC Citation
- **Audit Fact**: In `docs/final-repo-state.md:160`, an entry stated: `EXP-B2 Metrics: Test ROC-AUC = 0.9412, PR-AUC = 0.3845, F1 = 0.4120`.
- **Authoritative Resolution**: This note mislabeled the model as "Text + Meta + EPSS" and matched an example prediction probability in `docs/API.md:146` (`"predicted_kev_probability": 0.38451`). The physical serialized model artifact in `data/experiments/phase3/exp_b2/metrics.json` definitively records Test PR-AUC = **0.02884**. The value 0.3845 is formally discredited.

---

## 5. Automated Verification & Quality Assurance Record

The repository’s operational health is continuously verified by two test suites:

1. **Automated Pytest Suite (`tests/` — 46 Tests, 100% Passing)**:
   - `test_etl_invariants.py`: 15 tests verifying Parquet schema, uniqueness, foreign keys, and bit-for-bit rebuild reproducibility.
   - `test_backend_api.py`: 9 tests verifying REST routes, DuckDB queries, and HTTP 422 boundary guards.
   - `test_auth_rbac.py`: 15 tests verifying PBKDF2 hashing, JWT signing, session contexts, and least-privilege role boundaries.
   - `test_batch_triage.py`: 7 tests verifying multi-CVE batch queue parsing, analyst overrides, 100-item limit guards, deterministic sorting, and RBAC authorization.
2. **Professor Verification Suite (`scripts/professor_test_suite.py` — 15 Tests, 100% Passing)**:
   - Live end-to-end integration tests validating health checks, provenance metadata, analyst authentication, least-privilege enforcement, DuckDB Log4j search, CVSS regression, KEV prediction, boundary violation interception, Mode 1 and Mode 2 mathematical exactness ($0.9875$ and $1.0000$), TreeExplainer SHAP attributions, and batch triage error handling.

---

## 6. Viva Defense Quick-Reference Model

When questioned by examiners during a defense, ground all answers in the following mental anchors:

- **Anchor 1 (The Core Problem)**: Triage is not vulnerability scanning. Scanners find thousands of flaws; triage decides which flaws to patch under limited capacity.
- **Anchor 2 (Severity $\neq$ Risk)**: CVSS measures hypothetical worst-case technical impact under ideal conditions. It is not risk. Prioritizing solely on CVSS $\ge 7.0$ wastes 80–90% of effort on unexploited vulnerabilities.
- **Anchor 3 (Strict Temporal Boundary)**: In temporal systems, random cross-validation is scientific malpractice. We evaluate strictly on prospective 2025–2026 CVEs without future telemetry.
- **Anchor 4 (The Leakage Finding)**: Using a modern EPSS snapshot on historical data inflates PR-AUC by 11.49-fold (0.02884 $\rightarrow$ 0.33153). This explains why published academic papers often report unrealistically high scores.
- **Anchor 5 (The Prioritization Surface)**: Linear additive models create rigid priority ceilings where binary KEV flags crowd top queues. Mode 2 couples severity and threat multiplicatively, allowing critical infrastructure with severe uncataloged flaws to receive immediate priority.
