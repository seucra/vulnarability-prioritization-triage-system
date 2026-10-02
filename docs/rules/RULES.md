# Authoritative System Rules & Invariant Specifications

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Document Status**: Official System Rules (Single Source of Truth)  
**Classification**: Academic Research Prototype & Public Web Demonstration  

---

## 1. Cardinal Architectural Boundaries & Non-Claims

To ensure technical defensibility, external academic integrity, and strict clarity during evaluations, the following six boundaries are hard-coded rules:

1. **Academic Research Prototype Boundary**:  
   The Vulnerability Prioritization & Triage System (VTS) is an academic research prototype engineered for the Web Design Lab (WDL) curriculum at VIT Pune. It is **not** an enterprise production security operations center (SOC) solution or managed threat intelligence service.
2. **Fixed Benchmark Snapshot (No Real-Time EPSS Polling)**:  
   VTS utilizes fixed research-grade Parquet benchmark snapshots (`cve_features_engineered.parquet` containing 245,611 rows; EPSS date snapshot `2024-07-26`). It intentionally does **not** dynamically poll FIRST.org APIs or NIST live streams at inference time to guarantee deterministic reproducibility.
3. **Absence of Real Enterprise Telemetry**:  
   VTS does **not** consume live corporate network telemetry, active SIEM sensor logs, or CMDB endpoint streams. In place of live enterprise data, EXP-C1 employs controlled Monte Carlo simulations parameterized across 4 distinct asset criticality tiers ($x_4 \in \{0.25, 0.50, 0.75, 1.00\}$) across 2,000 synthetic enterprise assets.
4. **CVSS Ceiling Invariant**:  
   CVSS v3.1 base score represents intrinsic, context-free technical severity, **not** operational exploitation likelihood. CVSS base score alone serves as an upper bound on technical impact; it must never be conflated with dynamic threat or exploit probability.
5. **Deterministic Triage Formula Invariant**:  
   The composite triage risk score is computed strictly via the deterministic formula:
   $$\text{Score} = 0.35 \cdot x_1 + 0.30 \cdot x_2 + 0.20 \cdot x_3 + 0.15 \cdot x_4$$
   where:
   - $x_1$: Normalized CVSS base score ($\text{CVSS} / 10.0 \in [0.0, 1.0]$)
   - $x_2$: EPSS probability ($\in [0.0, 1.0]$)
   - $x_3$: Empirical or simulated CISA KEV exploitation flag ($\in \{0.0, 1.0\}$)
   - $x_4$: Asset criticality factor ($\in [0.0, 1.0]$)
   The weights sum strictly to 1.000 ($0.35 + 0.30 + 0.20 + 0.15 = 1.000$).
6. **No Phantom Feature Inventions**:  
   Feature sets are strictly defined. EXP-B1 uses 21 features (14 numerical/one-hot + 7 engineered interactions). EXP-B2 uses 20 features (dropping `epss_percentile` to test raw probability sensitivity). No undocumented, dynamic, or ungrounded external features may be introduced into the models.

---

## 2. The 15 System & ETL Invariants

All pipeline modifications, data migrations, and test runs must satisfy the 15 system invariants verified by [`tests/test_etl_invariants.py`](tests/test_etl_invariants.py) and [`tests/test_professor_verification.py`](tests/test_professor_verification.py):

| Invariant ID | Target Domain | Invariant Constraint Rule | Verification Assertion |
|---|---|---|---|
| **INV-01** | Raw Ingestion | Raw NVD cache count must equal 245,611 rows with exactly 44 raw schema columns. | `len(raw_df) == 245611`, `len(columns) == 44` |
| **INV-02** | Target Balance | In-KEV label count must exactly match 1,177 known exploited vulnerabilities across the raw corpus. | `cve_in_kev == True` count == 1,177 |
| **INV-03** | Temporal Order | All CVE-2024 records are strictly reserved for testing; no lookahead leakage to training set. | `train_df.cve_year < 2024`, `test_df.cve_year == 2024` |
| **INV-04** | Deduplication | Every CVE ID in `cve_features_engineered.parquet` is unique; zero duplicate records permitted. | `df['cve_id'].nunique() == len(df)` |
| **INV-05** | CVSS Normalization | $0.0 \le \text{cvss\_score} \le 10.0$ and $0.0 \le x_1 \le 1.0$ across all 245,611 records. | `min >= 0.0` and `max <= 10.0` |
| **INV-06** | EPSS Probability Bounds | $0.0 \le \text{epss\_score} \le 1.0$ across all records. | `min >= 0.0` and `max <= 10.0` |
| **INV-07** | Weight Sum | Risk scoring weights must sum to exactly $1.000$ ($\pm 10^{-6}$). | $0.35 + 0.30 + 0.20 + 0.15 = 1.000$ |
| **INV-08** | Score Clamping | Final composite triage score must be strictly bounded in $[0.0, 1.0]$ for any input combination. | `0.0 <= compute_score(...) <= 1.0` |
| **INV-09** | Priority Monotonicity | For identical CVSS, EPSS, and KEV, a higher asset criticality must strictly yield a higher or equal priority tier. | $\text{Tier}(x_4=1.0) \ge \text{Tier}(x_4=0.25)$ |
| **INV-10** | Deterministic Inference | Same input vector must yield the exact same score, percentiles, and SHAP values across repeated calls. | `run_inference(x) == run_inference(x)` |
| **INV-11** | Temporal Split Ratio | EXP-B1 temporal train/test split maintains 187,002 train rows (1999–2023) and 24,196 test rows (2024). | Train: 187,002; Test: 24,196 |
| **INV-12** | Model Calibration | Brier score of calibrated model must be $\le 0.010$ on the test set. | `brier_score_loss(y_test, y_prob) <= 0.010` |
| **INV-13** | Monotonic Calibration | Isotonic regression calibrator preserves rank monotonicity of raw XGBoost probability outputs. | Spearman $\rho(\hat{p}_{\text{raw}}, \hat{p}_{\text{cal}}) \ge 0.999$ |
| **INV-14** | Data Manifest Existence | `docs/research/DATA_MANIFEST.md` must exist and match serialized parquet record counts and SHA256 hashes. | File exists, schema validated |
| **INV-15** | Parquet Compression | All processed tabular datasets must use Apache Arrow Snappy-compressed Parquet format. | Snappy compression header verified |

---

## 3. Strict Research & Metric Citation Rules

To eliminate discrepancies between historical drafts and verified serialized artifacts:

### 3.1 Metric Precision & Method Specification
- **PR-AUC Calculation Method**:
  Always distinguish between `sklearn.metrics.average_precision_score` (AP) and Riemann trapezoidal rule `sklearn.metrics.auc(recall, precision)`.
  - EXP-B1 Test PR-AUC:
    - `average_precision_score`: **0.33153** (0.332)
    - Trapezoidal `auc(r, p)`: **0.33037** (0.330)
  - EXP-B2 Test PR-AUC:
    - `average_precision_score`: **0.02884** (0.029)
    - Trapezoidal `auc(r, p)`: **0.02722** (0.027)
- **Discredited 0.3845 Typo**:
  Never cite 0.3845 as the PR-AUC of EXP-B2. This was an ungrounded typo originating from an illustrative mock response in `docs/architecture/API.md:146` (`0.38451`). The verified serialized artifact value is **0.02884**.
- **EXP-C1 Simulation Invariance Rule**:
  Because asset criticality ($x_4$) was applied homogeneously to all CVEs in each simulation tier run, scalar addition/multiplication preserves exact ranking. Therefore, Spearman $\rho = 0.9962$ and Kendall $\tau = 0.9356$ are identical across all four tiers. Never claim tiers had diverging rank correlation without heterogeneous asset weighting.
- **EXP-C1 Parquet Loop Key Collision Rule**:
  In `scripts/experiments/run_exp_c1.py`, `tier_name.split()[0].lower()` caused `simulation_rankings.parquet` to overwrite each tier with key `'tier'`, persisting only Tier 4 values. Always acknowledge this known implementation boundary when auditing EXP-C1 raw parquet artifacts.

---

## 4. API & Validation Rules (Pydantic & FastAPI)

1. **Input Range Validation**:
   - `cvss_score`: Float bounded $[0.0, 10.0]$
   - `epss_score`: Float bounded $[0.0, 1.0]$
   - `cve_in_kev`: Boolean (`True`/`False`)
   - `asset_criticality`: Float bounded $[0.0, 1.0]$
2. **Payload Size Guardrails**:
   - Single triage: 1 record per request (`POST /api/v1/triage`)
   - Batch triage: Up to 1,000 records per request (`POST /api/v1/triage/batch`)
3. **HTTP Status Code Uniformity**:
   - `200 OK`: Successful computation/retrieval
   - `400 Bad Request`: Invalid request payload or parameter format
   - `401 Unauthorized`: Missing, expired, or invalid JWT bearer token
   - `403 Forbidden`: Authenticated user lacks role permissions (e.g. non-Admin accessing user management)
   - `404 Not Found`: Requested CVE ID or entity does not exist
   - `422 Unprocessable Entity`: Pydantic schema validation failure

---

## 5. Security & Authentication Rules

1. **Password Hashing**: PBKDF2 with SHA-256 (`hashlib.pbkdf2_hmac`), minimum 100,000 iterations, with unique 16-byte cryptographically random salt per user. Never store plaintext passwords.
2. **Session Token Expiry**: JWT access tokens are signed with HMAC-SHA256 (`HS256`) and have a maximum default validity period of 60 minutes (`ACCESS_TOKEN_EXPIRE_MINUTES = 60`).
3. **Role-Based Access Control (RBAC)**:
   - `Admin`: Full access (Read, Triage, Export, User Management)
   - `Analyst`: Full operational access (Read, Triage, Export, Batch Analysis)
   - `Auditor`: Read-only access (Read CVEs, View Metrics, Inspect Invariants)

---

## 6. Documentation & Repository Hygiene Standards

1. **Single Source of Truth Structure**:
   - `docs/prd/PRD.md`: All functional and non-functional requirements.
   - `docs/design/DESIGN.md`: All UI tokens, styling, layouts, and accessibility specs.
   - `docs/architecture/ARCHITECTURE.md`: All backend architectures, data models, network topologies.
   - `docs/memory/MEMORY.md`: Chronological history, technical decisions, and viva defense cheat sheet.
   - `docs/rules/RULES.md`: All invariants, non-claims, and metric citation standards.
   - `docs/research/`: Authoritative research experiment protocols, evidence audit, and manifests.
   - `docs/legacy/`: Archived snapshots and superseded drafts. Never cite files in `docs/legacy/` for current system state.
2. **Zero Modification to Tested Executables**:
   Under no circumstances during documentation refactoring should application code, model binaries, parquet datasets, or test cases be modified.
3. **Verification Before Push**:
   Run `pytest tests/` locally to ensure 100% test pass rate prior to pushing commits.
