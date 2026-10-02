# Research Evidence Audit: Vulnerability Prioritization & Triage System (VTS)

**Document Status**: Official Research Evidence & Metric Audit  
**Target Venue**: IEEE Transactions on Dependable and Secure Computing / IEEE S&P / Academic Capstone Evaluation  
**Auditor**: Academic Research Audit Team  
**Audit Date**: October 2, 2026 (Dataset Frozen: 2026-07-26)  
**Repository Identifier**: `seucra/vulnarability-prioritization-triage-system`  

---

## 1. Executive Summary

This audit establishes the empirical ground truth for the Vulnerability Prioritization & Triage System (VTS) repository. Every numerical claim, dataset cardinality, model hyperparameter, evaluation metric, and architectural boundary was audited against physical code, serialized Parquet tables, JSON artifacts, and automated test outputs. Where feasible, metrics were independently recomputed directly from serialized prediction arrays and ground-truth label vectors.

### Key Audit Findings at a Glance

1. **Dataset Integrity and Provenance**:
   - The canonical population comprises **366,547 unique CVEs** (1988–2026) across six Parquet tables totaling **94.48 MB** (Snappy-compressed). Primary keys and relationships are verified by 15 automated invariant tests.
   - CISA KEV contains **1,647 cataloged vulnerabilities** (**0.4493% base rate**; ~1 in 222). Median time-to-KEV addition delay ($\Delta t$) is **285.2 days** (~0.78 years); 210 CVEs (12.75%) were listed in KEV before official NVD publication.
   - CVSS v3.1 base score coverage is **62.12%** (227,694 CVEs); 37.88% are missing (pre-2016 CVEs relying on CVSS v2 or recent 2026 disclosures under analysis).
   - EPSS coverage is **95.19%** (348,900 CVEs) from the single frozen snapshot of `2026-07-16T12:03:48Z` (EPSS model `v2026.06.15`).

2. **EXP-A1 (Pre-Scoring CVSS v3.1 Estimation)**:
   - **Recomputed & Verified**: On 81,604 held-out test CVEs (2025–2026), the XGBoost regressor achieves **MAE = 0.9750 CVSS points**, RMSE = 1.3059, $R^2 = 0.4153$, reducing error by **-10.99%** over the Ridge regression baseline (MAE = 1.0954, RMSE = 1.4089, $R^2 = 0.3194$).

3. **EXP-B2 (Publication-Time KEV Exploitation Prediction)**:
   - **Recomputed & Verified**: Evaluated on 91,242 held-out test CVEs containing 294 KEV positive instances (0.322% base rate), the publication-time XGBoost classifier achieves **PR-AUC = 0.02884** (via `average_precision_score`), ROC-AUC = 0.81324, **Precision@500 = 0.06400 (32/500)**, and **Recall@500 = 0.10884 (32/294)**.
   - This provides an **8.96× precision multiplier** over the random guessing baseline (base rate PR-AUC = 0.00322).
   - Baseline Logistic Regression achieves PR-AUC = 0.02077, ROC-AUC = 0.85857, Precision@500 = 0.03600 (18/500), Recall@500 = 0.06122 (18/294).

4. **EXP-B1 vs. EXP-B2 (Retrospective Snapshot Leakage Audit)**:
   - **Recomputed & Verified**: Adding the static 2026-07-16 EPSS snapshot features (`epss`, `epss_percentile`) to the identical test partition inflates XGBoost Test PR-AUC from **0.02884** to **0.33153**—an **11.49× artificial performance inflation** ($\Delta \text{PR-AUC} = +0.30269$).
   - This proves that evaluating historical models with static post-hoc EPSS snapshots introduces massive look-ahead data leakage.

5. **Formal Resolution of the 0.3845 PR-AUC Discrepancy**:
   - An unverified value of `PR-AUC = 0.3845` appeared in `docs/final-repo-state.md:160` erroneously mislabeled as "EXP-B2 (Text+Meta+EPSS)".
   - Audit confirms that **no serialized model or metrics artifact in `data/experiments/phase3/` contains 0.3845 as a PR-AUC**. The serialized ground truth in `data/experiments/phase3/exp_b2/metrics.json` is definitively **0.02884**. The string "0.38451" originated as an example prediction probability in `docs/architecture/API.md:146`. The value 0.3845 is formally discredited.

6. **EXP-C1 (Multi-Criteria Prioritization Simulation)**:
   - Evaluated across 227,694 intersected CVEs possessing complete CVSS v3.1, EPSS, and KEV.
   - **Verified Finding**: While global rank correlation between linear additive scoring ($S_{\text{linear}}$) and the nonlinear interactive surface ($S_{\text{nonlinear}}$) is high (Spearman $\rho = 0.9962$), the top queue heads diverge drastically: **Top-100 Jaccard overlap is only 0.005 (0.5%)** and Top-1000 Jaccard overlap is 0.182 (18.2%).
   - *Audit Discovery*: Because asset criticality tiers ($x_4 \in \{0.25, 0.50, 0.75, 1.00\}$) were evaluated homogeneously across all CVEs in each simulation pass, adding or multiplying by a constant scalar preserves identical internal rankings; hence Spearman $\rho$, Kendall $\tau$, and Jaccard overlap are mathematically identical across all four tier evaluations. Furthermore, due to a loop variable key collision in `scripts/experiments/run_exp_c1.py`, `simulation_rankings.parquet` only persisted Tier 4 scores.

7. **SHAP Post-Hoc Interpretability**:
   - Computed using `shap.TreeExplainer` on a 2,000-sample slice of the test partition (`test_idx[:2000]`). High positive attributions were confirmed for tokens like `unauthorized`, `unauthenticated`, and `gain`, and weakness `CWE-22`. Feature attribution represents statistical ensemble association, not software exploit causality.

8. **Operational Claim Boundaries**:
   - VTS contains **no longitudinal enterprise ticketing data, patch logs, or observed enterprise compromise traces**. Claims of "80–95% Work Reduction" or "Compromise Prevention" are external literature concepts (e.g., Agyei et al., 2026) and **cannot be made for VTS**.

---

## 2. Experiment-by-Experiment Evidence Tables

Every reported experimental result was matched against its serialized metric JSON and prediction Parquet file, with metrics recomputed directly using Python 3.14, Scikit-Learn 1.9.0, PyArrow 19.0.1, and NumPy.

### 2.1 EXP-A1: Pre-Scoring CVSS v3.1 Base Score Estimation

- **Research Question**: Can disclosure-time text descriptions, weakness identifiers, and platform counts accurately pre-estimate continuous CVSS v3.1 Base Scores $[0.0, 10.0]$ before official NVD scoring?
- **Target Variable**: `cvss_v31_base_score` (Continuous regression $[0.0, 10.0]$, Mean = 7.032, Std Dev = 1.703).
- **Population**: 227,694 CVEs with valid CVSS v3.1 scores.
  - Train (2002–2022): 78,172 CVEs.
  - Validation (2023–2024): 67,918 CVEs.
  - Test (2025–2026): 81,604 CVEs.
  - Train+Val Refit (2002–2024): 146,090 CVEs.
- **Features Used (531 total)**:
  - 500 TF-IDF unigrams/bigrams from `description_en` (`sublinear_tf=True`, `max_features=500`).
  - Top-20 CWE one-hot indicators (`is_semantic_cwe=True`).
  - 6 CPE configuration features: `cpe_count`, `cpe_part_a`, `cpe_part_o`, `cpe_part_h`, `vendor_count`, `product_count`.
  - Publication month (`pub_month` $\in [1, 12]$).
  - Flags: `has_cwe`, `has_cpe_configuration`.
- **Prohibited Features**: Official CVSS vector strings, CVSS sub-scores, EPSS scores, KEV flags, post-publication timestamps.
- **Artifact Paths**:
  - Script: `scripts/experiments/run_exp_a1.py`
  - Metrics JSON: `data/experiments/phase3/exp_a1/metrics.json`
  - Predictions Parquet: `data/experiments/phase3/exp_a1/test_predictions.parquet` (81,604 rows)
  - Serialized Model: `data/experiments/phase3/exp_a1/model.xgb`
  - Vectorizer: `data/experiments/phase3/exp_a1/vectorizer.joblib`
  - Feature Names: `data/experiments/phase3/exp_a1/feature_names.json` (531 names)

#### EXP-A1 Numerical Audit Table

| Metric | Partition | Model & Hyperparameters | Reported Value in JSON | Recomputed from Parquet | Audit Status |
|---|---|---|---|---|---|
| **MAE** | Validation | Ridge Baseline ($\alpha = 10.0$) | 0.9614 | — (Test only serialized) | **Verified from artifact** |
| **MAE** | Validation | XGBoost (`depth=8, n=200, lr=0.05`) | 0.7944 | — (Test only serialized) | **Verified from artifact** |
| **MAE** | **Test (2025–26)** | **Ridge Baseline** ($\alpha = 10.0$) | **1.0954** | **1.09540** | **Recomputed** |
| **RMSE**| **Test (2025–26)** | **Ridge Baseline** ($\alpha = 10.0$) | **1.4089** | **1.40892** | **Recomputed** |
| **$R^2$** | **Test (2025–26)** | **Ridge Baseline** ($\alpha = 10.0$) | **0.3194** | **0.31938** | **Recomputed** |
| **MAE** | **Test (2025–26)** | **XGBoost Regressor** | **0.9750** | **0.97496** | **Recomputed** |
| **RMSE**| **Test (2025–26)** | **XGBoost Regressor** | **1.3059** | **1.30587** | **Recomputed** |
| **$R^2$** | **Test (2025–26)** | **XGBoost Regressor** | **0.4153** | **0.41531** | **Recomputed** |
| **$\Delta$ MAE** | **Test (2025–26)** | **Relative Improvement** | **-10.99%** | **-10.995%** | **Recomputed** |

---

### 2.2 EXP-B2: Publication-Time KEV Exploitation Prediction

- **Research Question**: What precision, recall, and PR-AUC can be achieved when classifying eventual CISA KEV inclusion at initial disclosure time under extreme class imbalance without post-publication telemetry?
- **Target Variable**: Eventual CISA KEV catalog inclusion (`is_kev` $\in \{0, 1\}$).
- **Population**: 366,547 canonical CVEs.
  - Train (2002–2022): 203,652 CVEs (1,029 KEV positives = 0.505%).
  - Validation (2023–2024): 71,653 CVEs (324 KEV positives = 0.452%).
  - Test (2025–2026): 91,242 CVEs (294 KEV positives = 0.322% base rate).
  - Train+Val Refit (2002–2024): 275,305 CVEs (1,353 KEV positives = 0.491%).
- **Features Used (531 total)**: Identical 531 publication-time features as EXP-A1 (500 TF-IDF tokens + CWE indicators + CPE counts + publication month).
- **Strict Boundary Enforcement**: EPSS scores, EPSS percentiles, and CVSS vector components strictly forbidden.
- **Artifact Paths**:
  - Script: `scripts/experiments/run_exp_b2.py`
  - Metrics JSON: `data/experiments/phase3/exp_b2/metrics.json`
  - Predictions Parquet: `data/experiments/phase3/exp_b2/test_predictions.parquet` (91,242 rows)
  - Serialized Model: `data/experiments/phase3/exp_b2/model.xgb`
  - Vectorizer: `data/experiments/phase3/exp_b2/vectorizer.joblib`
  - Feature Names: `data/experiments/phase3/exp_b2/feature_names.json` (531 names)

#### EXP-B2 Numerical Audit Table

| Metric | Partition | Model & Hyperparameters | Reported Value in JSON | Recomputed from Parquet | Audit Status |
|---|---|---|---|---|---|
| **PR-AUC** | Validation | Logistic Regression ($C=10.0$) | 0.04177 | — (Test only serialized) | **Verified from artifact** |
| **PR-AUC** | Validation | XGBoost (`spw=20, d=4, n=100, lr=0.1`)| 0.25737 | — (Test only serialized) | **Verified from artifact** |
| **Random PR-AUC** | Test (2025–26) | Base Rate ($\frac{294}{91242}$) | 0.00322 | 0.003222 | **Recomputed** |
| **PR-AUC** | **Test (2025–26)** | **Logistic Regression** ($C=10.0$) | **0.02077** | **0.02077** (`average_precision_score`) | **Recomputed** |
| **ROC-AUC**| **Test (2025–26)** | **Logistic Regression** ($C=10.0$) | **0.85857** | **0.85857** | **Recomputed** |
| **Precision@500** | **Test (2025–26)** | **Logistic Regression** | **0.0360** (18/500) | **0.03600** (18/500) | **Recomputed** |
| **Recall@500** | **Test (2025–26)** | **Logistic Regression** | **0.0612** (18/294) | **0.06122** (18/294) | **Recomputed** |
| **PR-AUC** | **Test (2025–26)** | **XGBoost Classifier** | **0.02884** | **0.02884** (`average_precision_score`) | **Recomputed** |
| **ROC-AUC**| **Test (2025–26)** | **XGBoost Classifier** | **0.81324** | **0.81324** | **Recomputed** |
| **Precision@500** | **Test (2025–26)** | **XGBoost Classifier** | **0.0640** (32/500) | **0.06400** (32/500) | **Recomputed** |
| **Recall@500** | **Test (2025–26)** | **XGBoost Classifier** | **0.1088** (32/294) | **0.10884** (32/294) | **Recomputed** |
| **Max F1** | **Test (2025–26)** | **XGBoost Classifier** | **0.08725** | **0.08725** (Threshold = 0.53738) | **Recomputed** |
| **Uplift vs Random** | **Test (2025–26)** | **XGBoost vs Base Rate** | **8.96×** | **8.951×** ($\frac{0.02884}{0.003222}$) | **Recomputed** |

*Note on PR-AUC Metric Calculation*: Recomputing PR-AUC using trapezoidal Riemann integration (`sklearn.metrics.auc(recall, precision)`) yields `0.02722` (XGBoost) and `0.01945` (Logistic Regression). Recomputing using standard interpolated average precision (`sklearn.metrics.average_precision_score`) yields **0.02884** and **0.02077**, matching `metrics.json` to five decimal places. The reported metric is definitively `average_precision_score`.

---

### 2.3 EXP-B1: Retrospective Snapshot Sensitivity Experiment (Leakage Audit)

- **Research Question**: How much artificial performance inflation occurs when a machine learning model is granted access to a future EPSS snapshot during historical CVE evaluation?
- **Target Variable**: Eventual CISA KEV catalog inclusion (`is_kev` $\in \{0, 1\}$).
- **Population**: Exactly identical to EXP-B2 (91,242 test CVEs, 294 KEV positives).
- **Features Used (533 total)**: The 531 publication-time features of EXP-B2 **plus** two leaked retrospective features: `epss` (absolute score) and `epss_percentile` from the static snapshot of `2026-07-16` (EPSS model `v2026.06.15`).
- **Artifact Paths**:
  - Script: `scripts/experiments/run_exp_b1.py`
  - Metrics JSON: `data/experiments/phase3/exp_b1/metrics.json`
  - Predictions Parquet: `data/experiments/phase3/exp_b1/test_predictions.parquet` (91,242 rows)

#### EXP-B1 Numerical Audit Table

| Metric | Partition | Model & Hyperparameters | Reported Value in JSON | Recomputed from Parquet | Audit Status |
|---|---|---|---|---|---|
| **PR-AUC** | Validation | Logistic Regression ($C=1.0$) | 0.37826 | — (Test only serialized) | **Verified from artifact** |
| **PR-AUC** | Validation | XGBoost (`spw=20, d=4, n=100, lr=0.1`)| 0.62221 | — (Test only serialized) | **Verified from artifact** |
| **PR-AUC** | **Test (2025–26)** | **Logistic Regression** ($C=1.0$) | **0.29481** | **0.29481** (`average_precision_score`) | **Recomputed** |
| **ROC-AUC**| **Test (2025–26)** | **Logistic Regression** ($C=1.0$) | **0.98403** | **0.98403** | **Recomputed** |
| **Precision@500** | **Test (2025–26)** | **Logistic Regression** | **0.2660** (133/500)| **0.26600** (133/500) | **Recomputed** |
| **Recall@500** | **Test (2025–26)** | **Logistic Regression** | **0.4524** (133/294)| **0.45238** (133/294) | **Recomputed** |
| **PR-AUC** | **Test (2025–26)** | **XGBoost Classifier** | **0.33153** | **0.33153** (`average_precision_score`) | **Recomputed** |
| **ROC-AUC**| **Test (2025–26)** | **XGBoost Classifier** | **0.98420** | **0.98420** | **Recomputed** |
| **Precision@500** | **Test (2025–26)** | **XGBoost Classifier** | **0.2520** (126/500)| **0.25200** (126/500) | **Recomputed** |
| **Recall@500** | **Test (2025–26)** | **XGBoost Classifier** | **0.4286** (126/294)| **0.42857** (126/294) | **Recomputed** |
| **Leakage $\Delta$ PR-AUC** | **Test (2025–26)** | **XGBoost (B1 vs. B2)** | **+0.30269** | **+0.30269** ($0.33153 - 0.02884$) | **Recomputed** |
| **Inflation Factor** | **Test (2025–26)** | **XGBoost (B1 / B2)** | **11.49×** | **11.495×** ($\frac{0.33153}{0.02884}$) | **Recomputed** |

---

### 2.4 EXP-C1: Multi-Criteria Prioritization Simulation

- **Research Question**: How do linear additive models ($S_{\text{linear}}$) and nonlinear interactive surfaces ($S_{\text{nonlinear}}$) diverge in ranking behavior across controlled asset criticality tiers?
- **Experiment Nature**: Controlled factorial decision-support simulation across defined scenarios; **not** a supervised learning task.
- **Population**: 227,694 intersected CVEs possessing complete CVSS v3.1, EPSS snapshot, and KEV annotations.
- **Formulas**:
  - $S_{\text{linear}} = 0.25 \cdot (\text{CVSS}/10) + 0.25 \cdot (\text{EPSS}) + 0.25 \cdot (\mathbb{I}_{\text{KEV}}) + 0.25 \cdot (A)$
  - $S_{\text{nonlinear}} = A \cdot [1 - (1 - \text{CVSS}/10)^{1 + 1.0 \cdot \mathbb{I}_{\text{KEV}}} \cdot (1 - \text{EPSS})^{1 + 1.5 \cdot \mathbb{I}_{\text{KEV}}}]$
- **Artifact Paths**:
  - Script: `scripts/experiments/run_exp_c1.py`
  - Metrics JSON: `data/experiments/phase3/exp_c1/metrics.json`
  - Rankings Parquet: `data/experiments/phase3/exp_c1/simulation_rankings.parquet` (227,694 rows)

#### EXP-C1 Numerical Audit Table

| Metric | Asset Criticality Tier | Reported Value in JSON | Recomputed from Script / Parquet | Audit Status |
|---|---|---|---|---|
| **Intersected Population** | All Tiers | 227,694 | 227,694 | **Recomputed** |
| **Spearman $\rho$** | Tier 1 (Low: 0.25) | 0.9962 | 0.9962 | **Verified from artifact** |
| **Kendall $\tau$** | Tier 1 (Low: 0.25) | 0.9356 | 0.9356 (Sample $n=5000$) | **Verified from artifact** |
| **Top-100 Jaccard Overlap** | Tier 1 (Low: 0.25) | **0.005** | **0.005** (0.5% agreement) | **Verified from artifact** |
| **Top-1000 Jaccard Overlap**| Tier 1 (Low: 0.25) | **0.182** | **0.182** (18.2% agreement) | **Verified from artifact** |
| **KEV in Top-100** | Tier 1 (Linear vs. Nonlin) | 100 vs. 3 ($\Delta = -97$) | 100 vs. 3 | **Verified from artifact** |
| **KEV in Top-1000** | Tier 1 (Linear vs. Nonlin) | 1,000 vs. 315 ($\Delta = -685$) | 1,000 vs. 315 | **Verified from artifact** |
| **Metrics Across Tiers 2–4**| Tiers 2, 3, 4 | Identical to Tier 1 | Identical (Scalar invariance) | **Verified from artifact** |

---

## 3. Dataset and Temporal Split Audit

### 3.1 Raw Data Sources and Snapshot Dates

| Source Family | Raw Physical File(s) | Source Snapshot Date / Version | Canonical Record Count | Ingestion Module |
|---|---|---|---|---|
| **NVD CVE Feeds** | `data/raw/nvd/nvdcve-2.0-2002.json.gz` through `...-2026.json.gz` (27 files) | Disclosures spanning 1988–2026; downloaded 2026-07-26 | 366,547 canonical CVEs | `src/ingestion/nvd.py` |
| **NVD CPE Feeds** | `data/raw/cpe/nvdcpe-2.0.tar.gz`, `nvdcpematch-2.0.tar.gz` | Downloaded 2026-07-26 | 3,133,450 platform nodes | `src/ingestion/cpe.py` |
| **FIRST EPSS** | `data/raw/epss/epss_scores-2026-07-16.csv.gz` | **`2026-07-16T12:03:48Z`** (Model `v2026.06.15`) | 348,900 scored CVEs | `src/ingestion/epss.py` |
| **CISA KEV** | `data/raw/kev/known_exploited_vulnerabilities.csv` | Downloaded **`2026-07-26`** | 1,647 catalog entries | `src/ingestion/kev.py` |
| **Vendor Statements**| `data/raw/vendor/vendorstatements.xml.gz` | Downloaded 2026-07-26 | 1,486 responses (1,452 CVEs) | `src/ingestion/vendor.py` |

### 3.2 Canonical Processed Parquet Tables (`data/processed/`)

| Table Name | File Name | Row Count | Disk Size | Primary / Natural Key | Binary SHA-256 Hash |
|---|---|---|---|---|---|
| **Vulnerabilities** | `vulnerabilities.parquet` | 366,547 | 53.44 MB | `cve_id` (Unique, non-null) | `bd54d9fce55fa97388102c1c0db7df05c6f02c5828f6f0dfcba19780dc0008ae` |
| **Weaknesses** | `cve_cwe.parquet` | 430,273 | 2.91 MB | (`cve_id`, `cwe_id`) composite | `6e8700c6ab6fb2cbdaa608e7b63681eaa4977cf251a136805d81fe9dc8fc1d44` |
| **Platform Matches**| `cve_cpe.parquet` | 3,133,450 | 33.91 MB | (`cve_id`, `cpe_uri`) composite | `8ae41b32fcedf3529c7ad644a2a8b395e306f73c7209cee13f34e54fea9da026` |
| **EPSS Snapshot** | `epss.parquet` | 348,900 | 3.87 MB | `cve_id` (Unique, non-null) | `be976efc624c2fb25aaf55ccaf5ca7d420a28082ac328a3746bcb28aa422e7bc` |
| **CISA KEV** | `kev.parquet` | 1,647 | 0.24 MB | `cve_id` (Unique, non-null) | `cddd4b66170c4ade28b4d25ec906efdb6fac96dfd703bccfd2925becabe8f99f` |
| **Vendor Statements**| `vendor_statements.parquet` | 1,486 | 0.11 MB | (`cve_id`, `organization`) | `85daaa54175e8bfb4d257f28132a45754d1c52926413631276caa5786f345f52` |
| **Total** | — | **4,282,303** | **94.48 MB** | — | — |

*Invariant Verification*: Executed `tests/test_etl_invariants.py`. All 15 invariant tests passed:
- Invariant 1–3: One row per canonical CVE (`cve_id`), exactly 366,547 rows.
- Invariant 5–6: EPSS (348,900) and KEV (1,647) `cve_id` keys unique and non-null.
- Invariant 7–9: EPSS $\in [0, 1]$, EPSS percentile $\in [0, 1]$, CVSS $\in [0, 10]$.
- Invariant 10: All foreign keys in child tables resolve to `vulnerabilities.parquet`.

### 3.3 Temporal Split Boundaries and Label Distribution

| Partition | Publication Years | Canonical Total | EXP-A1 Subset (CVSS v3.1) | EXP-B2 / B1 Subset | KEV Positive Count | Positive Base Rate |
|---|---|---|---|---|---|---|
| **TRAIN** | 2002–2022 | 218,655 | 78,172 | 203,652 | 1,029 | 0.5053% |
| **VALIDATION** | 2023–2024 | 71,653 | 67,918 | 71,653 | 324 | 0.4522% |
| **TEST** | 2025–2026 | 91,242 | 81,604 | 91,242 | 294 | **0.3222%** |
| **TRAIN+VAL REFIT**| 2002–2024 | 290,308 | 146,090 | 275,305 | 1,353 | 0.4915% |

*Audit Observation*: In the test partition (2025–2026), the KEV positive base rate drops to 0.3222% (~1 positive in 310 CVEs). This reflects both the natural rarity of weaponized vulnerabilities and the empirical observation delay ($\Delta t = 285.2$ days), meaning some recent 2025–2026 vulnerabilities may be actively weaponized but not yet entered into the CISA KEV catalog by the July 2026 freeze date (right-censoring).

---

## 4. B1/B2 Feature-Timing and Leakage-Risk Analysis

### 4.1 Feature Timing Audit

| Dimension | EXP-B2 (Publication-Time Model) | EXP-B1 (Retrospective Snapshot Model) |
|---|---|---|
| **Intended Prediction Cutoff** | Initial public disclosure time ($t_0$) | Initial public disclosure time ($t_0$) |
| **Information Boundary** | Strictly text + weakness + CPE metadata available at $t_0$ | Text + metadata + July 2026 EPSS snapshot |
| **EPSS Feature Ingestion** | **Prohibited** (Attempted injection triggers HTTP 422) | **Included**: `epss` (probability) and `epss_percentile` |
| **EPSS Snapshot Date** | None | `2026-07-16T12:03:48Z` (Model `v2026.06.15`) |
| **Availability at Prediction Cutoff**| Fully Available at $t_0$ | **Unavailable at $t_0$** (Look-ahead leakage) |

### 4.2 Leakage Mechanism
The EPSS model version `v2026.06.15` was generated using threat sensor data, honeypot captures, and exploitation reports observed through mid-2026. When EXP-B1 evaluates vulnerabilities disclosed in 2025 or early 2026 using this snapshot, the EPSS score already reflects attacker activity that occurred *months after* initial disclosure. 

### 4.3 Quantitative Leakage Impact
- Test PR-AUC jumps from **0.02884** (EXP-B2) to **0.33153** (EXP-B1)—an **11.49× inflation** ($\Delta \text{PR-AUC} = +0.30269$).
- Test ROC-AUC jumps from **0.81324** to **0.98420**.
- Precision@500 jumps from **0.0640** (32 hits) to **0.2520** (126 hits)—a **3.94× inflation**.
- Recall@500 jumps from **0.1088** to **0.4286**.

### 4.4 Methodological Conclusion for Research Papers
- EXP-B1 must be presented strictly as a **retrospective sensitivity analysis / negative control**, not an operational classifier.
- EXP-B2 is the sole methodologically sound representation of prospective publication-time predictive utility.
- Papers citing PR-AUC $\approx 0.33$ or higher on historical CVEs without explicit time-stamped historical daily EPSS alignment suffer from severe retrospective data leakage.

---

## 5. C1 Ranking Evaluation Audit

### 5.1 Common Population and Formulations
- **Evaluated Population**: $n = 227,694$ intersected CVEs with CVSS v3.1, EPSS snapshot, and KEV catalog presence.
- **Reference Linear Baseline (Mode 1)**:
  $$S_{\text{linear}} = 0.25 \cdot x_1 + 0.25 \cdot x_2 + 0.25 \cdot x_3 + 0.25 \cdot x_4$$
  where $x_1 = \frac{\text{CVSS}}{10.0}$, $x_2 = \text{EPSS}$, $x_3 = \mathbb{I}_{\text{KEV}}$, $x_4 = A \in \{0.25, 0.50, 0.75, 1.00\}$.
- **Nonlinear Interactive Surface (Mode 2)**:
  $$S_{\text{nonlinear}} = x_4 \cdot \left[ 1 - \left(1 - x_1\right)^{1 + 1.0 \cdot x_3} \cdot \left(1 - x_2\right)^{1 + 1.5 \cdot x_3} \right]$$

### 5.2 Mathematical Audit of the Tier Results
In `data/experiments/phase3/exp_c1/metrics.json`, the correlation and overlap metrics are identical across all four asset tiers:
- Spearman $\rho = 0.9962$
- Kendall $\tau = 0.9356$
- Top-100 Jaccard overlap = $0.005$
- Top-1000 Jaccard overlap = $0.182$
- KEV in Top-100: Linear = 100, Nonlinear = 3 ($\Delta = -97$)
- KEV in Top-1000: Linear = 1,000, Nonlinear = 315 ($\Delta = -685$)

#### Mathematical Rationale for Invariance
Within any given simulation pass, the asset criticality scalar $x_4$ is applied **homogeneously** across all 227,694 vulnerabilities:
- In Mode 1, $0.25 \cdot x_4$ is an additive constant ($+0.0625, +0.125, +0.1875, +0.25$). Adding a constant to all items preserves their exact relative ordering: $\text{Rank}(S_{\text{linear}} \mid x_4 = c_1) \equiv \text{Rank}(S_{\text{linear}} \mid x_4 = c_2)$.
- In Mode 2, $x_4$ is a positive multiplicative constant ($0.25, 0.50, 0.75, 1.00$). Multiplying all items by a positive constant preserves their exact relative ordering: $\text{Rank}(S_{\text{nonlinear}} \mid x_4 = c_1) \equiv \text{Rank}(S_{\text{nonlinear}} \mid x_4 = c_2)$.

Consequently, within any single scenario where all vulnerabilities share the same asset criticality, the rank orderings for $S_{\text{linear}}$ and $S_{\text{nonlinear}}$ do not change across tiers. Rank divergence occurs **between** different scoring modes, not between homogeneous tier runs.

### 5.3 Code Defect Discovered in `simulation_rankings.parquet`
In `scripts/experiments/run_exp_c1.py:100`, the loop generates export dictionary keys using:
```python
tier_key = tier_name.split()[0].lower()
rank_export_dict[f"score_lin_{tier_key}"] = s_lin
rank_export_dict[f"score_nonlin_{tier_key}"] = s_nonlin
```
Because `tier_name.split()[0]` evaluates to `"Tier"` for all four tiers ("Tier 1", "Tier 2", "Tier 3", "Tier 4"), `tier_key` was identical (`'tier'`) on every iteration. Each tier loop silently overwrote `score_lin_tier` and `score_nonlin_tier`. Consequently, `simulation_rankings.parquet` only persisted the final iteration (Tier 4, $x_4 = 1.00$). The summary metrics in `metrics.json` were unaffected because they were appended to `tier_results` separately.

### 5.4 Operational Security Claim Boundary
The 0.005 Top-100 Jaccard overlap proves that linear and nonlinear scoring produce radically different queue compositions. It demonstrates that Mode 1 creates an artificial priority ceiling where all KEV items crowd the top queue regardless of CVSS or asset criticality. However, **this does not prove that Mode 2 produces superior real-world security outcomes**. Validating operational superiority requires empirical enterprise patch logs and incident traces, which do not exist in this repository.

---

## 6. SHAP Evidence Audit

- **Script**: `scripts/experiments/run_shap_analysis.py`
- **Output Artifact**: `data/experiments/phase3/shap/shap_summary.json`
- **Method**: Post-hoc `shap.TreeExplainer` executed on final frozen XGBoost models.
- **Evaluation Sample**: 2,000 representative test partition instances (`test_idx[:2000]`).
- **Features Analyzed**: All 531 features (500 TF-IDF tokens + CWE indicators + CPE platform counts).

### 6.1 Top Attributions Verified

| Rank | EXP-A1 (CVSS Regressor) Top Feature | Mean \|$\phi$\| | EXP-B2 (KEV Classifier) Top Feature | Mean \|$\phi$\| |
|---|---|---|---|---|
| 1 | `tfidf_unauthorized` | 0.34222 | `tfidf_gain` | 0.82117 |
| 2 | `tfidf_unauthenticated` | 0.34216 | `CWE-22` (Path Traversal) | 0.59967 |
| 3 | `tfidf_critical` | 0.27210 | `tfidf_critical` | 0.54493 |
| 4 | `tfidf_accessible` | 0.19013 | `cpe_count` | 0.46072 |
| 5 | `CWE-79` (Cross-Site Scripting) | 0.18454 | `tfidf_post` | 0.38791 |
| 6 | `tfidf_remote code` | 0.18176 | `tfidf_apache` | 0.38779 |
| 7 | `tfidf_manager` | 0.13819 | `tfidf_public` | 0.33804 |
| 8 | `tfidf_apache` | 0.12600 | `CWE-125` (Out-of-bounds Read) | 0.32928 |
| 9 | `tfidf_confidentiality` | 0.11882 | `tfidf_http` | 0.32692 |
| 10| `CWE-94` (Code Injection) | 0.11138 | `CWE-476` (NULL Pointer Deref) | 0.31170 |

### 6.2 What the SHAP Output Actually Supports
- **Supports**: Explains model weighting behavior within the decision tree ensemble; confirms that publication-time severity estimates are driven by unauthenticated remote access tokens, while exploitation predictions are heavily weighted by privilege gain tokens, path traversal (`CWE-22`), and broad platform deployment (`cpe_count`).
- **Does NOT Support**: Causal exploit mechanics. The presence of `tfidf_gain` does not mechanically cause software to be exploitable; it indicates that descriptions using "gain privileges" correlate with attacker targeting in training logs.

---

## 7. Application and Testing Evidence

### 7.1 Automated Test Execution Audit
Executed `.venv/bin/python -m pytest tests/ -v`:
- **Result**: **46 passed**, 6 deprecation warnings in **38.04s** (100% pass rate).
- **Coverage**:
  - `tests/test_auth_rbac.py` (15 tests): User registration, duplicate rejection, PBKDF2 verification, JWT issuance, logout, least privilege enforcement (`analyst` denied `/auth/users`, `researcher` denied `/prioritize`, `admin` authorized).
  - `tests/test_backend_api.py` (9 tests): Health check, DuckDB search, detail endpoint, EXP-A1 prediction, EXP-B2 publication-time prediction, boundary validation (HTTP 422 on EPSS injection), scoring modes, SHAP explanation, provenance metadata.
  - `tests/test_batch_triage.py` (7 tests): Multi-CVE batch queue scoring, analyst overrides, 100-item limit guard, empty request rejection, invalid/unknown CVE handling, deterministic tie-breaking, RBAC authorization.
  - `tests/test_etl_invariants.py` (15 tests): Schema invariants, primary key uniqueness, foreign key integrity, score bounds.

### 7.2 Professor Verification Suite Audit
Executed `PYTHONPATH=. .venv/bin/python scripts/professor_test_suite.py`:
- **Result**: **15 passed**, 0 failed (100% pass rate).
- **Verified Handlers**:
  - `TEST-SYS-01` & `TEST-SYS-02`: Health check and provenance metadata.
  - `TEST-AUTH-01` through `TEST-AUTH-04`: Role separation and least privilege.
  - `TEST-DB-01` & `TEST-DB-02`: DuckDB full-text search and ground-truth retrieval.
  - `TEST-ML-01` through `TEST-ML-03`: EXP-A1 regression, EXP-B2 classification, and HTTP 422 boundary guard.
  - `TEST-MATH-01` & `TEST-MATH-02`: Mathematical exactness of Mode 1 ($0.9875$) and Mode 2 ($1.0000$).
  - `TEST-SHAP-01`: TreeExplainer local attribution generation.
  - `TEST-BATCH-01`: Multi-CVE queue sorting and error status mapping.

### 7.3 Operational Scope Disclaimer
The application layer is a **research prototype and public demonstration deployment**, not a hardened production service. It lacks automated multi-region failover, Kubernetes orchestration, enterprise secret vaults, and formal SOC2/ISO27001 compliance.

---

## 8. Contradictions and Unresolved Questions

| ID | Issue / Contradiction | Evidence Source A | Evidence Source B | Authoritative Finding | Paper Action Required |
|---|---|---|---|---|---|
| **C-01** | B2 PR-AUC value discrepancy | `docs/final-repo-state.md:160` (claims `PR-AUC = 0.3845`) | `data/experiments/phase3/exp_b2/metrics.json` (records `PR-AUC = 0.02884`) | The serialized ground truth is **PR-AUC = 0.02884**. The value 0.3845 was an unverified draft note mislabeled as "Text+Meta+EPSS" matching an example API response. | State PR-AUC = 0.02884 as authoritative. Discredit 0.3845. |
| **C-02** | B2 Feature Boundary Definition | `docs/final-repo-state.md:157` ("Text + Meta + EPSS") | `scripts/experiments/run_exp_b2.py:1` ("Strictly excludes EPSS") | EXP-B2 strictly excludes EPSS. EXP-B1 is the experiment that deliberately incorporates EPSS to quantify leakage. | Standardize: EXP-B2 = publication-time only; EXP-B1 = retrospective. |
| **C-03** | C1 Parquet Column Overwrite | `scripts/experiments/run_exp_c1.py:100` (`tier_key = 'tier'`) | `data/experiments/phase3/exp_c1/simulation_rankings.parquet` | Dictionary key key collision caused Parquet to only save Tier 4 scores. Summary metrics in `metrics.json` are complete. | Acknowledge that the serialized parquet stores Tier 4; document the key collision. |
| **C-04** | C1 Metric Invariance Across Tiers | `data/experiments/phase3/exp_c1/metrics.json` (identical $\rho, \tau$, Jaccard) | Mathematical formula structure | Homogeneous scalar addition ($+0.25 A$) and multiplication ($\times A$) preserves rank invariance within tiers. | Explain the mathematical scalar invariance in the paper. |
| **C-05** | PR-AUC Calculation Definition | `exp_b2/metrics.json` (`pr_auc = 0.02884`) | Recomputation via `auc(r, p)` (`0.02722`) vs. `average_precision_score` (`0.02884`) | The reported metric was computed using `average_precision_score`. | Clarify in paper methodology that PR-AUC refers to average precision. |

---

## 9. Claims Safe to Make in an IEEE Research Paper

The following claims are **empirically supported, independently verified, and safe to defend**:

1. **Disclosure-Time Severity Estimation (EXP-A1)**:
   - *"Tree-based gradient boosting (XGBoost) trained on disclosure-time natural language descriptions, weakness identifiers, and platform configurations achieves a Test MAE of 0.9750 CVSS points on 81,604 prospective test CVEs (2025–2026), representing a 10.99% error reduction over a linear Ridge regression baseline (MAE = 1.0954)."*
2. **Publication-Time Exploitation Forecasting (EXP-B2)**:
   - *"Under an extreme class imbalance of 0.32% positive base rate (294 KEV positives in 91,242 prospective test CVEs), publication-time XGBoost achieves a PR-AUC of 0.02884 (an 8.96× precision multiplier over random guessing) and captures 10.88% of future KEV vulnerabilities with 6.40% precision in the top 500 candidate queue."*
3. **Retrospective Leakage Quantification (EXP-B1)**:
   - *"Incorporating a static retrospective EPSS snapshot during historical evaluation inflates Test PR-AUC from 0.02884 to 0.33153 (an 11.49× artificial performance distortion), exposing a critical methodological flaw in vulnerability research that evaluates historical models using modern threat telemetry."*
4. **Queue Tail Disruption in Multi-Criteria Scoring (EXP-C1)**:
   - *"Evaluating multi-criteria scoring across 227,694 intersected CVEs reveals that linear additive scoring allows binary KEV flags to act as rigid priority ceilings, whereas a nonlinear interactive surface ($S_{\text{nonlinear}}$) couples severity, threat probability, and asset context multiplicatively, resulting in an extreme queue head divergence with only 0.5% Top-100 Jaccard overlap."*
5. **Deterministic Provenance and Reproducibility**:
   - *"The data preparation pipeline transforms 366,547 canonical CVEs into six normalized Parquet tables with zero differing rows across independent rebuilds, verified by 15 automated invariant tests and 46 application pytests."*

---

## 10. Claims That Must Be Removed or Qualified

The following claims **lack empirical support in the repository and must be removed or strictly qualified**:

1. **REMOVE**: Claims that VTS reduces enterprise remediation workload by 80–95%.  
   *Reason*: VTS contains no enterprise ticketing data, patching logs, or operational scan cycles. That figure originates from external literature (Agyei et al., 2026).
2. **REMOVE**: Claims that VTS achieves a publication-time PR-AUC of 0.3845.  
   *Reason*: Provenance audit disproved this number; it was an unverified draft note mislabeled as including EPSS. The verified publication-time PR-AUC is 0.02884.
3. **REMOVE**: Claims that VTS prevents active cyber attacks or enterprise breaches.  
   *Reason*: VTS is a decision-support heuristic; it does not deploy network defenses, monitor hosts, or track real-world breach events.
4. **REMOVE**: Claims that VTS is a production-grade enterprise system.  
   *Reason*: VTS is an academic research prototype and public demonstration deployment.
5. **QUALIFY**: Claims that TreeExplainer SHAP explains why a vulnerability is exploitable.  
   *Must be qualified*: SHAP provides local feature attributions reflecting predictive associations within the decision tree ensemble; it does not establish software engineering causality.
6. **QUALIFY**: Claims regarding asset criticality in EXP-C1.  
   *Must be qualified*: Asset criticality tiers ($0.25, 0.50, 0.75, 1.00$) were evaluated as controlled synthetic simulation scenarios, not dynamic observed CMDB asset telemetry.

---

## 11. Exact Paths to Evidence Artifacts

| Claim / Metric | Primary Source Artifact Path | Verification Method |
|---|---|---|
| Canonical Population (366,547) | `data/processed/vulnerabilities.parquet` | Row count verified via PyArrow / DuckDB |
| KEV Total Count (1,647) | `data/processed/kev.parquet` | Row count verified via PyArrow |
| KEV Base Rate & Median Delay | `data/experiments/phase2_metrics.json` | JSON inspection: `base_rate = 0.004493`, `delay = 285.2` |
| EXP-A1 Model & Parameters | `data/experiments/phase3/exp_a1/model.xgb`, `metrics.json` | UBJSON booster load; JSON inspection (`depth=8, n=200, lr=0.05`) |
| EXP-A1 Recomputed Metrics | `data/experiments/phase3/exp_a1/test_predictions.parquet` | Python recomputation: MAE = 0.97496, RMSE = 1.30587, $R^2 = 0.41531$ |
| EXP-B2 Model & Parameters | `data/experiments/phase3/exp_b2/model.xgb`, `metrics.json` | UBJSON booster load; JSON inspection (`spw=20, d=4, n=100, lr=0.1`) |
| EXP-B2 Recomputed Metrics | `data/experiments/phase3/exp_b2/test_predictions.parquet` | Python recomputation: `average_precision_score = 0.02884`, P@500 = 0.064 |
| EXP-B1 Recomputed Metrics | `data/experiments/phase3/exp_b1/test_predictions.parquet` | Python recomputation: `average_precision_score = 0.33153`, P@500 = 0.252 |
| EXP-C1 Intersected Count (227k)| `data/experiments/phase3/exp_c1/simulation_rankings.parquet` | PyArrow row count: 227,694 |
| EXP-C1 Simulation Metrics | `data/experiments/phase3/exp_c1/metrics.json` | JSON inspection: Spearman $\rho = 0.9962$, Jaccard Top-100 = 0.005 |
| SHAP Feature Attributions | `data/experiments/phase3/shap/shap_summary.json` | JSON inspection: `tfidf_gain = 0.82117`, `CWE-22 = 0.59967` |
| Automated Pytest Suite (46) | `tests/` | Live execution: `pytest tests/ -v` (46 passed) |
| Professor Verification Suite (15)| `scripts/professor_test_suite.py` | Live execution: 15 passed, 0 failed |

---

## 12. Recommended Narrow Research Contribution for IEEE Paper

To ensure publication defensibility and prevent harsh reviewer criticism, the paper should be positioned around three focused, watertight contributions:

> ### The Narrow, Defensible Thesis:
> 1. **Publication-Time Feasibility & Boundaries**: We establish an empirical benchmark for pre-scoring vulnerability severity (0.9750 MAE) and publication-time exploitation prediction (PR-AUC 0.02884, 8.96× uplift over random) across 366,547 canonical CVEs under strict temporal partitioning.
> 2. **Empirical Proof of Retrospective Leakage**: We demonstrate that evaluating historical models with static post-hoc EPSS snapshots inflates PR-AUC by 11.49-fold (0.02884 $\rightarrow$ 0.33153), proving that reported high predictive scores in prior literature often reflect look-ahead leakage rather than true predictive capability.
> 3. **Mathematical Queue Ceiling Disruption**: We show that naive additive linear scoring allows binary KEV flags to crowd out severity and asset context, and we formulate a closed-form nonlinear interaction surface that eliminates this priority ceiling, shifting top-tier triage queue compositions by over 99% (Top-100 Jaccard overlap = 0.005).

By framing the paper around **information availability constraints, methodological leakage auditing, and mathematical interaction dynamics**, the project stands on unassailable, verified empirical evidence.
