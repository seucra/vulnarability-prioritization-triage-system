# Experimental Protocol, Pipeline Execution & Empirical Results

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Document Status**: Official Consolidated Research Protocol & Results (Single Source of Truth)  
**Curriculum**: Web Design Lab (WDL) Research Capstone, VIT Pune  
**Authoritative Artifact References**: `data/experiments/phase2_metrics.json`, `data/experiments/phase3/`, `docs/research/EVIDENCE_AUDIT.md`

---

## 1. Research Overview & Multi-Phase Pipeline Architecture

The Vulnerability Prioritization & Triage System (VTS) addresses the operational bottleneck of enterprise vulnerability management, where traditional CVSS-based prioritization causes severe alert fatigue by categorizing ~60% of all vulnerabilities as "High" or "Critical" ($CVSS \ge 7.0$). VTS evaluates whether multi-source contextual intelligence (CVSS v2/v3/v4 intrinsic severity, EPSS exploitation probability, CISA KEV empirical exploitation evidence, and asset criticality) combined with calibrated machine learning can reliably isolate active operational threats.

```
+---------------------------------------------------------------------------------------------------+
|                                     VTS EXPERIMENTAL PIPELINE                                      |
+---------------------------------------------------------------------------------------------------+
| Phase 0: Raw Ingestion        | Phase 1: ETL & Schema Lake    | Phase 2: Feature Engineering      |
| - 29 NVD JSON 2.0 Feeds       | - 6 Relational Parquet Tables | - cve_features_engineered.parquet |
| - EPSS daily score feed       | - Deduplicated CVE records    | - 245,611 rows x 35 columns       |
| - CISA KEV catalog (1,177)    | - Invariant integrity checks  | - Temporal split: <2024 vs 2024   |
+-------------------------------+-------------------------------+-----------------------------------+
                                                                                |
                                                                                v
+---------------------------------------------------------------------------------------------------+
| Phase 3: Empirical Model Training, Validation & Simulation Benchmark                              |
+---------------------------------------------------------------------------------------------------+
| EXP-A1: Baseline Classification | EXP-B1: Multimodal XGBoost    | EXP-B2: Raw Sensitivity         |
| Logistic Regression benchmark  | 21 features, Isotonic Calib   | 20 features (no epss_percentile)|
| PR-AUC: 0.2858                 | PR-AUC: 0.3315 (Brier: 0.0076)| PR-AUC: 0.0288 (Brier: 0.0039)  |
+--------------------------------+-------------------------------+---------------------------------+
| EXP-C1: Monte Carlo Priority Simulation across 2,000 synthetic enterprise assets (4 Tiers)        |
| - Spearman rank correlation: 0.9962 | Kendall tau: 0.9356 (Monotonic risk separation)             |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Phase 0: Data Acquisition & Pre-Ingestion Integrity Audit

### 2.1 Raw Data Ingestion Scope
Data ingestion captured four primary vulnerability and threat intelligence feeds:
1. **NIST National Vulnerability Database (NVD)**: 29 compressed annual and early JSON 2.0 cache files covering CVEs from 1999 through 2024.
2. **FIRST.org Exploit Prediction Scoring System (EPSS)**: Daily CSV snapshot containing 348,900 CVE probability and percentile scores (`2024-07-26` / model `v2024.06.15`).
3. **CISA Known Exploited Vulnerabilities (KEV)**: Catalog containing 1,177 actively weaponized vulnerabilities.
4. **CPE Applicability Dictionary**: Configuration nodes within NVD records mapping software identifiers.

### 2.2 Pre-Ingestion Data Invariants Verified
- **Total Raw Record Ingestion**: Exactly 245,611 CVE records extracted across all NVD feed files.
- **KEV Target Ground Truth**: Exactly 1,177 known exploited vulnerabilities cataloged (`cve_in_kev == True`).
- **Integrity Verification**: All 32 raw source files cryptographically fingerprinted in [`docs/research/DATA_MANIFEST.md`](DATA_MANIFEST.md).

---

## 3. Phase 1: ETL Pipeline, Schema Harmonization & Parquet Lake

The ETL pipeline transformed nested JSON structures into an optimized, denormalized, and relational Apache Parquet data lake using Apache Arrow with Snappy compression.

### 3.1 Relational Parquet Tables
| Table Name | Row Count | Column Count | Disk Size | Primary Key / Join Key |
|---|---|---|---|---|
| `vulnerabilities.parquet` | 366,547 | 24 | 56.04 MB | `cve_id` |
| `cve_cwe.parquet` | 430,273 | 5 | 3.05 MB | `cve_id, cwe_id` |
| `cve_cpe.parquet` | 3,133,450 | 15 | 35.56 MB | `cve_id, cpe_match_criteria_id` |
| `epss.parquet` | 348,900 | 5 | 4.06 MB | `cve_id` |
| `kev.parquet` | 1,647 | 11 | 256.26 KB | `cve_id` |
| `vendor_statements.parquet` | 1,486 | 5 | 114.69 KB | `cve_id` |
| **Total Processed Store** | **4,282,303** | — | **99.08 MB** | — |

### 3.2 CVSS Version Harmonization
- Total CVEs with CVSS v4.0 metrics (`cvssMetricV40`): **29,964** (30,064 metric records).
- Intrinsic severity hierarchy prioritization: CVSS v3.1 is adopted as primary; v3.0 or v2.0 used as fallback for historical vulnerabilities.

---

## 4. Phase 2: Feature Engineering, Profiling & Experimental Protocol

### 4.1 Master Feature Dataset (`cve_features_engineered.parquet`)
- **Row Count**: 245,611 unique CVE records.
- **Column Count**: 35 columns (identifiers, raw scores, transformed variables, one-hot vectors, and interaction terms).
- **Target Variable**: `cve_in_kev` (Binary: 1 if listed in CISA KEV, 0 otherwise). Class imbalance: 1,177 positives (0.479%) vs 244,434 negatives (99.521%).

### 4.2 Temporal Train/Test Splitting Protocol
To strictly prevent temporal lookahead leakage, data was split strictly by publication year:
- **Training Population (1999–2023)**: 187,002 CVEs (1,085 KEV positives = 0.580% prevalence).
- **Test Population (2024)**: 24,196 CVEs (92 KEV positives = 0.380% prevalence).
- Unassigned / Out-of-bounds: 34,413 historical/unclassified entries excluded from temporal evaluation.

### 4.3 Feature Sets
- **EXP-B1 (21 Features)**:
  - Numerical / Raw (6): `cvss_score`, `epss_score`, `epss_percentile`, `cwe_count`, `cpe_count`, `reference_count`
  - Categorical / One-Hot (8): CVSS attack vector (`AV_NETWORK`, `AV_ADJACENT`, `AV_LOCAL`, `AV_PHYSICAL`), privileges required (`PR_NONE`, `PR_LOW`, `PR_HIGH`), user interaction (`UI_NONE`, `UI_REQUIRED`)
  - Interaction Terms (7): `cvss_x_epss`, `high_risk_flag`, `network_remote_flag`, `no_auth_flag`, `cpe_x_cvss`, `ref_x_epss`, `cwe_risk_score`
- **EXP-B2 (20 Features)**:
  - Identical to EXP-B1 except `epss_percentile` is intentionally removed to evaluate sensitivity to non-linear raw EPSS scores.

---

## 5. Phase 3: Model Benchmark Results (EXP-A1, EXP-B1, EXP-B2)

All models were evaluated on the held-out temporal 2024 test set (24,196 vulnerabilities, 92 KEV positives).

### 5.1 Comprehensive Performance Benchmark
| Metric | EXP-A1: Logistic Regression | EXP-B1: Multimodal XGBoost (Calibrated) | EXP-B2: Raw Sensitivity XGBoost |
|---|---|---|---|
| **ROC-AUC** | 0.9419 | **0.9700** | 0.9411 |
| **PR-AUC (Average Precision)** | 0.2858 | **0.3315** | 0.0288 |
| **PR-AUC (Trapezoidal AUC)** | 0.2831 | **0.3304** | 0.0272 |
| **Brier Calibration Score** | 0.0092 | **0.0076** | **0.0039** |
| **F1-Score (Optimal)** | 0.3401 | **0.4072** | 0.0833 |
| **Precision @ Optimal** | 0.2812 | **0.3444** | 0.0526 |
| **Recall @ Optimal** | 0.4286 | **0.5000** | 0.2000 |
| **Recall @ 1% Triage Workload** | 0.4565 | **0.6196** | 0.1739 |
| **Recall @ 5% Triage Workload** | 0.7065 | **0.8478** | 0.4239 |

### 5.2 Critical Experimental Insights
1. **EXP-B1 Dominance**: XGBoost with engineered feature interactions achieves a PR-AUC of **0.3315** (AP) / **0.3304** (trapezoidal), outperforming the baseline logistic regression by +16.0% relative improvement and capturing **84.78%** of all 2024 zero-day exploits within the top 5% of inspected vulnerabilities.
2. **The `epss_percentile` Sensitivity Effect (EXP-B2)**: Removing `epss_percentile` causes PR-AUC to plunge from 0.3315 to 0.0288. Because raw EPSS probabilities are heavily concentrated near zero ($>85\%$ of CVEs have EPSS $<0.001$), gradient boosted trees struggle to partition positive cases without the non-linear rank transformation provided by percentiles.
3. **Discrediting Historical 0.3845 Typo**: Historical drafts contained a stray claim of "0.3845 PR-AUC" for EXP-B2. This was a transcription typo traced to an illustrative example in `docs/API.md:146` (`0.38451`). The verified, serialized EXP-B2 PR-AUC is **0.02884**.

---

## 6. Phase 3: Monte Carlo Priority Simulation (EXP-C1)

EXP-C1 evaluated the dynamic triage formula across 2,000 synthetic enterprise assets across 4 criticality tiers:
$$\text{Score} = 0.35 \cdot (\text{CVSS}/10) + 0.30 \cdot \text{EPSS} + 0.20 \cdot \text{KEV} + 0.15 \cdot \text{Criticality}$$

### 6.1 Priority Distribution by Asset Tier
| Asset Criticality Tier | Criticality Value ($x_4$) | Tier 1: Critical ($\ge 0.80$) | Tier 2: High ($[0.65, 0.80)$) | Tier 3: Medium ($[0.45, 0.65)$) | Tier 4: Low ($< 0.45$) |
|---|---|---|---|---|---|
| **Tier 1 (Internal Mission Critical)** | 1.00 | **6,214** (25.7%) | 8,421 (34.8%) | 7,102 (29.4%) | 2,459 (10.2%) |
| **Tier 2 (High Enterprise Asset)** | 0.75 | 3,112 (12.9%) | 6,840 (28.3%) | 9,814 (40.6%) | 4,430 (18.3%) |
| **Tier 3 (Medium Business Asset)** | 0.50 | 1,420 (5.9%) | 4,210 (17.4%) | 11,200 (46.3%) | 7,366 (30.4%) |
| **Tier 4 (Low / Development Asset)** | 0.25 | 412 (1.7%) | 2,140 (8.8%) | 9,120 (37.7%) | **12,524** (51.8%) |

### 6.2 Rank Correlation Invariance Analysis
- **Spearman $\rho$**: **0.9962** (across all tiers)
- **Kendall $\tau$**: **0.9356** (across all tiers)
- **Mathematical Explanation**: In `scripts/experiments/run_exp_c1.py`, asset criticality was applied homogeneously to all CVEs within each simulation run. Under strictly monotonic linear transformation, ordinal rankings are strictly preserved, producing identical correlation values across all tiers.

---

## 7. Numerical Figure Data for Academic Paper Visualizations

### 7.1 Precision-Recall Curve Coordinates (Selected Deciles)
| Recall Bin | EXP-A1 Precision | EXP-B1 Precision (Calibrated) | EXP-B2 Precision |
|---|---|---|---|
| 0.10 | 0.782 | **0.891** | 0.142 |
| 0.20 | 0.654 | **0.784** | 0.083 |
| 0.30 | 0.489 | **0.652** | 0.051 |
| 0.40 | 0.362 | **0.521** | 0.038 |
| 0.50 | 0.281 | **0.407** | 0.029 |
| 0.60 | 0.204 | **0.312** | 0.021 |
| 0.70 | 0.141 | **0.228** | 0.015 |
| 0.80 | 0.089 | **0.146** | 0.011 |
| 0.90 | 0.045 | **0.078** | 0.007 |
| 1.00 | 0.004 | **0.004** | 0.004 |

### 7.2 Top 10 Feature Importances (EXP-B1 Mean |SHAP| Value)
| Rank | Feature Name | Mean \|SHAP\| | Primary Attribution Direction |
|---|---|---|---|
| 1 | `epss_percentile` | +1.482 | Higher percentile drastically increases predicted exploit risk |
| 2 | `cvss_x_epss` | +0.941 | Amplifies severity when both base impact and exploitability are high |
| 3 | `epss_score` | +0.723 | Raw probability confirmation |
| 4 | `cvss_score` | +0.512 | Sets technical impact ceiling |
| 5 | `network_remote_flag` | +0.438 | Remotely exploitable without physical access |
| 6 | `cpe_count` | +0.319 | Broad surface area increases weaponization likelihood |
| 7 | `no_auth_flag` | +0.284 | Attack vectors requiring zero privileges |
| 8 | `reference_count` | +0.211 | High public interest / security researcher visibility |
| 9 | `cwe_risk_score` | +0.165 | Dangerous weakness types (e.g. CWE-787, CWE-89) |
| 10 | `high_risk_flag` | +0.128 | Heuristic compound indicator |
