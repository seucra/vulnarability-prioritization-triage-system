# FINAL RESEARCH FACT SHEET

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Document Status**: Official Research Ground Truth  
**Created Date**: August 23, 2026  
**Environment**: Python 3.14.6, PyArrow 19.0.1, Scikit-Learn 1.9.0, XGBoost 3.4.0, SHAP 0.52.0, DuckDB 1.2.1  

---

## 1. Frozen Datasets & Provenance

### 1.1 Key Freeze Dates
- **Dataset Freeze Date**: `2026-07-26`
- **EPSS Score Snapshot Date**: `2026-07-16T12:03:48Z` (EPSS Model `v2026.06.15`)
- **NVD Feed Range**: `2002` through `2026` yearly feeds (spanning publication years 1988–2026)

### 1.2 Processed Parquet Data Inventory (`data/processed/`)
- **Total Record Count**: `4,282,303` records across 6 Parquet tables
- **Total Disk Size**: `94.48 MB` (Snappy compressed)

| Table | File | Record Count | Disk Size | Canonical Entity | Unique CVEs | Binary SHA-256 Hash |
|---|---|---|---|---|---|---|
| Vulnerabilities | `vulnerabilities.parquet` | **366,547** | 53.44 MB | NVD CVE Records | 366,547 | `bd54d9fce55fa97388102c1c0db7df05c6f02c5828f6f0dfcba19780dc0008ae` |
| Weaknesses | `cve_cwe.parquet` | **430,273** | 2.91 MB | CWE Mappings | 345,926 | `6e8700c6ab6fb2cbdaa608e7b63681eaa4977cf251a136805d81fe9dc8fc1d44` |
| CPE Applicability | `cve_cpe.parquet` | **3,133,450** | 33.91 MB | Platform Match Nodes | 306,176 | `8ae41b32fcedf3529c7ad644a2a8b395e306f73c7209cee13f34e54fea9da026` |
| EPSS Snapshot | `epss.parquet` | **348,900** | 3.87 MB | Daily EPSS Scores | 348,900 | `be976efc624c2fb25aaf55ccaf5ca7d420a28082ac328a3746bcb28aa422e7bc` |
| CISA KEV Catalog | `kev.parquet` | **1,647** | 0.24 MB | Known Exploited Catalog | 1,647 | `cddd4b66170c4ade28b4d25ec906efdb6fac96dfd703bccfd2925becabe8f99f` |
| Vendor Statements | `vendor_statements.parquet` | **1,486** | 0.11 MB | NVD Vendor Responses | 1,452 | `85daaa54175e8bfb4d257f28132a45754d1c52926413631276caa5786f345f52` |

---

## 2. Dataset Profile & Statistical Characteristics

### 2.1 CVSS Coverage Across Versions (n = 366,547 total CVEs)
- **CVSS v2**: 194,548 records (53.08%), Mean = 5.909, Median = 5.5
- **CVSS v3.0**: 54,540 records (14.88%), Mean = 7.192, Median = 7.5
- **CVSS v3.1**: **227,694 records** (**62.12%**), Mean = **7.032**, Median = **7.2**, Std = 1.703
- **CVSS v4.0**: 29,964 records (8.17%), Mean = 6.145, Median = 6.6

### 2.2 EPSS Characteristics (n = 348,900)
- **Median EPSS**: `0.00727` (0.73%)
- **Mean EPSS**: `0.02888` (2.89%)
- **90th Percentile**: `0.04282`
- **99th Percentile**: `0.58648`
- **Correlation with Percentile**: Pearson $r = 0.4125$

### 2.3 CISA KEV Characteristics (n = 1,647)
- **Overall Class Imbalance**: 1,647 / 366,547 = **0.4493%** positive rate (~1 in 222 CVEs)
- **Median Addition Delay ($\Delta t$)**: **285.2 days** (0.78 years)
- **Negative Delay Count**: **210 CVEs** (12.75%) were added to KEV *before* official NVD publication

---

## 3. Strict Temporal Partitions

| Partition | Publication Years | Total Canonical CVEs | EXP-A1 Population (CVSS v3.1) | EXP-B2 / B1 Population | KEV Positives (%) | Role |
|---|---|---|---|---|---|---|
| **TRAIN** | 2002–2022 | 218,655 | 78,172 | 203,652 | 1,029 (0.51%) | Model fitting & tuning |
| **VALIDATION** | 2023–2024 | 71,653 | 67,918 | 71,653 | 324 (0.45%) | Hyperparameter selection |
| **TEST** | 2025–2026 | 91,242 | 81,604 | 91,242 | 294 (0.32%) | **100% Untouched Evaluation** |
| **TRAIN + VAL** | 2002–2024 | 290,308 | 146,090 | 275,305 | 1,353 (0.49%) | Final refit before test |

---

## 4. Exact Experimental Results

### 4.1 EXP-A1: Pre-Scoring CVSS v3.1 Base Score Estimation
- **Task**: Regression $[0.0, 10.0]$
- **Features (531 total)**: 500 TF-IDF tokens from `description_en` + CWE indicators + CPE counts + publication month
- **Random Seed**: `42`
- **Models**:
  - `Baseline`: Ridge Regression ($\alpha = 10.0$)
  - `Nonlinear`: XGBoost Regressor (`max_depth=8, n_estimators=200, learning_rate=0.05`, `tree_method='hist'`)
- **Test Set Results (2025–2026, n = 81,604)**:
  - Ridge Baseline: **MAE = 1.0954**, RMSE = 1.4089, $R^2 = 0.3194$
  - XGBoost: **MAE = 0.9750**, RMSE = 1.3059, $R^2 = 0.4153$
  - **Improvement**: **-10.99% Error Reduction** ($\Delta \text{MAE} = -0.1204$)

### 4.2 EXP-B2: Publication-Time KEV Prediction (Primary Model - No EPSS)
- **Task**: Imbalanced Binary Classification $\{0, 1\}$
- **Prediction Point**: Initial CVE Publication / Triage Time
- **Features (531 total)**: 500 TF-IDF tokens + CWE + CPE + publication month (Strictly excludes EPSS, CVSS components, post-publication timestamps)
- **Models**:
  - `Baseline`: Logistic Regression (`class_weight='balanced'`, $C = 10.0$)
  - `Nonlinear`: XGBoost Classifier (`scale_pos_weight=20, max_depth=4, n_estimators=100, learning_rate=0.1`)
- **Test Set Results (2025–2026, n = 91,242, 294 KEV positives = 0.32% base rate)**:
  - Random Guessing PR-AUC: `0.00322`
  - Logistic Regression: **PR-AUC = 0.02077**, ROC-AUC = 0.85857, Precision@500 = 0.0360, Recall@500 = 0.0612
  - XGBoost: **PR-AUC = 0.02884**, ROC-AUC = 0.81324, Precision@500 = **0.0640**, Recall@500 = **0.1088**
  - **Uplift**: **+38.85% PR-AUC Uplift** over Logistic Regression (**8.96x precision vs random guessing**)

### 4.3 EXP-B1: Retrospective Snapshot Sensitivity (EPSS Leakage Audit)
- **Task**: Retrospective Sensitivity Benchmark
- **Features**: Identical to EXP-B2 **PLUS** 2026-07-16 EPSS score & percentile
- **Test Set Results (2025–2026)**:
  - Logistic Regression: **PR-AUC = 0.29481** (14.19x inflation)
  - XGBoost: **PR-AUC = 0.33153** (11.49x inflation)
  - **Retrospective Snapshot Leakage Delta**: $\Delta \text{PR-AUC} = +0.30269$ (**11.49x inflation**)

### 4.4 EXP-C1: Multi-Criteria Decision-Support Prioritization Simulation
- **Population**: $n = 227,694$ intersected CVEs
- **Linear Baseline Formula**:
  $$S_{\text{linear}} = 0.25 \cdot \left(\frac{\text{CVSS}}{10.0}\right) + 0.25 \cdot \text{EPSS} + 0.25 \cdot \mathbb{I}_{\text{KEV}} + 0.25 \cdot \text{Asset}_{\text{crit}}$$
- **Nonlinear Interactive Surface Formula**:
  $$S_{\text{nonlinear}} = \text{Asset}_{\text{crit}} \cdot \left[ 1 - \left(1 - \frac{\text{CVSS}}{10.0}\right)^{1 + 1.0 \cdot \mathbb{I}_{\text{KEV}}} \cdot \left(1 - \text{EPSS}\right)^{1 + 1.5 \cdot \mathbb{I}_{\text{KEV}}} \right]$$
- **Simulation Results**:
  - Global Rank Correlation: Spearman $\rho = 0.9962$, Kendall $\tau = 0.9356$
  - **Top-100 Queue Jaccard Overlap**: **0.005 (0.5% agreement)**
  - Top-1000 Queue Jaccard Overlap: 0.182 (18.2% agreement)
  - Key Finding: Linear sum forces binary KEV flag ($x_3=1$) to act as a rigid rank ceiling; $S_{\text{nonlinear}}$ allows high-severity / high-threat non-KEV vulnerabilities in critical asset contexts to enter top triage queues.

---

## 5. SHAP Post-Hoc Feature Attributions

### EXP-A1 (CVSS Regressor) Top Features
1. `tfidf_unauthorized` ($|\phi| = 0.34222$)
2. `tfidf_unauthenticated` ($|\phi| = 0.34216$)
3. `tfidf_critical` ($|\phi| = 0.27210$)
4. `tfidf_accessible` ($|\phi| = 0.19013$)
5. `CWE-79` ($|\phi| = 0.18454$)

### EXP-B2 (KEV Classifier) Top Features
1. `tfidf_gain` ($|\phi| = 0.82117$)
2. `CWE-22` (Path Traversal, $|\phi| = 0.59967$)
3. `tfidf_critical` ($|\phi| = 0.54493$)
4. `cpe_count` ($|\phi| = 0.46072$)
5. `tfidf_post` ($|\phi| = 0.38791$)

---

## 6. Categorization of Claims

- **Experimentally Demonstrated**:
  - Pre-scoring CVSS estimation (EXP-A1: 0.9750 MAE).
  - Publication-time KEV prediction (EXP-B2: 0.02884 PR-AUC, 8.96x vs random).
  - Retrospective EPSS snapshot leakage quantification (EXP-B1: 11.49x inflation).
  - Queue tail disruption in prioritization simulation (EXP-C1: 0.005 Top-100 Jaccard overlap).
  - SHAP feature importance tree attributions.
- **Implemented but not Experimentally Evaluated**:
  - FastAPI REST API backend (Port 5002, 15 endpoints).
  - SQLite user store and RBAC authorization policies (`analyst`, `researcher`, `admin`).
  - Native JavaScript Single Page Application (SPA) dashboard on GitHub Pages.
- **Proposed / Future Work**:
  - Dynamic real-time NVD feed polling and online model retraining.
  - Fine-grained enterprise organizational multi-tenancy.
  - Historical time-series EPSS trajectory tracking.
- **Merely Documented**:
  - Theoretical integration with enterprise SIEM/SOAR platforms.
  - Production deployment via Kubernetes / Cloud serverless clusters.
