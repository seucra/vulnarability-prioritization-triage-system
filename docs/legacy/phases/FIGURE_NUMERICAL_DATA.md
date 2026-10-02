# Phase 2 & Phase 3 Research Figures — Machine-Readable Numerical Data

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Execution Date**: August 23, 2026  
**Document Purpose**: Provides structured textual and tabular numerical representations underlying Phase 2 and Phase 3 research figures, referencing exact metrics, statistical summaries, and sampled machine-readable artifacts where full point-level outputs are uncompressed or high-dimensional. Allows automated tools and researchers to analyze research results without relying on image pixel rendering.  

---

## Machine-Readable CSV Directory Index (`docs/research/figure_data/`)

| Figure Name | Machine-Readable CSV File | Description |
|---|---|---|
| `cvss_distributions.png` | [phase2_cvss_distribution.csv](figure_data/phase2_cvss_distribution.csv) | CVSS v2, v3.0, v3.1, v4.0 distribution statistics & boxplot whiskers |
| `epss_distribution_and_percentiles.png` | [phase2_epss_distribution.csv](figure_data/phase2_epss_distribution.csv) | EPSS score histogram bins and percentile density curve |
| `kev_class_imbalance.png` | [phase2_kev_imbalance.csv](figure_data/phase2_kev_imbalance.csv) | CISA KEV binary class counts and percentages |
| `kev_publication_to_added_delay.png` | [phase2_kev_delay.csv](figure_data/phase2_kev_delay.csv) | KEV addition delay distribution and histogram bins |
| `temporal_availability_by_year.png` | [phase2_temporal_availability.csv](figure_data/phase2_temporal_availability.csv) | Yearly CVE publication volume and feature availability (2000–2026) |
| `a1_cvss_actual_vs_predicted.png` | [phase3_a1_predictions.csv](figure_data/phase3_a1_predictions.csv) | EXP-A1 1,000-row sample from full 81,604-row test prediction artifact |
| `a1_cvss_residuals.png` | [phase3_a1_residuals.csv](figure_data/phase3_a1_residuals.csv) | EXP-A1 XGBoost residual error histogram bins |
| `b1_vs_b2_comparison.png` | [phase3_b1_b2_comparison.csv](figure_data/phase3_b1_b2_comparison.csv) | EXP-B1 vs EXP-B2 PR-AUC retrospective EPSS leakage audit |
| `b2_pr_curve.png` | [phase3_b2_pr_curve.csv](figure_data/phase3_b2_pr_curve.csv) | EXP-B2 100 sampled threshold points along PR curve |
| `b2_roc_curve.png` | [phase3_b2_roc_curve.csv](figure_data/phase3_b2_roc_curve.csv) | EXP-B2 100 sampled threshold points along ROC curve |
| `c1_ranking_changes_across_tiers.png` | [phase3_c1_rankings.csv](figure_data/phase3_c1_rankings.csv) | EXP-C1 rank correlation and top-queue overlap across 4 asset tiers |
| `c1_risk_surface_contours.png` | [phase3_c1_risk_surface.csv](figure_data/phase3_c1_risk_surface.csv) | Exact $50 \times 50$ grid (2,500 points) for plotted slice ($x_3=1, x_4=1.0$ vs $x_3=0, x_4=1.0$) |
| `shap_a1_global_importance.png` | [phase3_shap_a1.csv](figure_data/phase3_shap_a1.csv) | EXP-A1 CVSS regressor global SHAP feature importances |
| `shap_b2_global_importance.png` | [phase3_shap_b2.csv](figure_data/phase3_shap_b2.csv) | EXP-B2 KEV classifier global SHAP feature importances |

---

# Phase 2 Visualizations — Exact Numerical Data

## 1. CVSS Base Score Distributions (`cvss_distributions.png`)

- **Dataset / Population**: Canonical NVD vulnerabilities dataset (`data/processed/vulnerabilities.parquet`, $N = 366,547$ total CVE records).
- **Filtering**: Non-null CVSS score entries extracted per metric version.

### Summary Statistics Table

| CVSS Version | Column Name | Populated Count ($n$) | Missing Count | Coverage % | Min | Q1 (P25) | Median (P50) | Q3 (P75) | Max | Mean | Std Dev | Whisker Low | Whisker High |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| **CVSS v2.0** | `cvss_v2_base_score` | 194,548 | 171,999 | 53.0759% | 0.0 | 4.3 | 5.5 | 7.5 | 10.0 | 5.909 | 1.973 | 0.0 | 10.0 |
| **CVSS v3.0** | `cvss_v30_base_score` | 54,540 | 312,007 | 14.8794% | 0.0 | 6.1 | 7.5 | 8.6 | 10.0 | 7.192 | 1.667 | 2.35 | 10.0 |
| **CVSS v3.1** | `cvss_v31_base_score` | 227,694 | 138,853 | 62.1186% | 0.0 | 5.5 | 7.2 | 8.2 | 10.0 | 7.032 | 1.703 | 1.45 | 10.0 |
| **CVSS v4.0** | `cvss_v40_base_score` | 29,964 | 336,583 | 8.1747% | 0.0 | 5.1 | 6.6 | 8.4 | 10.0 | 6.145 | 2.338 | 0.15 | 10.0 |

- **CSV File**: `docs/research/figure_data/phase2_cvss_distribution.csv`

---

## 2. EPSS Score Distribution & Percentile Curve (`epss_distribution_and_percentiles.png`)

- **Dataset / Population**: FIRST EPSS snapshot dataset (`data/processed/epss.parquet`, $N = 348,900$ CVE entries).
- **Snapshot Metadata**: Model `v2026.06.15`, Score Date `2026-07-16T12:03:48Z`.

### EPSS Score Distribution Summary

| Metric | EPSS Probability Score (`epss`) | EPSS Percentile (`percentile`) |
|---|---|---|
| **Minimum** | 0.00046 | 0.00000 |
| **10th Percentile (P10)** | 0.00200 | 0.10000 |
| **25th Percentile (P25)** | 0.00329 | 0.25001 |
| **Median (P50)** | **0.00727** | **0.50001** |
| **Mean** | **0.02888** | **0.50000** |
| **75th Percentile (P75)** | 0.01728 | 0.75000 |
| **90th Percentile (P90)** | 0.04282 | 0.90000 |
| **95th Percentile (P95)** | 0.09783 | 0.95000 |
| **99th Percentile (P99)** | **0.58648** | 0.99000 |
| **99.9th Percentile (P99.9)** | **0.97856** | 0.99900 |
| **Maximum** | 0.99999 | 1.00000 |
| **Standard Deviation** | 0.09298 | 0.28868 |

- **CSV File**: `docs/research/figure_data/phase2_epss_distribution.csv` (contains 50 histogram bin counts and density calculations).

---

## 3. CISA KEV Binary Class Imbalance (`kev_class_imbalance.png`)

- **Dataset / Population**: Canonical NVD vulnerabilities ($N = 366,547$) intersected with CISA KEV catalog ($N = 1,647$).

### Class Balance Table

| Category Class | Label | Record Count | Class Percentage | Plot Scale |
|---|---|---|---|---|
| **Negative Class ($y=0$)** | Non-KEV (Unobserved Exploitation) | **364,900** | **99.5507%** | Log Scale Bar 1 |
| **Positive Class ($y=1$)** | CISA KEV (Known Exploited) | **1,647** | **0.4493%** | Log Scale Bar 2 |
| **Total Population** | Canonical Dataset | **366,547** | **100.0000%** | — |

- **Imbalance Ratio**: 364,900 / 1,647 = **221.55 to 1** (~1 positive per 222 CVEs).
- **CSV File**: `docs/research/figure_data/phase2_kev_imbalance.csv`

---

## 4. KEV Publication-to-Addition Delay (`kev_publication_to_added_delay.png`)

- **Dataset / Population**: CISA KEV catalog entries merged with canonical NVD publication timestamps ($n = 1,647$ KEV CVEs).
- **Delay Formula**: $\Delta t = \frac{\text{Timestamp}(\text{date\_added}) - \text{Timestamp}(\text{published})}{365.25 \times 86400} \text{ (in years)}$.

### Delay Distribution Summary Statistics

| Statistic | Value in Years | Value in Days |
|---|---|---|
| **Minimum Delay** | -0.80 years | -290.8 days |
| **25th Percentile (Q1)** | 0.03 years | 10.7 days |
| **Median Delay (P50)** | **0.78 years** | **285.2 days** |
| **Mean Delay** | **2.44 years** | **890.7 days** |
| **75th Percentile (Q3)** | 3.84 years | 1,402.0 days |
| **Maximum Delay** | 19.69 years | 7,190.8 days |
| **Negative Delay Count ($\Delta t < 0$)** | **210 CVEs** | **12.75% of KEV** (Added to KEV prior to NVD publication) |

- **CSV File**: `docs/research/figure_data/phase2_kev_delay.csv` (contains 40 histogram bin counts across time delay ranges).

---

## 5. Temporal Availability by Year (`temporal_availability_by_year.png`)

- **Dataset / Population**: Publication years 2000 to 2026 in canonical dataset ($N = 363,858$ CVEs for years $\ge 2000$).

### Plotted Yearly Series Table

| Year | Total Published CVEs | CVSS v2 Available | CVSS v3.1 Available | EPSS Snapshot Coverage | KEV Catalog Additions |
|---|---|---|---|---|---|
| **2000** | 1,020 | 1,019 | 9 | 1,019 | 0 |
| **2001** | 1,679 | 1,676 | 38 | 1,676 | 0 |
| **2002** | 2,170 | 2,156 | 54 | 2,156 | 1 |
| **2003** | 1,548 | 1,527 | 17 | 1,527 | 0 |
| **2004** | 2,479 | 2,451 | 44 | 2,451 | 2 |
| **2005** | 5,010 | 4,932 | 64 | 4,932 | 1 |
| **2006** | 6,659 | 6,608 | 47 | 6,608 | 2 |
| **2007** | 6,596 | 6,516 | 59 | 6,516 | 2 |
| **2008** | 5,664 | 5,632 | 87 | 5,632 | 6 |
| **2009** | 5,778 | 5,732 | 107 | 5,732 | 14 |
| **2010** | 4,667 | 4,639 | 124 | 4,639 | 23 |
| **2011** | 4,172 | 4,150 | 58 | 4,150 | 9 |
| **2012** | 5,351 | 5,288 | 114 | 5,288 | 22 |
| **2013** | 5,324 | 5,187 | 97 | 5,187 | 35 |
| **2014** | 8,008 | 7,928 | 113 | 7,928 | 34 |
| **2015** | 6,595 | 6,494 | 94 | 6,494 | 43 |
| **2016** | 6,517 | 6,449 | 791 | 6,449 | 53 |
| **2017** | 18,113 | 14,642 | 1,801 | 14,642 | 89 |
| **2018** | 18,154 | 16,510 | 1,852 | 16,510 | 76 |
| **2019** | 18,938 | 17,305 | 9,224 | 17,305 | 128 |
| **2020** | 19,222 | 18,322 | 18,322 | 18,322 | 146 |
| **2021** | 21,950 | 20,149 | 20,045 | 20,149 | 213 |
| **2022** | 26,431 | 13,223 | 24,978 | 25,074 | 130 |
| **2023** | 30,949 | 1,926 | 28,816 | 28,817 | 164 |
| **2024** | 40,704 | 2,971 | 39,102 | 39,959 | 160 |
| **2025** | 49,972 | 5,899 | 44,081 | 48,167 | 194 |
| **2026** | 41,270 | 3,644 | 37,523 | 39,962 | 100 |

- **CSV File**: `docs/research/figure_data/phase2_temporal_availability.csv`

---

# Phase 3 Visualizations — Exact Numerical Data

## 6. EXP-A1: Actual vs. Predicted & Residuals (`a1_cvss_actual_vs_predicted.png`, `a1_cvss_residuals.png`)

- **Dataset / Population**: TEST Partition (Publication Years 2025–2026, $n = 81,604$ CVSS v3.1-scored CVEs).
- **Target**: Authoritative NVD `cvss_v31_base_score` ($y \in [0.0, 10.0]$).
- **Residual Definition**: $\text{Residual} = \hat{y}_{\text{XGBoost}} - y_{\text{Actual}}$.

### Evaluation Metrics & Distribution Summary

| Metric / Parameter | Ridge Regression Baseline | XGBoost Regressor (Nonlinear) | Absolute Delta |
|---|---|---|---|
| **Test MAE** | 1.0954 | **0.9750** | **-0.1204** (-10.99%) |
| **Test RMSE** | 1.4089 | **1.3059** | **-0.1030** (-7.31%) |
| **Test $R^2$** | 0.3194 | **0.4153** | **+0.0959** (+30.03%) |
| **Actual Mean ($y_{\text{test}}$)** | 7.0321 | 7.0321 | — |
| **Predicted Mean ($\hat{y}$)** | 7.0410 | 7.0733 | +0.0412 bias |
| **Predicted Std Dev ($\hat{y}$)** | 1.0210 | 1.1412 | — |
| **Residual Mean** | +0.0089 | +0.0412 | — |
| **Residual Std Dev** | 1.4088 | 1.3053 | — |

- **CSV Files**:
  - `docs/research/figure_data/phase3_a1_predictions.csv` (contains a 1,000-row representative sample of the full 81,604-row test prediction artifact `data/experiments/phase3/exp_a1/test_predictions.parquet`).
  - `docs/research/figure_data/phase3_a1_residuals.csv` (contains 50 residual error histogram bins computed over all 81,604 test predictions).

---

## 7. Retrospective EPSS Snapshot Leakage Comparison (`b1_vs_b2_comparison.png`)

- **Dataset / Population**: TEST Partition ($n = 91,242$ CVEs, 294 KEV positives).
- **Comparison Focus**: Quantifies artificial PR-AUC performance inflation caused by introducing retrospective static EPSS snapshots into historical prediction models.

### EXP-B1 vs. EXP-B2 Results Table

| Model Architecture | EXP-B2 PR-AUC (Publication-Time, No EPSS) | EXP-B1 PR-AUC (Retrospective EPSS 2026 Snapshot) | Absolute Leakage Delta ($\Delta \text{PR-AUC}$) | Retrospective Inflation Multiplier |
|---|---|---|---|---|
| **Logistic Regression** | 0.02077 | **0.29481** | +0.27404 | **14.19x Inflation** |
| **XGBoost Classifier** | 0.02884 | **0.33153** | +0.30269 | **11.49x Inflation** |

- **CSV File**: `docs/research/figure_data/phase3_b1_b2_comparison.csv`

---

## 8. EXP-B2: Precision-Recall & ROC Curves (`b2_pr_curve.png`, `b2_roc_curve.png`)

- **Dataset / Population**: TEST Partition (Publication Years 2025–2026, $N = 91,242$ total CVEs).
- **Class Counts**: 294 Positive KEV CVEs ($y=1$), 90,948 Negative Non-KEV CVEs ($y=0$).
- **Random Baseline Precision**: $\frac{294}{91,242} = 0.003222$ (0.3222%).

### PR & ROC Metric Summary

| Model | PR-AUC (Primary) | ROC-AUC | Precision@500 | Recall@500 | Max F1 | Optimal Threshold |
|---|---|---|---|---|---|---|
| **Random Baseline** | 0.00322 | 0.50000 | 0.00322 | 0.00548 | 0.00642 | — |
| **Logistic Regression** | 0.02077 | **0.85857** | 0.03600 (3.6%) | 0.06122 (6.1%) | 0.04985 | 0.99354 |
| **XGBoost Classifier** | **0.02884** | 0.81324 | **0.06400 (6.4%)** | **0.10884 (10.9%)** | **0.08725** | 0.53738 |
| **Relative Uplift (XGB vs Log)** | **+38.85%** | -5.28% | **+77.78%** | **+77.78%** | **+75.03%** | — |

- **CSV Files**:
  - `docs/research/figure_data/phase3_b2_pr_curve.csv` (contains 100 sampled threshold evaluation points along the continuous Precision-Recall curve).
  - `docs/research/figure_data/phase3_b2_roc_curve.csv` (contains 100 sampled threshold evaluation points along the continuous ROC curve).

---

## 9. EXP-C1: Ranking Changes Across Asset Tiers (`c1_ranking_changes_across_tiers.png`)

- **Dataset / Population**: Intersected CVE dataset ($n = 227,694$ CVEs).
- **Scenarios**: Evaluated across 4 Asset Criticality Tiers ($x_4 \in \{0.25, 0.50, 0.75, 1.00\}$).

### Multi-Criteria Triage Simulation Results Table

| Asset Criticality Tier | Asset Value ($x_4$) | Spearman Rank Corr ($\rho$) | Kendall Rank Corr ($\tau$) | Top-100 Jaccard Overlap | Top-1000 Jaccard Overlap | KEV in Top-100 (Lin vs Nonlin) | KEV in Top-1000 (Lin vs Nonlin) |
|---|---|---|---|---|---|---|---|
| **Tier 1 (Low)** | 0.25 | 0.9962 | 0.9356 | **0.0050** | **0.1820** | 100 vs 3 ($\Delta = -97$) | 1,000 vs 315 ($\Delta = -685$) |
| **Tier 2 (Medium)** | 0.50 | 0.9962 | 0.9356 | **0.0050** | **0.1820** | 100 vs 3 ($\Delta = -97$) | 1,000 vs 315 ($\Delta = -685$) |
| **Tier 3 (High)** | 0.75 | 0.9962 | 0.9356 | **0.0050** | **0.1820** | 100 vs 3 ($\Delta = -97$) | 1,000 vs 315 ($\Delta = -685$) |
| **Tier 4 (Critical)** | 1.00 | 0.9962 | 0.9356 | **0.0050** | **0.1820** | 100 vs 3 ($\Delta = -97$) | 1,000 vs 315 ($\Delta = -685$) |

- **CSV File**: `docs/research/figure_data/phase3_c1_rankings.csv`

---

## 10. EXP-C1: Interactive Risk Surface Grid (`c1_risk_surface_contours.png`)

- **General Formulas**:
  - **Mode 1 Linear Baseline**:
    $$S_{\text{linear}}(x) = 0.25 \cdot x_1 + 0.25 \cdot x_2 + 0.25 \cdot x_3 + 0.25 \cdot x_4$$
  - **Mode 2 Nonlinear Interactive Surface**:
    $$S_{\text{nonlinear}}(x) = x_4 \cdot \left[ 1 - (1 - x_1)^{1 + 1.0 \cdot x_3} \cdot (1 - x_2)^{1 + 1.5 \cdot x_3} \right]$$
- **Grid Resolution**: $50 \times 50 = 2,500$ evaluation points ($x_1 \in [0, 1]$, $x_2 \in [0, 1]$).

### Contour Surface Sample Grid Points ($x_4 = 1.0$)

| Normalized CVSS ($x_1$) | EPSS Score ($x_2$) | Linear Score ($S_{\text{linear}}$, $x_3=0$) | Nonlinear Score ($S_{\text{nonlinear}}$, $x_3=1$) | Absolute Delta ($S_{\text{nonlin}} - S_{\text{lin}}$) |
|---|---|---|---|---|
| 0.0000 | 0.0000 | 0.250000 | 0.000000 | -0.250000 |
| 0.2500 | 0.1000 | 0.337500 | 0.564287 | +0.226787 |
| 0.5000 | 0.2000 | 0.425000 | 0.856885 | +0.431885 |
| 0.7500 | 0.5000 | 0.562500 | 0.988950 | +0.426450 |
| 1.0000 | 1.0000 | 0.750000 | 1.000000 | +0.250000 |

- **CSV File**: `docs/research/figure_data/phase3_c1_risk_surface.csv` (contains the exact $50 \times 50$ grid sampling of 2,500 points for the specific visual slice $x_3=1, x_4=1.0$ vs $x_3=0, x_4=1.0$).

---

## 11. SHAP Post-Hoc Global Feature Importances (`shap_a1_global_importance.png`, `shap_b2_global_importance.png`)

- **Method**: Calculated using `shap.TreeExplainer` on frozen XGBoost test set models ($n = 81,604$ for A1, $n = 91,242$ for B2).
- **Metric**: Mean Absolute SHAP Value ($|\phi_j| = \frac{1}{N} \sum_{i=1}^N |\phi_j^{(i)}|$).

### EXP-A1 & EXP-B2 Top-10 Global SHAP Feature Importances

| Rank | EXP-A1 (CVSS Regressor) Feature | EXP-A1 $|\phi|$ | EXP-B2 (KEV Classifier) Feature | EXP-B2 $|\phi|$ |
|---|---|---|---|---|
| 1 | `tfidf_unauthorized` | **0.342220** | `tfidf_gain` | **0.821174** |
| 2 | `tfidf_unauthenticated` | **0.342159** | `CWE-22` (Path Traversal) | **0.599672** |
| 3 | `tfidf_critical` | **0.272102** | `tfidf_critical` | **0.544931** |
| 4 | `tfidf_accessible` | **0.190134** | `cpe_count` | **0.460718** |
| 5 | `CWE-79` (XSS) | **0.184541** | `tfidf_post` | **0.387910** |
| 6 | `CWE-434` (Unrestricted Upload) | 0.171203 | `tfidf_remote` | 0.354120 |
| 7 | `cpe_count` | 0.165412 | `part_a_count` (Apps) | 0.312019 |
| 8 | `tfidf_execute` | 0.154210 | `vendor_count` | 0.289410 |
| 9 | `tfidf_arbitrary` | 0.149812 | `CWE-89` (SQL Injection) | 0.264102 |
| 10 | `CWE-476` (NULL Pointer) | 0.138210 | `product_count` | 0.241508 |

- **CSV Files**:
  - `docs/research/figure_data/phase3_shap_a1.csv`
  - `docs/research/figure_data/phase3_shap_b2.csv`

---

## 12. Reproduction Validation Statement

- All numerical outputs were reproduced **strictly from the current frozen datasets** (`data/processed/*.parquet`), **current experiment scripts** (`scripts/experiments/*.py`), and **current serialized model binaries** (`data/experiments/phase3/*`).
- Zero research datasets, model configurations, random seeds (`RANDOM_SEED = 42`), or evaluation formulas were modified during extraction.
- All generated CSV files under `docs/research/figure_data/` correspond 100% to the input series plotted by `scripts/research/generate_phase2_figures.py` and `scripts/experiments/generate_phase3_figures.py`.

---

## 13. Extraction Limitations

The machine-readable CSV artifacts under `docs/research/figure_data/` reflect specific sampling and grid-discretization strategies designed to represent visual figures without producing unmanageably large text files:

1. **`phase3_a1_predictions.csv`**: Contains a **1,000-row representative sample** from the full 81,604-row EXP-A1 test partition prediction artifact (`data/experiments/phase3/exp_a1/test_predictions.parquet`). The full 81,604-row prediction dataset remains preserved in Parquet format.
2. **`phase3_b2_pr_curve.csv` & `phase3_b2_roc_curve.csv`**: Contain **100 sampled threshold points** evaluated along the continuous Precision-Recall and ROC curves, rather than complete uncompressed threshold arrays (which contain over 91,000 threshold evaluation steps).
3. **`phase3_c1_risk_surface.csv`**: Evaluates an exact **$50 \times 50$ grid (2,500 points)** for the specific 2D visual slice rendered in `c1_risk_surface_contours.png` ($x_3=1, x_4=1.0$ for the nonlinear surface and $x_3=0, x_4=1.0$ for the linear comparison). The generalized multi-dimensional mathematical formulations for $S_{\text{linear}}$ and $S_{\text{nonlinear}}$ apply continuously across all $x_1, x_2 \in [0, 1]$, $x_3 \in \{0, 1\}$, and $x_4 \in [0.25, 1.00]$.
