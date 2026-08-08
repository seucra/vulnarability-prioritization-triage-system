# Phase 2 — Research & Experimental Protocol

**Repository**: `wdl-vuln-prioritization`  
**Phase**: Phase 2 — Experimental Protocol & Dataset Characterization  
**Date**: 2026-08-08  
**Status**: Protocol Formulated & Established (No Model Training Executed)  

---

## 1. Phase Objective

The objective of Phase 2 is to establish the empirical, theoretical, and methodological protocol for machine-learning-assisted vulnerability prioritization using the frozen canonical datasets compiled during Phase 1.1 (`data/processed/*.parquet`).

Phase 2 does **NOT** execute model training, hyperparameter optimization, SHAP explainability runs, or pipeline backend engineering. Instead, it defines:
1. What supervised learning tasks are supported by the available data.
2. Legitimate target variables and their statistical viability.
3. Feature availability at prediction time to eliminate temporal data leakage.
4. A scientifically defensible temporal split strategy.
5. Baseline models, nonlinear model families, and evaluation metrics.
6. The exact reference paper methodology and its formal boundaries.
7. Open research decisions and explicit validity threats.

---

## 2. Research Context & Reference Paper Analysis

Our investigation builds upon the foundational framework proposed by:

> **K. G. Agyei et al.**, *"Explainable Risk-Based Vulnerability Prioritization in Hybrid Cloud: Integrating CVSS, EPSS, and CISA KEV with Asset Criticality Signals,"* **World Journal of Advanced Research and Reviews**, vol. 30, no. 1, pp. 2044–2052, 2026. DOI: [10.30574/wjarr.2026.30.1.1006](https://doi.org/10.30574/wjarr.2026.30.1.1006).

### Reference Paper Methodological Analysis

| Element | Reference Paper Formulation | Project Methodological Position |
|---|---|---|
| **Prioritization Model** | Transparent weighted linear combination of CVSS base score, EPSS probability, CISA KEV binary flag, and asset criticality signals. | Serves as the primary transparent baseline model. |
| **Formula** | $S_{\text{priority}} = w_1 \cdot \text{CVSS}_{\text{norm}} + w_2 \cdot \text{EPSS} + w_3 \cdot \mathbb{I}_{\text{KEV}} + w_4 \cdot \text{Asset}_{\text{crit}}$ | Linear baseline equation evaluated across simulated asset environments. |
| **Normalizations** | $\text{CVSS}_{\text{norm}} = \frac{\text{CVSS}}{10.0} \in [0.0, 1.0]$, $\text{EPSS} \in [0.0, 1.0]$, $\mathbb{I}_{\text{KEV}} \in \{0, 1\}$. | Maintained for baseline comparisons. |
| **Assumptions** | Linear additive interaction between risk signals; independent signal contribution. | Identified as a core limitation: real-world risk involves multiplicative interactions (e.g. high EPSS + critical asset vs low EPSS + high CVSS). |
| **Future Work Claim** | Proposes machine-learned nonlinear models (e.g. XGBoost) and post-hoc explainability (SHAP) to capture signal interactions. | Our research directly evaluates this proposed nonlinear extension. |

> [!CAUTION]
> **Methodological Constraint (No Circular Target Labeling)**: We do **NOT** possess real enterprise remediation-order ground truth in public datasets. Therefore, we **MUST NOT** calculate a synthetic priority score (e.g. $w_1 \cdot \text{CVSS} + w_2 \cdot \text{EPSS} + \dots$) and train an ML model to predict that synthetic score. Doing so would be circular. Synthetic/controlled asset scenarios are strictly used for decision-support simulation, not supervised learning labels.

---

## 3. Candidate Research Questions

We establish three candidate research questions for evaluation. Each addresses a distinct technical challenge in vulnerability management:

### Candidate Question A (CVSS Estimation from Description & Metadata)
> *Can vulnerability natural language descriptions, vendor/product CPE structures, and CWE taxonomy attributes predict authoritative CVSS severity base scores and component vectors prior to formal NVD analyst scoring?*

- **Target**: `cvss_v31_base_score` (Continuous [0.0, 10.0]) or `cvss_v31_severity` (Categorical).
- **Motivation**: NVD analyst scoring incurs a multi-day to multi-week backlog. Predicting CVSS scores directly from initial CNA descriptions accelerates initial risk assessment.

### Candidate Question B (CISA KEV Known Exploitation Prediction)
> *Can early vulnerability metadata (CVSS components, CWE weakness classification, CPE applicability density, and text features) identify whether a vulnerability will ultimately be added to the CISA Known Exploited Vulnerabilities (KEV) catalog?*

- **Target**: `is_kev` (Binary $\{0, 1\}$).
- **Motivation**: Identifies high-risk vulnerabilities likely to experience real-world exploitation in enterprise environments.

### Candidate Question C (Nonlinear Prioritization & Decision Support)
> *Does a machine-learned nonlinear prioritization model (or multi-criteria decision framework) capture non-additive interactions between severity, threat likelihood, and asset criticality more effectively than the reference paper's linear weighted sum?*

- **Target**: Decision-support simulation ranking comparison (Evaluated via rank correlation and top-$k$ precision against simulated asset contexts).
- **Motivation**: Tests the explicit hypothesis proposed in the reference paper's future work section.

---

## 4. Candidate Target Analysis & Viability

We evaluate each potential target variable across sample size, missingness, class balance, temporal coverage, and methodological viability:

| Candidate Target | Variable Name | Task Type | Total Samples | Missingness % | Class Balance | Temporal Bounds | Authoritative vs Derived | Methodological Viability |
|---|---|---|---|---|---|---|---|---|
| **CVSS v3.1 Base Score** | `cvss_v31_base_score` | Regression | 227,694 | 37.88% | Continuous [0.0, 10.0] | 2016–2026 | Authoritative NVD | **Viable** (Primary regression target; well-understood scale). |
| **CVSS v3.1 Severity** | `cvss_v31_severity` | Classification | 227,694 | 37.88% | Low: 2.2%, Med: 44.6%, High: 39.1%, Crit: 14.1% | 2016–2026 | Authoritative NVD | **Viable** (Multi-class classification target). |
| **CVSS v3.1 Vector Components** | `AV, AC, PR, UI, S, C, I, A` | Multi-Output Classification | 227,694 | 37.88% | Varies per component | 2016–2026 | Authoritative NVD | **Viable** (Decomposes CVSS into sub-objective predictions). |
| **CISA KEV Membership** | `is_kev` | Binary Classification | 366,547 | 0.00% | Positive: 1,647 (0.45%), Negative: 364,900 (99.55%) | 2002–2026 | Authoritative CISA | **Viable** (Requires specialized imbalanced metrics: PR-AUC, ROC-AUC). |
| **KEV Addition Delay ($\Delta t$)** | `days_to_kev` | Survival / Time-to-Event | 1,647 | 99.55% (Unobserved for Non-KEV) | Right-censored continuous | 2021–2026 | Derived | **Conditionally Viable** (Only for KEV subset; high right-censoring). |
| **Synthetic Priority Score** | $S = w \cdot X$ | Regression | N/A | N/A | Continuous | N/A | Derived (Synthetic) | **REJECTED AS ML TARGET** (Circular learning). |

---

## 5. Feature Availability & Data Leakage Audit

To prevent **temporal data leakage** (where future information is inadvertently used to predict historical events), we audit every potential feature against its availability timestamp relative to prediction time:

| Feature Name | Source Table | Available Timestamp | Target Problem | Potential Leakage? | Leakage Reason | Safe Usage Guidance |
|---|---|---|---|---|---|---|
| `description_en` | `vulnerabilities.parquet` | CVE Publication Time | Target A & B | No | Available at initial publication. | **SAFE** for prediction at publication time. |
| `publication_year` | `vulnerabilities.parquet` | CVE Publication Time | Target A & B | No | Derived directly from `published`. | **SAFE** as split key / feature. |
| `published` timestamp | `vulnerabilities.parquet` | CVE Publication Time | Target A & B | No | Initial timestamp. | **SAFE** for temporal ordering. |
| `last_modified` timestamp | `vulnerabilities.parquet` | Revision Time | Target A & B | **YES** | Updated months/years after publication; contains future edits. | **DO NOT USE** as input for publication-time prediction. |
| `cwe_id` / `is_semantic_cwe` | `cve_cwe.parquet` | Initial Analysis Time | Target A & B | Low | Assigned during initial NVD triage. | **SAFE** when predicting post-triage targets. |
| `cpe23_uri` / `vendor` / `product` | `cve_cpe.parquet` | Config Assignment Time | Target A & B | Low | Derived from configuration nodes. | **SAFE** for platform context. |
| `cvss_v31_base_score` | `vulnerabilities.parquet` | NVD Analyst Review | Target B (KEV) | **YES (for Target A)** | Cannot use CVSS v3.1 to predict CVSS v3.1. | **TARGET ONLY** for Target A; **SAFE** input for Target B *if predicting KEV post-scoring*. |
| `cvss_v31_vector` components | `vulnerabilities.parquet` | NVD Analyst Review | Target B (KEV) | **YES (for Target A)** | Target identity for component prediction. | **TARGET ONLY** for Target A; **SAFE** input for Target B post-scoring. |
| `epss` score snapshot | `epss.parquet` | Snapshot Date (`2026-07-16`) | Target B (KEV) | **HIGH (for historical CVEs)** | EPSS score represents a 2026 static snapshot, not historical EPSS at CVE publication. | **MUST DISCLOSE SNAPSHOT LEAKAGE** if used as input for pre-2026 KEV prediction. |
| `date_added` (KEV) | `kev.parquet` | KEV Addition Date | Target A & B | **CRITICAL** | Target identity / future label timestamp. | **DO NOT USE** as input feature. |
| `known_ransomware_campaign_use` | `kev.parquet` | KEV Addition Date | Target A & B | **CRITICAL** | Post-exploitation observation tag. | **DO NOT USE** as input feature. |

---

## 6. Temporal Considerations & Candidate Split Strategies

The dataset spans publication years from 1988 to 2026. Standard random $k$-fold cross-validation causes severe temporal leakage because future vulnerabilities (e.g. 2025) train models to predict past vulnerabilities (e.g. 2018).

We evaluate three candidate split strategies:

```
Strategy 1: Random Stratified Split (Baseline / Reference)
[ Train: 70% random ] [ Val: 15% random ] [ Test: 15% random ]
- Advantage: Standard baseline benchmark.
- Disadvantage: Severe temporal leakage across publication years; optimistic performance estimates.

Strategy 2: Publication-Time Split (Recommended Primary Split)
[ Train: 2002 – 2022 (218,655 CVEs) ] [ Val: 2023 – 2024 (71,653 CVEs) ] [ Test: 2025 – 2026 (91,242 CVEs) ]
- Advantage: Strictly respects arrow of time; mirrors real-world deployment where models predict future CVEs.
- Disadvantage: CVSS version availability shifts over time (e.g. CVSS v4.0 appears only in 2024–2026).

Strategy 3: Rolling Window / Temporal Expanding Evaluation
[ Train: <= T_i ] [ Evaluate: T_{i+1} ] (e.g. Expanding 3-year windows)
- Advantage: Provides trajectory of model performance stability across historical epochs.
- Disadvantage: Increases computational overhead for validation.
```

---

## 7. Model Families Analysis

We evaluate candidate model families for Phase 3 execution across performance, interpretability, computational complexity, and post-hoc explainability compatibility:

| Model Family | Representative Algorithms | Suitable Target | Interpretability | Computational Overhead | Leakage Sensitivity | SHAP Compatibility | Recommended Role |
|---|---|---|---|---|---|---|---|
| **Linear / Logistic Baseline** | Ridge, Lasso, Logistic Regression | Continuous Score / KEV Binary | High (Coefficients) | Negligible | Low | Tree Explainer N/A (Linear Explainer) | **Mandatory Baseline** |
| **Single Decision Trees** | CART, DecisionTreeClassifier | Continuous / Categorical | High (Visual Tree) | Low | Moderate | Compatible | **Intermediary Baseline** |
| **Random Forests** | RandomForestRegressor / Classifier | Continuous / Categorical / KEV | Moderate (Feature Importance) | Moderate | Moderate | Fully Compatible (TreeExplainer) | **Strong Ensemble Baseline** |
| **Gradient Boosted Decision Trees** | XGBoost, LightGBM, CatBoost | Continuous / KEV Binary | Low (Black-box ensemble) | High | High | Fully Compatible (Optimized C++ TreeExplainer) | **Primary Candidate Nonlinear Model** |
| **Text Vectorizers + Linear/GBDT** | TF-IDF / Embeddings + XGBoost | CVSS Prediction from Text | Low to Moderate | High | High | Compatible via Kernel/TreeExplainer | **Exploratory for Target A** |

---

## 8. Recommended Evaluation Metrics

We establish primary and secondary evaluation metrics tailored to target characteristics.

> [!IMPORTANT]
> **Accuracy Warning**: Accuracy is **REJECTED** as a primary metric for CISA KEV prediction due to the 0.45% class imbalance (a naive constant-zero classifier achieves 99.55% accuracy while providing zero security value).

### 8.1 Regression Tasks (CVSS Base Score Prediction)
- **Primary Metric**: **MAE (Mean Absolute Error)** — Directly interpretable in CVSS points (0.0 to 10.0 scale).
- **Secondary Metrics**: 
  - **RMSE (Root Mean Squared Error)** — Penalizes large scoring errors.
  - **$R^2$ (Coefficient of Determination)** — Quantifies variance explained.

### 8.2 Classification Tasks (CVSS Severity Category)
- **Primary Metric**: **Macro-averaged F1-Score** — Balances performance across Low, Medium, High, and Critical classes.
- **Secondary Metrics**: Confusion Matrix, Weighted F1-Score.

### 8.3 Imbalanced Binary Classification Tasks (CISA KEV Prediction)
- **Primary Metrics**: 
  - **PR-AUC (Precision-Recall Area Under Curve / Average Precision)** — Robust metric for extreme class imbalance (0.45% positive rate).
  - **ROC-AUC (Receiver Operating Characteristic AUC)** — Evaluates global ranking capability.
- **Secondary Metrics**: Precision@$k$ ($k \in \{100, 500, 1000\}$), Recall@$k$, F1-Score at optimal decision threshold.

### 8.4 Prioritization & Decision Support (Ranking Evaluation)
- **Primary Metric**: **Spearman Rank Correlation Coefficient ($\rho$)** & **Kendall's $\tau$** — Evaluates rank-order agreement between prioritization models.
- **Secondary Metric**: Top-$k$ Overlap Ratio (Jaccard similarity among top 1% prioritized vulnerabilities).

---

## 9. Explainability & Post-Hoc Analysis Framework

To satisfy research objectives regarding transparent decision support:
1. **Global Feature Importance**: Quantify global feature contributions using SHAP (SHapley Additive exPlanations) mean absolute Shapley values ($|\phi_j|$).
2. **Local Instance Explanations**: Generate individual SHAP force plots / waterfall plots explaining why specific CVEs received elevated risk prioritisations.
3. **Feature Interaction Audits**: Inspect 2-way SHAP interaction values ($\phi_{i, j}$) to test the paper's core hypothesis regarding nonlinear interactions (e.g. interaction between EPSS score and CVSS Attack Vector).

---

## 10. Proposed Experiment Matrix (Phase 3 Proposal)

| Exp ID | Research Question | Target Variable | Population / Subset | Input Features | Baseline Model | Candidate Nonlinear Model | Split Strategy | Primary Metrics | Secondary Metrics | Explainability Method |
|---|---|---|---|---|---|---|---|---|---|---|
| **EXP-A1** | Candidate A (CVSS Score) | `cvss_v31_base_score` | CVEs with CVSS v3.1 (227,694) | TF-IDF text + CWE + CPE counts | Linear Regression | XGBoost Regressor | Publication-Time (2002-22 / 23-24 / 25-26) | MAE | RMSE, $R^2$ | SHAP TreeExplainer |
| **EXP-A2** | Candidate A (CVSS Severity) | `cvss_v31_severity` | CVEs with CVSS v3.1 (227,694) | TF-IDF text + CWE + CPE counts | Logistic Regression | Random Forest / XGBoost | Publication-Time | Macro F1 | Confusion Matrix | SHAP Summary Plot |
| **EXP-B1** | Candidate B (KEV Binary) | `is_kev` | Canonical NVD (366,547) | CVSS v3.1 components + CWE + CPE + EPSS | Weighted Logistic Regression | XGBoost Classifier | Publication-Time | PR-AUC | ROC-AUC, Precision@500, Recall@500 | SHAP Force Plots |
| **EXP-B2** | Candidate B (KEV Leakage Control) | `is_kev` | Canonical NVD (366,547) | Metadata strictly available at publication (excluding EPSS snapshot) | Logistic Regression | XGBoost Classifier | Publication-Time | PR-AUC | ROC-AUC | SHAP Dependence Plots |
| **EXP-C1** | Candidate C (Prioritization) | Ranking Order | Simulated Asset Contexts | CVSS + EPSS + KEV + Asset Criticality | Agyei et al. Weighted Linear Sum | Multi-Criteria / GBDT Risk Surface | Controlled Simulation | Spearman $\rho$ | Top-100 Overlap | SHAP Interaction Values |

---

## 11. Threats to Validity

### 11.1 Internal Validity
- **Snapshot Temporal Leakage**: EPSS scores represent a single static snapshot (2026-07-16). Using EPSS as a predictor for historical KEV additions (e.g. 2021) introduces retrospective leakage (EPSS score was calculated with knowledge of 2026 data).
- **CISA KEV Zero-Day Addition Delay**: 210 CVEs (12.75% of KEV) were added to KEV prior to NVD publication, creating negative delay statistics ($\Delta t < 0$).

### 11.2 External Validity
- **Absence of Real Enterprise Remediation Labels**: Public datasets contain vulnerability characteristics, not organizational patching orders. Prioritization efficacy outside simulated asset contexts cannot be claimed without enterprise log validation.
- **CPE Matching Completeness**: The NVD API 2.0 configuration nodes capture 83.53% of CVEs; unmapped CVEs (16.47%) lack platform applicability features.

### 11.3 Construct Validity
- **Non-KEV $\neq$ Non-Exploited**: Vulnerabilities not listed in CISA KEV may still experience unobserved or targeted exploitation. The binary KEV label represents *known published exploitation*, not absolute non-exploitation.

---

## 12. Recommended vs. Rejected Research Directions

### Recommended for Phase 3 Execution
1. **EXP-B1 / EXP-B2 (CISA KEV Exploitation Prediction)**: Strongest empirical grounding with clear binary labels and high security relevance.
2. **EXP-A1 (CVSS Estimation from Initial Text/Metadata)**: Clear utility for addressing NVD analyst scoring backlogs.
3. **EXP-C1 (Reference Paper Linear Baseline vs. Nonlinear Simulation)**: Directly tests the proposed extension in Agyei et al. (2026).

### Rejected and Why
- **Supervised Learning of a Synthetic Priority Label**: *Rejected because it is circular.* (Training an ML model to predict $w_1 \text{CVSS} + w_2 \text{EPSS} + w_3 \text{KEV}$ simply fits linear regression weights to an arbitrary user-defined equation).
- **Time-Series Survival Modeling on Full Dataset**: *Rejected due to 99.55% right-censoring in KEV timing.*
- **Random 10-Fold CV Evaluation**: *Rejected due to severe temporal data leakage across publication years.*

---

## 13. Open Research Decisions

The following methodological choices remain open for final confirmation prior to Phase 3 code execution:

> [!NOTE]
> **OPEN DECISION 1: Temporal Split Threshold Selection**  
> We propose Train (2002–2022), Val (2023–2024), Test (2025–2026). Alternative threshold: Train (2002–2023), Val (2024), Test (2025–2026).

> [!NOTE]
> **OPEN DECISION 2: EPSS Inclusion in KEV Prediction Features**  
> Should EXP-B include EPSS snapshot scores as an input feature despite snapshot temporal leakage, or should EXP-B2 (EPSS-excluded) serve as the primary submission model?

> [!NOTE]
> **OPEN DECISION 3: Asset Criticality Simulation Distributions**  
> For Candidate Question C, what synthetic asset criticality distribution (e.g. Uniform vs Log-normal vs Categorical Tier 1/2/3) should be instantiated for simulated enterprise environments?
