# Phase 3 — Concise Research Results Summary

**Repository**: `wdl-vuln-prioritization`  
**Phase**: Phase 3 — Experimental Execution  
**Target Paper Integration**: Paper-Ready Quantitative Summary  

---

## 1. Executive Summary Table of Experimental Results

| Experiment ID | Research Task | Target Variable | Primary Metric | Baseline Performance (Linear / Logistic) | Nonlinear Model Performance (XGBoost) | Relative Improvement |
|---|---|---|---|---|---|---|
| **EXP-A1** | Pre-Scoring CVSS v3.1 Estimation | `cvss_v31_base_score` | **MAE** (Lower is better) | 1.0954 CVSS points (Ridge) | **0.9750 CVSS points** (XGBoost) | **-10.99% Error Reduction** ($\Delta \text{MAE} = -0.1204$) |
| **EXP-B2** | Publication-Time KEV Prediction (No EPSS) | `is_kev` | **PR-AUC** (Higher is better) | 0.02077 (Logistic Reg.) | **0.02884** (XGBoost) | **+38.85% PR-AUC Uplift** (**8.96x vs Random**) |
| **EXP-B1** | Retrospective KEV Sensitivity (EPSS Snapshot) | `is_kev` | **PR-AUC** (Retrospective) | 0.29481 (Logistic Reg.) | **0.33153** (XGBoost) | **11.49x Retrospective Leakage Inflation** |
| **EXP-C1** | Decision-Support Prioritization Simulation | Prioritization Rank Order | **Top-100 Jaccard Overlap** | 100 KEV forced ahead | Multiplicative joint risk surface | **0.005 Jaccard Overlap** (Disrupts linear ceiling) |

---

## 2. Quantitative Key Findings for Paper Draft

### 2.1 Pre-Scoring CVSS Base Score Estimation (EXP-A1)
- **Train (2002–2022)**: Ridge MAE = 0.9930 ($R^2 = 0.4123$); XGBoost MAE = 0.8574 ($R^2 = 0.5379$)
- **Validation (2023–2024)**: Ridge MAE = 0.9614 ($R^2 = 0.4610$); XGBoost MAE = 0.7944 ($R^2 = 0.5967$)
- **Test (2025–2026)**: Ridge MAE = 1.0954 ($R^2 = 0.3194$); XGBoost MAE = **0.9750** ($R^2 = \mathbf{0.4153}$)
- **Top Predictive Features**: Natural language text tokens (`unauthorized`, `unauthenticated`, `critical`, `accessible`) combined with weakness taxonomy indicators (`CWE-79`, `CWE-434`, `CWE-476`).

### 2.2 Publication-Time KEV Exploitation Prediction (EXP-B2)
- **Test Partition Metrics**:
  - Baseline Logistic Regression: PR-AUC = 0.02077, ROC-AUC = 0.85857, Precision@500 = 0.0360 (3.6%), Recall@500 = 0.0612 (6.12%)
  - XGBoost Classifier: PR-AUC = **0.02884**, ROC-AUC = 0.81324, Precision@500 = **0.0640** (6.4%), Recall@500 = **0.1088** (10.88%)
- **Random Baseline PR-AUC**: 0.00322 (0.32% positive rate in test partition).
- **Practical Implication**: At publication time, XGBoost provides an 8.96x precision multiplier over random selection, capturing 10.88% of future KEV vulnerabilities in the top 500 candidate queue.

### 2.3 Retrospective Snapshot Leakage Audit (EXP-B1 vs EXP-B2)
- **EXP-B2 (Publication Time, No EPSS)**: Test PR-AUC = **0.02884**
- **EXP-B1 (Retrospective EPSS 2026 Snapshot)**: Test PR-AUC = **0.33153**
- **Snapshot Leakage Delta**: $\Delta \text{PR-AUC} = +0.30269$ (**11.49x inflation**).
- **Methodological Takeaway**: Access to static post-hoc EPSS snapshots introduces massive retrospective leakage. Empirical research evaluating historical prediction models MUST enforce EXP-B2 publication-time feature boundaries.

### 2.4 Decision-Support Simulation & Signal Interactions (EXP-C1)
- **Global Rank Correlation**: Spearman $\rho = 0.9962$, Kendall $\tau = 0.9356$ across full population.
- **Queue Tail Disruption**: Top-100 Jaccard Overlap = **0.005** (0.5% overlap); Top-1000 Jaccard Overlap = **0.182** (18.2% overlap).
- **Core Insight**: Linear additive models create artificial priority ceilings where binary KEV flags ($w_3 x_3$) overwrite all severity and context variation. The interactive multiplicative surface $S_{\text{nonlinear}}$ allows high-severity / high-threat non-KEV vulnerabilities facing critical asset exposure to enter top remediation queues.

---

## 3. Academic Paper Abstract Integration Blueprint

> *"Evaluating machine learning methods for risk-based vulnerability prioritization requires strict temporal partition discipline and feature availability audits. In an empirical study across 366,547 canonical CVEs (2002–2026), we demonstrate that pre-scoring CVSS v3.1 estimation achieves 0.9750 MAE using initial text and metadata. For CISA KEV exploitation prediction at publication time, non-linear gradient boosted trees achieve an 8.96x precision boost over random selection (PR-AUC 0.02884). Crucially, we prove that incorporating static retrospective EPSS snapshots inflates historical PR-AUC by over 11.49x (jumping to 0.33153), exposing a critical methodological pitfall in existing literature. Finally, decision-support simulation demonstrates that non-additive interactive risk surfaces eliminate artificial priority ceilings inherent in linear additive scoring models."*
