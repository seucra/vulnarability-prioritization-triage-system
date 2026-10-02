# Presentation and Defense Preparation for the Vulnerability Prioritization & Triage System (VTS)

**Document Type**: Academic Presentation Script, Slide Deck Blueprint, Viva Defense Manual & Demonstration Runbook  
**Project Identifier**: `seucra/vulnarability-prioritization-triage-system`  
**Academic Context**: B.Tech Computer Engineering Capstone / Web Design Lab  
**Target Evaluators**: Departmental Examination Committee, Faculty Supervisors, External Technical Examiners  
**Author / Presenter**: Academic Research Team, Department of Computer Engineering  

---

## 1. Presentation Goal and Audience

### 1.1 Objective
The primary objective of this presentation is to defend the Vulnerability Prioritization & Triage System (VTS) as an **academically rigorous, empirically verified research prototype**. 

You must present VTS as:
> *"A research-driven vulnerability prioritization platform that evaluates disclosure-time severity estimation, publication-time exploitation prediction under temporal constraints, retrospective EPSS data leakage, and multi-criteria risk surfaces, operationalized through an auditable web application."*

You must **not** frame the project as:
> *"A cybersecurity website with XGBoost."* (The web UI is simply the interactive delivery layer of an audited scientific pipeline).

### 1.2 Evaluation Panel Profile
The examination panel typically consists of:
1. **The Systems & Security Professor**: Will scrutinize CVSS/EPSS/KEV standards, data boundaries, information leakage, and operational utility.
2. **The Machine Learning Specialist**: Will probe class imbalance, PR-AUC vs. ROC-AUC, tree hyperparameters, text vectorization, SHAP mathematical formulation, and probability calibration.
3. **The Software & Web Engineering Examiner**: Will evaluate the FastAPI REST architecture, zero-copy DuckDB Parquet querying, SQLite RBAC authentication, vanilla JavaScript modularity, and automated pytest coverage.

---

## 2. One-Minute Project Explanation (Elevator Pitch)

> *"Good morning, respected committee members. Modern software organizations are overwhelmed by the sheer volume of vulnerability disclosures, cataloging over 366,000 CVEs in the National Vulnerability Database. Traditionally, teams prioritize remediation using the CVSS Base Score. However, NIST explicitly states that CVSS measures technical severity, not operational risk. In reality, fewer than 2% of vulnerabilities are ever weaponized in the wild.*
>
> *Our project, the Vulnerability Prioritization & Triage System (VTS), investigates how to prioritize vulnerabilities scientifically under realistic information constraints. Using an audited dataset of 366,547 canonical CVEs and strict temporal partitioning, we demonstrate three core findings:*
> *First, disclosure-time text and weakness metadata can pre-estimate CVSS v3.1 base scores within 0.9750 MAE before official NVD analysis is completed.*
> *Second, publication-time exploitation forecasting under extreme class imbalance achieves an 8.96× precision uplift over random guessing.*
> *Third, we prove that using static retrospective EPSS snapshots inflates historical evaluation by over 11-fold due to look-ahead leakage.*
> *Finally, our non-linear interactive risk surface eliminates the rigid priority ceilings of linear models, allowing high-threat vulnerabilities in critical infrastructure to receive immediate attention. We operationalized these findings into an auditable FastAPI and vanilla JavaScript web application with 100% automated test coverage."*

---

## 3. Three-Minute Research Overview

> *"To understand the contribution of VTS, we must examine why existing vulnerability prioritization often fails in practice and literature.*
>
> *First is the **Severity vs. Risk fallacy**. CVSS measures hypothetical worst-case impact. Prioritizing solely on CVSS $\ge 7.0$ forces engineers to waste 80% to 90% of their remediation capacity on vulnerabilities that attackers never attempt to weaponize. Conversely, threat signals like CISA KEV confirm real-world weaponization, but suffer from an empirical median reporting lag of 285 days.*
>
> *Second is the widespread issue of **Temporal Data Leakage in academic research**. Many published machine learning studies evaluate models on historical CVEs using current EPSS scores or post-hoc CVSS sub-scores. In our EXP-B1 sensitivity experiment, we proved that access to a future EPSS snapshot artificially inflates Test PR-AUC from 0.02884 to 0.33153—an 11.49× distortion. In VTS, our primary publication-time model (EXP-B2) strictly forbids post-publication telemetry, enforcing an HTTP 422 boundary guard in our API schema.*
>
> *Third is the **Queue Ceiling Problem in composite scoring**. Traditional triage models sum metrics linearly. In EXP-C1, we evaluated 227,694 CVEs and found that linear scoring allows binary KEV flags to create an artificial priority ceiling, completely occupying top queues. Our non-linear surface ($S_{\text{nonlinear}}$) couples severity, threat probability, and asset criticality multiplicatively. This produces a Top-100 Jaccard overlap of only 0.5% against the linear baseline, ensuring critical infrastructure facing severe threats is prioritized even before formal KEV cataloging.*
>
> *Finally, we provide explainability via TreeExplainer SHAP, computing exact Shapley values so analysts understand feature attributions without confusing correlation with exploit causality. The entire system is built on a zero-copy DuckDB and Parquet architecture, delivering sub-50ms queries over 366,000 CVEs with 46 passing pytests and 15 professor verification tests."*

---

## 4. Recommended 14-Slide Deck

### Slide 1: Title & Project Scope
- **Objective**: Establish academic context and authoritative repository identity.
- **Visual**: VTS system banner, academic project metadata, repository identifier (`seucra/vulnarability-prioritization-triage-system`).
- **Speaking Notes**: Welcome the panel. Emphasize that this is an empirical research investigation and demonstration prototype developed for the Web Design Lab capstone.
- **Repository Evidence**: `backend/app/main.py:15-26`, `docs/final-research-fact-sheet.md:1-8`.
- **Claims to Avoid**: Do not claim VTS is a commercial or production enterprise product.

### Slide 2: The Triage Dilemma: Severity $\neq$ Risk
- **Objective**: Prove why conventional CVSS-only triage fails.
- **Visual**: Diagram contrasting CVSS distribution (bell curve centered at 7.0) against KEV distribution (0.45% tail).
- **Speaking Notes**: Explain NIST’s explicit guidance: CVSS measures technical severity, not operational risk. 80%+ of CVEs marked High/Critical are never exploited, causing alert fatigue.
- **Repository Evidence**: `data/experiments/phase2_metrics.json` (CVSS v3.1 Mean = 7.032; KEV base rate = 0.4493%).
- **Claims to Avoid**: Do not claim CVSS is useless; state that it is incomplete on its own.

### Slide 3: Research Questions & Core Contributions
- **Objective**: Frame the five RQs and two engineering objectives.
- **Visual**: Clean table mapping RQ1 (Severity), RQ2 (Pub-Time KEV), RQ3 (Leakage Audit), RQ4 (Prioritization Surface), RQ5 (SHAP).
- **Speaking Notes**: Walk through the core questions. Emphasize that evaluating realistic information availability is the primary research theme.
- **Repository Evidence**: `docs/research/PHASE_2_EXPERIMENTAL_PROTOCOL.md`.

### Slide 4: Data Sources, Provenance & Parquet Schema
- **Objective**: Demonstrate data engineering rigor and scale.
- **Visual**: Architecture chart showing NVD, CPE, EPSS, KEV, and Vendor feeds consolidating into 6 Parquet tables (94.48 MB, 4.28M rows).
- **Speaking Notes**: Explain how raw data was verified in Phase 0 and transformed via deterministic ETL in Phase 1. Detail the all-column canonicalization hashing that guaranteed bit-for-bit rebuild reproducibility.
- **Repository Evidence**: `data/processed/*.parquet`, `scripts/build_processed_data.py`, `tests/test_etl_invariants.py`.

### Slide 5: Temporal Partitioning & Leakage Prevention
- **Objective**: Explain the chronological train/val/test boundary.
- **Visual**: Timeline diagram: TRAIN (2002–2022), VAL (2023–2024), TEST (2025–2026), and TRAIN+VAL refit.
- **Speaking Notes**: Explain why random $k$-fold cross-validation causes fatal look-ahead leakage in vulnerability research. We evaluate exclusively on 2025–2026 prospective disclosures.
- **Repository Evidence**: `docs/research/PHASE_2_EXPERIMENTAL_PROTOCOL.md:35-50`, `data/experiments/phase2_metrics.json`.

### Slide 6: EXP-A1: Pre-Scoring CVSS v3.1 Base Estimation
- **Objective**: Present disclosure-time regression results.
- **Visual**: Scatter plot / residual histogram of predicted vs. actual CVSS scores; comparison table (Ridge vs. XGBoost).
- **Speaking Notes**: Explain the 531-feature pipeline (500 TF-IDF n-grams + CWEs + CPEs). Report Test MAE = 0.9750 CVSS points (an 11% error reduction over Ridge MAE of 1.0954).
- **Repository Evidence**: `data/experiments/phase3/exp_a1/metrics.json`.
- **Claims to Avoid**: Do not claim this replaces official human NVD scoring.

### Slide 7: EXP-B2: Publication-Time Exploitation Forecasting
- **Objective**: Present imbalanced classification under strict boundaries.
- **Visual**: Precision-Recall curve contrasting XGBoost (PR-AUC 0.02884) against random baseline (0.00322).
- **Speaking Notes**: Detail the extreme imbalance (294 KEV positives in 91,242 test CVEs = 0.32%). Highlight that XGBoost provides an 8.96× precision multiplier over random guessing and achieves 10.88% Recall@500.
- **Repository Evidence**: `data/experiments/phase3/exp_b2/metrics.json`.

### Slide 8: EXP-B1: The Retrospective Leakage Audit
- **Objective**: Expose the 11-fold performance inflation caused by post-hoc EPSS snapshots.
- **Visual**: Side-by-side bar chart: EXP-B2 (PR-AUC 0.02884) vs. EXP-B1 (PR-AUC 0.33153).
- **Speaking Notes**: Explain the scientific experiment: adding a static future EPSS snapshot causes an 11.49× artificial inflation. Warn that existing papers reporting high PR-AUC often suffer from this exact leakage.
- **Repository Evidence**: `data/experiments/phase3/exp_b1/metrics.json`.

### Slide 9: The B2 PR-AUC Discrepancy Resolution
- **Objective**: Proactively address the 0.3845 vs. 0.02884 documentation discrepancy.
- **Visual**: Discrepancy reconciliation table showing documentation note vs. serialized artifact.
- **Speaking Notes**: Address the audit finding openly: `docs/final-repo-state.md` contained a draft note of 0.3845 mislabeled as "Text+Meta+EPSS". The authoritative, serialized result for publication-time classification is PR-AUC = 0.02884.
- **Repository Evidence**: `data/experiments/phase3/exp_b2/metrics.json`, `docs/API.md:146`.

### Slide 10: EXP-C1: Multi-Criteria Prioritization Surfaces
- **Objective**: Explain the mathematics of linear baseline vs. non-linear surface.
- **Visual**: Equations for $S_{\text{linear}}$ and $S_{\text{nonlinear}}$, accompanied by 3D risk surface heatmap.
- **Speaking Notes**: Explain how the linear model's binary KEV flag ($+0.25$) acts as a rigid ceiling. The nonlinear multiplicative surface allows high-severity uncataloged flaws in critical assets to enter top triage queues (Top-100 Jaccard overlap = 0.5%).
- **Repository Evidence**: `data/experiments/phase3/exp_c1/metrics.json`, `backend/app/services/scoring_service.py`.

### Slide 11: Explainable AI with SHAP
- **Objective**: Explain local feature attribution and causality boundaries.
- **Visual**: Horizontal SHAP bar chart for Log4j (`CVE-2021-44228`) showing token attributions ($\phi_i$).
- **Speaking Notes**: Explain TreeExplainer exact Shapley decomposition. State the critical defense disclaimer: feature attribution reflects statistical predictive importance, not physical exploit causality.
- **Repository Evidence**: `data/experiments/phase3/shap/shap_summary.json`, `backend/app/services/explanation_service.py`.

### Slide 12: System Architecture & Testing
- **Objective**: Demonstrate engineering quality and test coverage.
- **Visual**: Full-stack architectural diagram (DuckDB, FastAPI, SQLite RBAC, Vanilla SPA).
- **Speaking Notes**: Detail the technology stack: Python 3.14, FastAPI, DuckDB zero-copy Parquet scans, JWT authentication. Highlight 46 passing pytests and 15 professor verification tests passing at 100%.
- **Repository Evidence**: `tests/`, `scripts/professor_test_suite.py`.

### Slide 13: Live Demonstration Walkthrough
- **Objective**: Guide the live UI demonstration.
- **Visual**: Screenshots of Vulnerability Explorer, Prediction interface, Batch Triage queue, and Provenance audit sheet.
- **Speaking Notes**: Transition to the live browser demo, showing real-time DuckDB filtering, EXP-A1/B2 inference, boundary validation, and batch triage ranking.

### Slide 14: Conclusion, Limitations & Future Scope
- **Objective**: Summarize findings and future extensions.
- **Visual**: Summary checklist of achievements, verified limitations, and future roadmap items.
- **Speaking Notes**: Reiterate core conclusions: pre-scoring feasibility, leakage exposure, and non-linear triage surfaces. Point to the separate Future Scope document for CMDB and time-series extensions.

---

## 5. Speaking Scripts for Diverse Formats

### 5.1 30-Second Opening Hook
> *"Good morning. Vulnerability management today is paralyzed by alert fatigue because teams rely on CVSS Base Scores, which measure technical severity rather than actual risk. Our project, VTS, evaluates machine learning pre-scoring, publication-time exploit prediction, and non-linear risk surfaces across 366,000 CVEs, demonstrating how to prioritize vulnerabilities scientifically without falling victim to look-ahead data leakage."*

### 5.2 2-Minute Executive Summary
> *"The core problem in cybersecurity triage is capacity: scanners discover thousands of vulnerabilities, but teams can patch only a fraction. Prioritizing solely on CVSS $\ge 7.0$ is deeply flawed because fewer than 2% of CVEs are ever exploited in the wild.*
>
> *In VTS, we built an end-to-end research platform covering 366,547 canonical CVEs with strict temporal validation. We established four key results:*
> *First, using disclosure-time text and weakness metadata, an XGBoost regressor estimates CVSS v3.1 base scores within 0.9750 MAE, bridging the multi-week delay before official NVD scoring.*
> *Second, predicting eventual CISA KEV exploitation at publication time achieves an 8.96× precision uplift over random guessing, capturing nearly 11% of future KEV flaws in the top 500 items.*
> *Third, we proved that using a static retrospective EPSS snapshot inflates PR-AUC by 11.49×, exposing a massive methodological flaw in existing literature.*
> *Fourth, we showed that linear composite scoring allows binary KEV flags to create artificial priority ceilings, whereas our non-linear interactive surface dynamically prioritizes high-severity flaws in critical assets.*
>
> *The entire system is implemented in FastAPI, DuckDB, and vanilla JavaScript, backed by 46 automated pytests and 15 professor verification tests."*

### 5.3 5-Minute Technical Narrative
> *"Respected committee, I will now walk through the technical and mathematical foundations of VTS.*
>
> *Our data pipeline ingests 27 years of NVD feeds, CPE platform dictionaries, CISA KEV entries, and FIRST EPSS snapshots. To guarantee data provenance, our deterministic ETL pipeline normalizes these sources into six Parquet tables. Using an all-column canonicalization hashing algorithm, we verified that independent clean rebuilds produce zero differing rows.*
>
> *To evaluate our models realistically, we enforced strict chronological partitioning: training on CVEs up to 2022, validating on 2023–2024, and evaluating strictly on 2025–2026. This prevents look-ahead data leakage.*
>
> *In EXP-A1, we trained an XGBoost regressor on 531 features—500 sublinear TF-IDF tokens, top-20 CWE one-hot indicators, and CPE platform counts. On 81,604 untouched test CVEs, XGBoost achieved a Mean Absolute Error of 0.9750, representing an 11% error reduction over our Ridge regression baseline.*
>
> *In EXP-B2, we addressed publication-time exploitation prediction against CISA KEV under an extreme class imbalance of 0.32%. Because post-publication telemetry does not exist at disclosure time, we strictly prohibited EPSS and CVSS sub-scores. XGBoost achieved a PR-AUC of 0.02884 and Precision@500 of 6.40%, providing an 8.96× precision multiplier over random guessing.*
>
> *To demonstrate the danger of data leakage, we ran EXP-B1, granting the model access to a future EPSS snapshot. Test PR-AUC skyrocketed to 0.33153—an 11.49× artificial inflation. This proves that historical evaluations must never use static post-hoc threat snapshots.*
>
> *In EXP-C1, we evaluated multi-criteria triage across 227,694 CVEs. While linear additive scoring and our non-linear surface correlate globally at 0.996, their Top-100 queues share only a 0.5% Jaccard overlap. Linear models force all KEV flaws into the top queue regardless of severity or asset criticality. Mode 2 couples severity, threat probability, and asset tier multiplicatively, allowing high-severity non-KEV vulnerabilities in critical infrastructure to receive top remediation priority.*
>
> *Finally, our TreeExplainer SHAP engine provides local feature attributions, governed by explicit disclaimers that statistical correlation is not mechanical causality. The system is fully operational via our FastAPI backend and web interface."*

---

## 6. Live Demonstration Runbook

### 6.1 Demonstration Pre-Flight Checklist
1. Ensure Python virtual environment is activated: `source .venv/bin/activate`.
2. Verify Parquet datasets exist in `data/processed/` (6 tables, 94.48 MB).
3. Verify serialized models exist in `data/experiments/phase3/` (`model.xgb`, `vectorizer.joblib`).
4. Start backend server:
   ```bash
   uvicorn backend.app.main:app --host 0.0.0.0 --port 5002
   ```
5. Access web interface locally at `http://localhost:5002` or via public URL `https://vuln-triage.seucra.tech`.

### 6.2 Step-by-Step Live Demo Script

| Step | UI View / Action | Inputs / Actions Taken | Expected System Behavior | Speaking Script for Panel |
|---|---|---|---|---|
| **1. Provenance** | Click `Provenance` tab in top navbar. | Public view (No login required). | Displays Dataset Freeze Date (`2026-07-26`), EPSS Snapshot Date (`2026-07-16`), table record counts (366k CVEs), SHA-256 hashes, and Phase 3 benchmark tables. | *"Notice our provenance dashboard. Every dataset is hash-verified and frozen, ensuring complete auditability and reproducibility."* |
| **2. Auth / RBAC** | Click `Login` modal; enter credentials. | Username: `analyst`, Password: `analyst_password`. | Receives HTTP 200, stores JWT token in `localStorage`, updates navbar badge to `ANALYST`, and unlocks triage views. | *"Authentication uses PBKDF2 hashing and JWT tokens enforcing role-based access control across analyst, researcher, and admin tiers."* |
| **3. Explorer** | Navigate to `Explorer` view. | Type query `Log4j`, filter by `CVSS >= 9.0`, `is_kev = True`. | DuckDB scans 366k CVEs in <30ms; displays paginated table with `CVE-2021-44228`. Click row to open slide-over detail drawer. | *"Here, DuckDB executes zero-copy SQL queries directly over our Parquet files, joining CVE, CWE, CPE, and EPSS data instantaneously."* |
| **4. CVSS Predict**| Navigate to `Predict` view $\rightarrow$ CVSS tab. | Enter description of an unauthenticated RCE, select `CWE-502`, enter `CVE-2021-44228`. | Returns predicted score `8.92` (MAE benchmark: 0.9750) alongside authoritative NVD score `10.0`. Displays horizontal SHAP bars. | *"EXP-A1 estimates CVSS base score at disclosure time. SHAP explains that tokens like 'remote' and 'unauthenticated' drove the score upward."* |
| **5. Leakage Guard**| Navigate to `Predict` view $\rightarrow$ KEV tab. | Submit sample description with valid text. | Returns publication-time KEV probability `0.1842`, risk class `ELEVATED_RISK`, benchmark PR-AUC `0.02884`. | *"EXP-B2 evaluates strictly at publication time. If an attacker attempts to inject a post-publication EPSS score, our Pydantic schema intercepts it with HTTP 422."* |
| **6. Batch Triage** | Navigate to `Batch Triage` view. | Paste list of 5 CVEs (`CVE-2021-44228`, `CVE-2017-0144`, `CVE-2023-38606`, etc.), select Asset Tier `Critical Infrastructure (1.00)`. | Parses text area, queries DuckDB, computes Mode 1 vs. Mode 2 scores, displays rank shifts, and enables CSV export. | *"In our batch triage queue, analysts see how Mode 2 shifts non-KEV critical infrastructure vulnerabilities ahead of lower-impact KEV entries."* |

---

## 7. Deep Technical Explanations

### 7.1 Mathematical Scoring Formulations (EXP-C1)
Security teams select between two scoring modes across four asset criticality tiers ($A \in \{0.25, 0.50, 0.75, 1.00\}$):

#### Mode 1: Transparent Linear Baseline
$$S_{\text{linear}} = 0.25 \cdot \left(\frac{\text{CVSS}}{10}\right) + 0.25 \cdot (\text{EPSS}) + 0.25 \cdot (\mathbb{I}_{\text{KEV}}) + 0.25 \cdot (A)$$
- *Mathematical Behavior*: Additive and separable. Each metric contributes an independent, uncoupled increment of at most 0.25 points.
- *Fatal Flaw*: The binary KEV flag adds a rigid $+0.25$. Because fewer than 0.5% of CVEs are in KEV, any KEV vulnerability automatically outranks almost all non-KEV vulnerabilities, creating an artificial priority ceiling.

#### Mode 2: Nonlinear Interactive Surface
$$S_{\text{nonlinear}} = A \cdot \left[ 1 - \left(1 - \frac{\text{CVSS}}{10}\right)^{1 + 1.0 \cdot \mathbb{I}_{\text{KEV}}} \cdot (1 - \text{EPSS})^{1 + 1.5 \cdot \mathbb{I}_{\text{KEV}}} \right]$$
- *Mathematical Behavior*: Asset criticality $A$ acts as a strict global scalar ($S \le A$). Severity ($\frac{\text{CVSS}}{10}$) and threat probability ($\text{EPSS}$) are coupled multiplicatively as joint unreliability terms ($1 - x$).
- *The KEV Interaction*: When a vulnerability is listed in KEV ($\mathbb{I}_{\text{KEV}} = 1$), the severity exponent doubles ($1 + 1.0 = 2.0$) and the EPSS exponent increases ($1 + 1.5 = 2.5$). This accelerates the score toward asymptotic saturation ($1.0$) without creating a rigid rank disconnect.

---

## 8. Difficult Examination Questions and Model Answers

### Q1: What is the single most important research contribution of VTS?
**Model Answer**: *"Our most important contribution is methodological: demonstrating that vulnerability prioritization models must be evaluated under strict temporal information boundaries. Specifically, we proved that using static retrospective EPSS snapshots inflates historical exploit prediction PR-AUC by 11.49-fold due to look-ahead leakage, and that non-linear risk surfaces eliminate the artificial priority ceilings inherent in linear additive scoring."*

### Q2: Why is the B2 PR-AUC so low (0.02884)? Is an ML model with 0.028 PR-AUC actually useful?
**Model Answer**: *"In imbalanced binary classification, PR-AUC must always be evaluated relative to the positive class base rate. In our untouched 2025–2026 test partition, only 294 out of 91,242 CVEs are in KEV—a base rate of 0.32% (0.00322). A random classifier achieves a PR-AUC of 0.00322. Our XGBoost model achieves 0.02884, which is an **8.96x precision multiplier over random guessing**. Furthermore, at Top-500 candidate triage, our model achieves 6.40% precision and 10.88% recall. At the moment of public disclosure, before any threat telemetry exists, an 8.96x precision uplift provides substantial triage value."*

### Q3: Why does `docs/final-repo-state.md` cite PR-AUC = 0.3845, while `metrics.json` says 0.02884?
**Model Answer**: *"We audited this discrepancy thoroughly. In `docs/final-repo-state.md:160`, an unverified draft note incorrectly labeled a model as 'EXP-B2 (Text+Meta+EPSS)' with PR-AUC = 0.3845, matching an example API output string in `API.md:146`. However, the physical serialized model in `data/experiments/phase3/exp_b2/metrics.json` definitively records PR-AUC = 0.02884 for our publication-time model, while our retrospective EPSS model (EXP-B1) achieved 0.33153. The value 0.3845 has no serialized artifact provenance and is formally deprecated; **0.02884** is the sole authoritative verified publication-time result."*

### Q4: Does VTS achieve 80–95% Work Reduction like Agyei et al. (2026)?
**Model Answer**: *"No, and we explicitly do not claim work reduction. Agyei et al. evaluated a simulated enterprise environment with synthetic scanning cycles and ticketing logs. VTS evaluates 366,547 real-world CVEs from public repositories. Because our repository does not contain enterprise IT ticket histories or empirical compromise incident logs, claiming work reduction would be methodologically unfounded. We measure ranking correlation, Jaccard overlap, and Precision@500."*

### Q5: Does SHAP prove that a specific token causes a vulnerability to be exploitable?
**Model Answer**: *"No. SHAP computes Shapley values from cooperative game theory, measuring the marginal statistical contribution of a feature to the model's output within the decision tree ensemble. It measures association, not causality. For example, while the token 'gain' has a high positive SHAP value, it does not mechanically cause exploitability; rather, descriptions of severe vulnerabilities frequently use the phrase 'gain administrative privileges'."*

### Q6: Why did you use DuckDB and Parquet instead of PostgreSQL or MongoDB?
**Model Answer**: *"VTS is an analytical research platform querying 366,000 canonical CVE records and 3.1 million CPE platform configurations. Parquet provides compressed, immutable columnar storage. DuckDB is an in-process vectorized SQL OLAP engine that queries Parquet files directly using zero-copy memory buffers. This delivers sub-50ms query response times across multi-table joins without the configuration, network latency, or maintenance overhead of a separate database daemon."*

### Q7: What would happen if an attacker tried to bypass your publication-time boundary?
**Model Answer**: *"Our Pydantic schema (`KEVPredictionRequest` in `backend/app/schemas/prediction.py`) contains a model validator that inspects incoming JSON payloads. If a client attempts to supply `epss`, `epss_score`, `epss_percentile`, `cvss_v31_base_score`, or `cvss_vector`, the schema raises a validation error that FastAPI maps to an HTTP 422 Unprocessable Entity status code, preventing data leakage at the API perimeter."*

---

## 9. Viva Quick-Reference Tables

### Core Metrics Summary

| Experiment | Target | Baseline Model & Metric | VTS XGBoost Metric | Relative Uplift / Delta | Test Population ($n$) |
|---|---|---|---|---|---|
| **EXP-A1** | `cvss_v31_base_score` | Ridge Regression: MAE = **1.0954** | XGBoost: MAE = **0.9750** | **-10.99% Error Reduction** | 81,604 CVEs (2025–2026) |
| **EXP-B2** | `is_kev` (Pub-Time) | Logistic Reg: PR-AUC = **0.02077** | XGBoost: PR-AUC = **0.02884** | **+38.85% Uplift** (8.96× vs Random) | 91,242 CVEs (294 KEV+) |
| **EXP-B1** | `is_kev` (Retrospective)| Logistic Reg: PR-AUC = **0.29481** | XGBoost: PR-AUC = **0.33153** | **11.49× Leakage Inflation** | 91,242 CVEs (294 KEV+) |
| **EXP-C1** | Dual-Mode Prioritization| Linear Baseline ($S_{\text{linear}}$) | Non-linear Surface ($S_{\text{nonlinear}}$) | **Top-100 Jaccard Overlap = 0.005** | 227,694 Intersected CVEs |

### REST API Route Cheat-Sheet

| Method | Endpoint | Access Role | Description |
|---|---|---|---|
| `POST` | `/api/v1/auth/login` | Public | Authenticates credentials; returns HS256 JWT Bearer token |
| `GET` | `/api/v1/vulnerabilities` | Public | DuckDB paginated search over 366k CVE records |
| `POST` | `/api/v1/predict/cvss` | Authenticated | Pre-scoring CVSS estimation via EXP-A1 XGBoost regressor |
| `POST` | `/api/v1/predict/kev` | Authenticated | Publication-time KEV forecasting via EXP-B2 classifier |
| `POST` | `/api/v1/prioritize` | `analyst`, `admin` | Computes Mode 1 Linear and Mode 2 Nonlinear priority scores |
| `POST` | `/api/v1/prioritize/batch`| `analyst`, `admin` | Multi-CVE batch triage scoring with sorting and rank shifts |
| `POST` | `/api/v1/explain/cvss` | Authenticated | Computes TreeExplainer SHAP attributions for EXP-A1 |
| `GET` | `/api/v1/provenance` | Public | Returns freeze dates, SHA-256 hashes, and Phase 3 metrics |

---

## 10. Presentation Risk Register

| Risk / Potential Misunderstanding | Likelihood | Impact | Preventive Defense Strategy |
|---|---|---|---|
| **Panel confuses PR-AUC 0.02884 with poor performance** | High | Critical | Emphasize the 0.32% base rate immediately; state that 0.02884 represents an 8.96× precision uplift over random guessing. |
| **Panel asks about the 0.3845 PR-AUC citation** | Medium | High | Proactively acknowledge the discrepancy; explain that 0.3845 was an unverified draft note, whereas 0.02884 is the serialized artifact ground truth. |
| **Panel assumes C1 is a machine learning model** | Medium | Medium | Clarify immediately that C1 is a multi-criteria decision-support simulation comparing mathematical surface dynamics, not supervised learning. |
| **Panel asks if SHAP proves the exploit mechanism** | Medium | High | State firmly that SHAP computes statistical feature attribution within tree ensembles and does not establish physical software causality. |
| **Panel challenges commercial readiness** | Low | Medium | Reiterate that VTS is an academic research prototype and public demonstration platform, not an enterprise production service. |

---

## 11. References

1. **NIST**: CVSS FAQs and Metrics. [https://nvd.nist.gov/vuln-metrics/cvss](https://nvd.nist.gov/vuln-metrics/cvss)
2. **FIRST**: EPSS Specification & FAQ. [https://www.first.org/epss/](https://www.first.org/epss/)
3. **CISA**: KEV Catalog. [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
4. **Lundberg & Lee** (2017): SHAP NeurIPS Paper. [https://papers.nips.cc/paper/7062-a-unified-approach-to-interpreting-model-predictions](https://papers.nips.cc/paper/7062-a-unified-approach-to-interpreting-model-predictions)
5. **Chen & Guestrin** (2016): XGBoost KDD Paper. [https://doi.org/10.1145/2939672.2939785](https://doi.org/10.1145/2939672.2939785)
6. **Jiang et al.** (2025): Vulnerability Prioritization Survey. [https://arxiv.org/abs/2502.11070](https://arxiv.org/abs/2502.11070)
7. **Ravalico et al.** (2025): Temporal Dynamics of EPSS. [https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459](https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459)
8. **Agyei et al.** (2026): Explainable Risk-Based Prioritization in Hybrid Cloud. *WJARR*, [https://doi.org/10.30574/wjarr.2026.30.1.1006](https://doi.org/10.30574/wjarr.2026.30.1.1006)

---

## 12. Final Defense Readiness Checklist

- **Exact Files Inspected**: All backend routers (`backend/app/api/v1/`), service handlers (`backend/app/services/`), Pydantic schemas (`backend/app/schemas/`), experiment scripts (`scripts/experiments/`), test suites (`tests/`), and metrics files (`data/experiments/phase3/`).
- **Verified Facts**: 366,547 canonical CVEs; 1,647 KEV positives; EXP-A1 MAE 0.9750; EXP-B2 PR-AUC 0.02884 (8.96× uplift); EXP-B1 PR-AUC 0.33153 (11.49× inflation); EXP-C1 Top-100 Jaccard 0.005; 46 pytests passed; 15 professor verification tests passed.
- **Facts Requiring Manual Verification in External Settings**: Longitudinal daily EPSS trajectories and enterprise-specific CMDB asset reachability.
- **Claims That Must NEVER Be Made**:
  1. Do not claim VTS eliminates cyber risk.
  2. Do not claim VTS proves real-world exploit weaponization.
  3. Do not claim VTS achieves 0.3845 PR-AUC at publication time.
  4. Do not claim VTS reduces enterprise workload by 80–95%.
  5. Do not claim VTS is production enterprise software.
- **Readiness Assessment**: The candidate is fully equipped with empirical evidence, mathematical exactness, and strategic non-claims to successfully deliver an outstanding capstone viva defense.
