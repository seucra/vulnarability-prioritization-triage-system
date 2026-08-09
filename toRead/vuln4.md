# Deliverable 4/4 — Formal Presentation & Viva Preparation Document

## Vulnerability Prioritization & Triage System

This is the **presentation-facing document**. It is intentionally different from the deep-learning document: the goal is to give you a clean, defensible way to present the project to a strict professor who cares about terminology, methodology, research grounding, and exact distinctions.

---

# 1. Project Title

**Vulnerability Prioritization and Triage System Using Machine Learning and Nonlinear Risk Modeling**

Repository:

`seucra/vulnarability-prioritization-triage-system`

---

# 2. Opening — What Is the Project?

### Recommended answer

> The project is a research-oriented vulnerability prioritization and triage system that investigates the use of machine learning and nonlinear risk modeling to support vulnerability assessment. It integrates vulnerability information from NVD, CISA KEV, EPSS, CWE and CPE data, evaluates temporally separated machine-learning models, and exposes the resulting research capabilities through a FastAPI backend and web interface.

Then immediately establish the important distinction:

> The system is intended as a decision-support prototype. It does not claim to replace authoritative CVSS scoring, CISA's KEV determination, or human security analysts.

That prevents overclaiming from the beginning.

---

# 3. Why This Problem?

### Recommended answer

> Traditional vulnerability prioritization can rely heavily on severity measures such as CVSS. However, severity alone does not necessarily represent the operational priority of a vulnerability. Exploitation likelihood, known exploitation, and asset criticality can change the practical risk associated with a vulnerability. Therefore, this project investigates whether machine learning and contextual nonlinear prioritization can provide additional decision-support information.

---

# 4. What Are the Main Components?

Draw this:

```text
                 Vulnerability Data
                        │
        ┌───────────────┼────────────────┐
        │               │                │
       NVD             KEV              EPSS
        │               │                │
        └───────────────┼────────────────┘
                        │
                  Deterministic ETL
                        │
                Frozen Parquet Data
                        │
          ┌─────────────┼─────────────┐
          │             │             │
         A1            B2            C1
          │             │             │
       CVSS ML        KEV ML       Risk Model
          │             │             │
          └─────────────┼─────────────┘
                        │
                       SHAP
                        │
                     FastAPI
                        │
                    Frontend
```

### Explain it as:

> The project consists of four major research components: A1 for CVSS estimation, B2 for publication-time KEV prediction, B1 as a retrospective EPSS sensitivity experiment, and C1 for linear versus nonlinear prioritization. These research artifacts are subsequently exposed through the application backend and frontend.

---

# 5. Data Sources

The project works with:

| Source            | Purpose                               |
| ----------------- | ------------------------------------- |
| NVD               | Vulnerability/CVE information         |
| CWE               | Weakness taxonomy                     |
| CPE               | Affected platform/product information |
| CISA KEV          | Known exploited vulnerability target  |
| EPSS              | Exploitation prediction signal        |
| Vendor statements | Additional vulnerability context      |

The processed dataset contains approximately:

* **366,547 canonical CVEs**
* **1,647 KEV records**
* **348,900 EPSS records**

Use the term **canonical dataset**, not merely "database."

---

# 6. Why Was the Data Processed?

### Answer

> The raw sources have different structures and representations. A deterministic ETL pipeline was therefore created to normalize and combine the sources into consistent analytical datasets. The resulting Parquet files were then frozen so that subsequent experiments and application components operated on a reproducible dataset.

---

# 7. Why Freeze the Dataset?

### Answer

> Dataset freezing prevents subsequent application development or data updates from silently changing the experimental inputs. It allows the reported results to be reproduced against the exact dataset used during experimentation.

If asked how reproducibility was verified:

> Independent clean rebuilds were compared using schema checks, null-count checks, logical row comparisons, and canonical SHA-256 fingerprints. All six processed tables produced zero logical row differences.

---

# 8. Temporal Experimental Design

This is one of your strongest presentation points.

Draw:

```text
2002 ─────────────── 2022 | 2023 ───── 2024 | 2025 ───────── 2026
        TRAIN                VALIDATION             TEST
```

### Exact answer

> A fixed temporal split was used: 2002–2022 for training, 2023–2024 for validation, and 2025–2026 for testing. Model selection and hyperparameter tuning were performed using training and validation data, after which the final configuration was frozen, refit on the combined training and validation period, and evaluated on the untouched test period.

---

# 9. Why Not Randomly Split the Dataset?

### Answer

> Random splitting can allow information from later publication periods to appear in the training data while evaluating earlier observations. This does not represent the chronological direction of a real prediction task. A temporal split therefore provides a more realistic evaluation of generalization to future vulnerabilities.

---

# 10. What Is Data Leakage?

### Exact concept

> Data leakage occurs when information that would not legitimately be available at the prediction point is used during model development or prediction.

Then give the project's strongest example:

```text
CVE published in 2021
        ↓
2026 EPSS snapshot
        ↓
historical prediction
```

> Using the 2026 EPSS snapshot to make a 2021 publication-time prediction introduces future information into the prediction.

---

# 11. A1 — CVSS Estimation

### Research question

> Can pre-scoring vulnerability information be used to estimate the CVSS v3.1 base score?

### Target

```text
cvss_v31_base_score
```

### Task type

**Regression**

Because CVSS base score is continuous.

### Models

```text
Ridge Regression
        vs
XGBoost Regressor
```

---

# 12. Why Ridge?

### Answer

> Ridge Regression provides a regularized linear baseline. It establishes how well the problem can be addressed using a relatively simple linear relationship before introducing a nonlinear model.

---

# 13. Why XGBoost?

### Answer

> XGBoost was selected as the nonlinear model because gradient-boosted decision trees can represent nonlinear relationships and feature interactions that a linear model cannot directly represent.

Do not say:

> "XGBoost is the best algorithm."

The experiment does not establish that.

---

# 14. A1 Results

| Model   |   Test MAE |  Test RMSE |    Test R² |
| ------- | ---------: | ---------: | ---------: |
| Ridge   |     1.0954 |     1.4089 |     0.3194 |
| XGBoost | **0.9750** | **1.3059** | **0.4153** |

### Interpretation

> XGBoost reduced test MAE by 0.1204 CVSS points, corresponding to a 10.99% relative error reduction compared with the Ridge baseline.

---

# 15. What Does MAE = 0.9750 Mean?

### Answer

> MAE is the mean absolute difference between the predicted and actual values. An MAE of 0.9750 means the average absolute prediction error over the evaluated test observations was approximately 0.975 CVSS points.

Then explicitly:

> It does not mean that every prediction has an error below 0.975.

---

# 16. B2 — KEV Prediction

### Research question

> Can publication-time vulnerability information predict future KEV catalog inclusion?

### Target

```text
is_kev
```

### Task

**Binary classification**

### Models

```text
Logistic Regression
        vs
XGBoost Classifier
```

---

# 17. Why Is This a Difficult Classification Problem?

KEV positives are rare.

The test partition contains:

```text
294 KEV positives
91,242 total CVEs
```

approximately:

```text
0.32% positive rate
```

Therefore a model predicting "not KEV" almost everywhere can achieve high accuracy without being useful.

---

# 18. Why PR-AUC?

### Answer

> Because the KEV target is highly imbalanced, accuracy can be misleading. Precision-Recall analysis focuses directly on the model's ability to identify the minority positive class, which is more relevant to candidate prioritization.

---

# 19. B2 Results

| Model               |      PR-AUC | ROC-AUC | Precision@500 | Recall@500 |
| ------------------- | ----------: | ------: | ------------: | ---------: |
| Logistic Regression |     0.02077 | 0.85857 |         3.60% |          — |
| XGBoost             | **0.02884** | 0.81324 |     **6.40%** | **10.88%** |

Random PR-AUC baseline:

```text
0.00322
```

### Interpretation

> XGBoost achieved a PR-AUC of 0.02884 and a Precision@500 of 6.4%. Relative to the random positive-rate baseline, its Precision@500 corresponds to approximately an 8.96-fold enrichment.

Be careful:

**8.96× does not mean 89.6% accuracy.**

---

# 20. Why Is ROC-AUC Lower for XGBoost?

This is a likely question.

The result is:

```text
Logistic ROC-AUC = 0.85857
XGBoost ROC-AUC  = 0.81324
```

while:

```text
Logistic PR-AUC = 0.02077
XGBoost PR-AUC  = 0.02884
```

### Answer

> ROC-AUC and PR-AUC measure different aspects of ranking performance. The project uses PR-AUC as the primary metric because of the extreme class imbalance. Therefore the primary comparison should be based on PR-AUC rather than interpreting the higher ROC-AUC of Logistic Regression as evidence that it is the better model for the intended triage task.

---

# 21. B1 — Why Did We Run It?

B1 is not the primary deployment model.

It is a **retrospective sensitivity analysis**.

It includes:

```text
2026-07-16 EPSS snapshot
```

and compares the resulting performance with B2.

---

# 22. B1 vs B2

```text
B2:
No retrospective EPSS
PR-AUC = 0.02884

B1:
2026 EPSS snapshot
PR-AUC = 0.33153
```

Difference:

```text
+0.30269 PR-AUC
```

or approximately:

```text
11.49×
```

the B2 PR-AUC.

### Main conclusion

> The large performance increase demonstrates that retrospective snapshot access can substantially inflate historical predictive performance.

This is one of the most defensible findings in the project.

---

# 23. Why Isn't B1 Used in the Application's Primary Prediction?

### Answer

> Because B1 uses retrospective information. The application therefore exposes the EPSS snapshot as a current static data reference, while the primary B2 prediction endpoint enforces publication-time feature boundaries and rejects EPSS inputs.

---

# 24. C1 — Prioritization

C1 addresses a different problem.

A1 asks:

> What is the CVSS score?

B2 asks:

> How likely is future KEV inclusion?

C1 asks:

> How should multiple signals be combined for prioritization under controlled asset context?

---

# 25. Linear Baseline

[
S_{linear}
==========

0.25x_1+
0.25x_2+
0.25x_3+
0.25x_4
]

where the factors represent the normalized project inputs.

### Important wording

> This is a **project-controlled equal-weights baseline**, not a claim that these weights are universally optimal.

---

# 26. Nonlinear Surface

[
S_{nonlinear}
=============

x_4
\left[
1-(1-x_1)^{1+x_3}
(1-x_2)^{1+1.5x_3}
\right]
]

Parameters:

[
\alpha=1.0,\qquad\beta=1.5
]

The point is to allow the influence of the signals to interact rather than simply add independently.

---

# 27. Why Asset Criticality?

Because:

> The operational priority of a vulnerability depends not only on characteristics of the vulnerability but also on the importance of the asset affected by it.

Controlled tiers:

| Tier              | Criticality |
| ----------------- | ----------: |
| Tier 1 — Low      |        0.25 |
| Tier 2 — Medium   |        0.50 |
| Tier 3 — High     |        0.75 |
| Tier 4 — Critical |        1.00 |

### Important qualification

> These are controlled experimental inputs and are not observed enterprise ground truth.

---

# 28. C1 Results

```text
Spearman ρ = 0.9962
Kendall τ = 0.9356
```

Yet:

```text
Top-100 Jaccard = 0.005
Top-1000 Jaccard = 0.182
```

### Interpretation

> The two approaches maintain strong overall rank correlation while producing substantially different high-priority candidate sets.

This demonstrates why global correlation alone is insufficient when the practical use case is top-K vulnerability triage.

---

# 29. Why Is Top-100 Important?

An analyst may not have the capacity to investigate hundreds of thousands of vulnerabilities.

They may need:

```text
Top 10
Top 100
Top 500
```

Therefore:

> Differences at the top of the ranking can be operationally significant even when global rankings remain highly correlated.

---

# 30. SHAP

### Answer

> SHAP is used as a post-hoc feature attribution method to examine how individual features contribute to the predictions of the frozen tree models.

### Important limitation

> SHAP explains model behavior; it does not establish causal relationships in the real world.

---

# 31. Why Was the Dataset Not Modified During Application Development?

### Answer

> The application operates against the frozen processed datasets. This separates research data from application behavior and ensures that adding or modifying API/UI functionality cannot silently alter the experimental dataset.

---

# 32. Backend Architecture

Show:

```text
                    FastAPI
                       │
            ┌──────────┼──────────┐
            │          │          │
       Vulnerability Inference  Scoring
         Service      Service    Service
            │          │          │
         DuckDB      Models     Equations
            │          │          │
            └──────────┼──────────┘
                       │
                 Explanation
                    Service
                       │
                     SHAP
```

Supporting services include:

* configuration
* database/query layer
* provenance
* schemas
* exception handling

---

# 33. Main API Endpoints

### Vulnerabilities

```text
GET /api/v1/vulnerabilities
GET /api/v1/vulnerabilities/{cve_id}
```

### Predictions

```text
POST /api/v1/predict/cvss
POST /api/v1/predict/kev
```

### Prioritization

```text
POST /api/v1/prioritize
```

### Explainability

```text
POST /api/v1/explain
```

### Provenance

```text
GET /api/v1/provenance
```

---

# 34. Why Does B2 Reject EPSS at the API Level?

This is an important architecture/research connection.

Bad architecture:

```text
documentation:
"Please don't send EPSS."
```

Better:

```text
request
 ↓
validation
 ↓
EPSS present?
 ↓
YES → reject
```

### Answer

> The methodological rule is enforced at the backend boundary rather than relying only on frontend behavior. This prevents a client from bypassing the intended publication-time feature restriction.

---

# 35. Why Is There No Login System?

### Answer

> Authentication was explicitly excluded from the current academic prototype. The project focuses on the vulnerability prioritization methodology, experimental validation, and research-backed application architecture.

Do not start discussing passwords or OAuth unless asked.

---

# 36. Frontend

The frontend provides five major research-facing workspaces:

```text
1. Vulnerability Explorer
2. Predictive Analysis
3. Prioritization
4. Explainability
5. Research Provenance
```

The UI is deliberately not the research contribution.

### Good answer if asked:

> The frontend is an application layer for interacting with the validated backend capabilities. The research contribution resides primarily in the data methodology, temporal experimental design, models, prioritization formulation, and empirical results.

---

# 37. What Has Actually Been Proven?

Be precise.

### Supported by the experiments:

* Pre-scoring information contains predictive signal for CVSS estimation.
* XGBoost outperformed Ridge on A1's test metrics.
* Publication-time information contains measurable signal for KEV prediction.
* XGBoost achieved higher B2 PR-AUC than Logistic Regression.
* Retrospective EPSS access dramatically changes historical predictive performance.
* Linear and nonlinear prioritization can produce very different top-K queues.
* The entire research pipeline can be reproduced against the frozen dataset.

---

# 38. What Has NOT Been Proven?

This is equally important.

The project has **not** proven that:

* XGBoost is universally superior to all other ML algorithms.
* The nonlinear C1 equation is universally better than linear scoring.
* the system predicts actual exploitation perfectly.
* the system improves real-world remediation outcomes.
* the synthetic asset tiers represent real enterprise risk.
* SHAP explanations represent causality.
* the model should replace CVSS.
* the system should replace human security analysts.
* the system is production-ready for unrestricted enterprise deployment.

---

# 39. Major Limitations

If asked:

> "What are the limitations?"

Give these.

### 1. KEV as target

KEV membership is an operational proxy, not a complete ground truth for exploitation.

### 2. Synthetic asset criticality

C1 does not use real enterprise asset data.

### 3. No remediation ground truth

The project does not yet evaluate whether its rankings improve actual remediation decisions.

### 4. Temporal dataset boundary

Results are based on the available 2002–2026 dataset snapshot.

### 5. Retrospective EPSS

The available EPSS snapshot is not suitable as a historical publication-time feature.

### 6. Model limitations

ML predictions are imperfect and subject to distribution shift.

### 7. Explainability

SHAP provides model attribution, not causal explanation.

---

# 40. Future Work

Keep this concise in a presentation.

> Future work includes time-aligned EPSS evaluation, rolling temporal validation, improved exploitation ground truth, real enterprise asset context, remediation outcome data, probability calibration, uncertainty estimation, learning-to-rank approaches, analyst evaluation, and continuous versioned data/model pipelines.

---

# 41. Likely Professor Questions

## Q: What is the novelty?

### Answer

> The project combines temporally disciplined vulnerability prediction with an explicit retrospective leakage audit and a controlled comparison between linear and nonlinear context-aware prioritization. The emphasis is not simply on applying an ML algorithm, but on evaluating whether the methodology remains valid under realistic information-availability constraints.

---

## Q: Why did you choose XGBoost?

> XGBoost was selected as the nonlinear tree-based model because it can capture nonlinear relationships and feature interactions, while Ridge and Logistic Regression provide comparatively simple linear baselines.

---

## Q: Why not neural networks?

> The project does not claim that XGBoost is universally optimal. The selected models provide a controlled comparison between linear baselines and nonlinear tree-based models while keeping the experimental scope manageable and interpretable.

---

## Q: Why is your PR-AUC so low?

> The KEV target is extremely imbalanced, with approximately 0.32% positives in the test partition. Therefore absolute PR-AUC values are necessarily influenced by the low base rate. The comparison against the random baseline and the top-K metrics provide more meaningful context.

---

## Q: Why is ROC-AUC high but PR-AUC low?

> ROC-AUC evaluates ranking across positive and negative examples over false-positive rates, while PR-AUC is strongly affected by the positive class prevalence. Under extreme class imbalance, a model can have a relatively high ROC-AUC while still producing low precision among the positive predictions.

---

## Q: Why did EPSS cause such a huge improvement?

> Because the B1 experiment uses a later static EPSS snapshot containing information that was unavailable at many historical prediction points. The result therefore demonstrates retrospective information leakage rather than legitimate historical predictive performance.

---

## Q: So why include EPSS at all?

> EPSS remains useful as a current threat-intelligence signal. The methodological issue is not that EPSS is inherently invalid; the issue is using a future snapshot to evaluate a historical prediction.

---

## Q: Why not just use the linear formula?

> The linear formula is intentionally retained as the transparent baseline. C1 investigates whether contextual interactions can produce materially different prioritization behavior. The nonlinear formulation is therefore an experimental decision surface, not presented as universally optimal.

---

## Q: Where did your nonlinear weights come from?

> The nonlinear surface uses fixed project-controlled parameters α = 1.0 and β = 1.5. They are part of the controlled experimental formulation and should not be represented as empirically learned universal constants.

---

## Q: Is C1 machine learning?

> No. C1 is a controlled decision-support simulation comparing a project-controlled linear baseline with a nonlinear mathematical surface. It is intentionally separated from the supervised prediction experiments.

---

## Q: Why use synthetic asset tiers?

> Real enterprise asset criticality data were unavailable. Controlled tiers allow the interaction between vulnerability/threat signals and asset criticality to be studied without fabricating enterprise ground truth.

---

## Q: Why SHAP after model freezing?

> Performing explanation after final model selection avoids using the explanation process as an implicit model-selection mechanism and preserves the separation between model development and post-hoc interpretation.

---

## Q: Can SHAP tell us why a vulnerability is actually dangerous?

> No. SHAP tells us which features influenced the model's prediction. It does not establish that those features causally determine real-world exploitation or risk.

---

## Q: Why Parquet?

> The processed vulnerability data are analytical and largely immutable. Parquet provides efficient columnar storage and works well with analytical query engines such as DuckDB.

---

## Q: Why DuckDB?

> DuckDB allows analytical SQL queries directly over the frozen Parquet datasets without requiring a mutable relational database for the research prototype.

---

## Q: Why FastAPI?

> FastAPI provides a typed Python REST API suitable for exposing the Python-based ML and analytical services while providing request validation and automatic API documentation.

---

## Q: Why build the frontend after the ML?

> Because the frontend should represent validated research capabilities. Building the interface first could cause the research design to be driven by UI assumptions rather than the experimental methodology.

---

# 42. If She Asks You to Explain the Entire Project in 60 Seconds

Use this:

> The project is a research-oriented vulnerability prioritization and triage system. We first collected and deterministically processed NVD, CWE, CPE, KEV, EPSS and vendor data into a frozen canonical dataset. We then used a temporal split of 2002–2022 for training, 2023–2024 for validation, and 2025–2026 for testing. Experiment A1 evaluates pre-scoring CVSS estimation using Ridge and XGBoost regression, while B2 evaluates publication-time KEV prediction using Logistic Regression and XGBoost classification. A separate B1 experiment demonstrates the severe performance inflation caused by using a retrospective EPSS snapshot. C1 then compares a transparent equal-weight linear prioritization baseline with a nonlinear interaction surface under controlled asset criticality tiers. Finally, SHAP provides post-hoc model explanations, and the validated capabilities are exposed through a FastAPI backend and web interface.

---

# 43. If She Asks "What Is Your Main Finding?"

Use:

> The main methodological finding is that vulnerability prediction must respect temporal feature availability. The B1 versus B2 comparison shows that retrospective EPSS information can inflate historical predictive performance dramatically, with XGBoost PR-AUC increasing from 0.02884 without retrospective EPSS to 0.33153 when the 2026 snapshot is included. This demonstrates why publication-time feature boundaries are essential for valid historical evaluation.

---

# 44. If She Asks "What Is Your Contribution?"

Use:

> The project contributes a reproducible vulnerability-prioritization research pipeline combining deterministic data preparation, temporal evaluation, publication-time exploitation prediction, retrospective leakage analysis, nonlinear contextual prioritization, post-hoc explainability, and an application layer exposing these research capabilities.

---

# 45. Presentation Order

For the actual presentation, use this order:

```text
1. Problem
      ↓
2. Motivation
      ↓
3. Research objectives
      ↓
4. Data sources
      ↓
5. System architecture
      ↓
6. Dataset preparation
      ↓
7. Temporal methodology
      ↓
8. EXP-A1
      ↓
9. EXP-B2
      ↓
10. EXP-B1 leakage experiment
      ↓
11. EXP-C1
      ↓
12. SHAP
      ↓
13. Application architecture
      ↓
14. Demonstration
      ↓
15. Results
      ↓
16. Limitations
      ↓
17. Future scope
      ↓
18. Conclusion
```

Do **not** begin with the UI.

Begin with the research problem.

---

# 46. What to Demonstrate

The live demonstration should be short.

### Demo 1 — Explorer

Search for a CVE and open its details.

Show:

* authoritative CVSS
* CWE
* CPE
* KEV
* EPSS snapshot

### Demo 2 — A1

Enter a vulnerability description.

Show:

```text
Predicted CVSS v3.1
```

Explicitly distinguish it from the authoritative score.

### Demo 3 — B2

Run publication-time KEV prediction.

Then, if useful, demonstrate that prohibited post-publication information is rejected.

This is a **very good methodological demonstration**.

### Demo 4 — C1

Change:

```text
Tier 1 → Tier 4
```

and show how prioritization changes.

### Demo 5 — SHAP / Provenance

Show feature attribution and dataset/model provenance.

Do not spend excessive time here.

---

# 47. Words to Avoid

Because the professor is strict about terminology, avoid casual claims such as:

| Avoid                                   | Prefer                                                                       |
| --------------------------------------- | ---------------------------------------------------------------------------- |
| "AI predicts hacking"                   | "model predicts KEV membership probability"                                  |
| "CVSS prediction is accurate"           | "CVSS estimation achieves MAE of..."                                         |
| "EPSS is cheating"                      | "retrospective EPSS introduces temporal leakage"                             |
| "XGBoost is better"                     | "XGBoost achieved higher B2 PR-AUC in this experiment"                       |
| "risk is calculated perfectly"          | "project-controlled prioritization score"                                    |
| "SHAP tells why"                        | "SHAP provides feature attribution"                                          |
| "KEV means exploited probability"       | "KEV membership is used as the prediction target/proxy"                      |
| "criticality is real"                   | "controlled asset criticality tier"                                          |
| "the model understands vulnerabilities" | "the model learns statistical relationships from the feature representation" |

---

# 48. Final Closing Statement

Use this at the end:

> In conclusion, the project demonstrates a reproducible methodology for vulnerability prioritization that combines machine-learning prediction, threat-intelligence signals, contextual prioritization, and explainability. The experiments particularly demonstrate the importance of temporal feature availability: retrospective information can substantially inflate apparent predictive performance. The resulting system therefore treats research provenance and temporal validity as architectural requirements rather than documentation afterthoughts. The current implementation is a validated research prototype, while real enterprise asset data, remediation outcomes, time-aligned EPSS, and human analyst evaluation remain important directions for future work.

---

# Final Mental Model for the Viva

If you remember only this structure:

```text
                 WHY?
                  │
            Vulnerability
            prioritization
                  │
                 HOW?
                  │
       ┌──────────┼──────────┐
       │          │          │
      A1         B2         C1
    CVSS ML    KEV ML     Risk Model
       │          │          │
       │        B1          │
       │     Leakage        │
       │       Audit        │
       └──────────┼──────────┘
                  │
               SHAP
                  │
              FastAPI
                  │
              Frontend
```

And the methodological spine:

```text
DATA
 ↓
DETERMINISTIC ETL
 ↓
FROZEN DATASET
 ↓
TEMPORAL SPLIT
 ↓
PREDICTION-TIME FEATURES
 ↓
MODEL
 ↓
UNTOUCHED TEST
 ↓
INTERPRETATION
 ↓
APPLICATION
```

That is the project.

**All four requested deliverables are now complete:**

1. **Compiled project report / major decisions and reasoning**
2. **Future scope**
3. **Deep understanding / learning document**
4. **Formal presentation & viva preparation document**

