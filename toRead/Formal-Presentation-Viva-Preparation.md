# Vulnerability Prioritization & Triage System
## Formal Presentation & Viva Preparation Document

**Repository:** `seucra/vulnarability-prioritization-triage-system`  
**Purpose:** Formal academic presentation, demonstration, viva, and professor questioning preparation.

---

# 1. Presentation Objective

The presentation should communicate the project as:

> A research-driven vulnerability prioritization and triage system that evaluates machine-learning-based vulnerability severity estimation, publication-time KEV prediction, temporal leakage, and nonlinear risk prioritization, and exposes the resulting capabilities through a web application.

The presentation should **not** frame the project primarily as:

> "A cybersecurity website with XGBoost."

The application is the final delivery layer.

The research methodology is the core.

---

# 2. Recommended Presentation Flow

Use this order:

```text
1. Problem
2. Motivation
3. Objectives
4. Existing difficulty
5. Proposed approach
6. Dataset
7. Data pipeline
8. Research methodology
9. Temporal split
10. EXP-A1
11. EXP-B2
12. EXP-B1 leakage experiment
13. EXP-C1 prioritization
14. SHAP explainability
15. System architecture
16. Backend/API
17. Authentication/RBAC
18. Frontend
19. Live demonstration
20. Results
21. Limitations
22. Conclusion
23. Future scope
```

This order moves from:

```text
WHY
 ↓
WHAT
 ↓
HOW
 ↓
RESULT
 ↓
SYSTEM
 ↓
DEMO
 ↓
LIMITATIONS
 ↓
FUTURE
```

---

# 3. Opening Statement

A concise opening:

> Vulnerability management produces a very large number of vulnerabilities, but remediation capacity is limited. Severity alone does not necessarily determine which vulnerability should be addressed first. This project investigates whether vulnerability characteristics, exploitation-related signals, and asset context can be combined into a more informed prioritization workflow, while maintaining strict temporal boundaries so that historical experiments do not use information that would not have been available at prediction time.

---

# 4. Problem Statement

The problem can be presented as:

> Organizations may have thousands of vulnerabilities but limited time and resources for remediation. A useful triage system therefore needs to distinguish vulnerabilities by severity, exploitation likelihood, and contextual impact rather than relying exclusively on a static severity score.

The research adds an important constraint:

> Any prediction must respect information availability at the prediction point.

---

# 5. Motivation

Three observations motivate the project.

### Observation 1

CVSS expresses severity, but severity is not identical to exploitation likelihood.

### Observation 2

A vulnerability's prioritization can depend on the asset it affects.

### Observation 3

Historical machine-learning evaluation can become invalid if future information is accidentally included.

The project therefore investigates:

```text
severity estimation
+
future KEV prediction
+
temporal leakage
+
context-aware prioritization
```

---

# 6. Objectives

The major objectives are:

1. Build a deterministic canonical vulnerability dataset.
2. Preserve reproducibility through a frozen research dataset.
3. Evaluate pre-scoring CVSS estimation.
4. Evaluate publication-time prediction of future KEV inclusion.
5. Quantify the effect of retrospective EPSS leakage.
6. Compare a transparent linear prioritization baseline with a nonlinear interactive surface.
7. Explain frozen nonlinear model predictions using SHAP.
8. Expose the validated research capabilities through a usable web application.
9. Enforce important research boundaries at the backend API.
10. Provide a research prototype suitable for academic demonstration.

---

# 7. Research Questions

Present the project around four questions.

### RQ-A

> Can vulnerability severity be estimated before formal CVSS scoring?

Experiment:

```text
EXP-A1
```

### RQ-B

> Can publication-time information predict future KEV inclusion?

Experiment:

```text
EXP-B2
```

### RQ-B2

> How much can historical evaluation be inflated by access to a later EPSS snapshot?

Experiment:

```text
EXP-B1
```

### RQ-C

> Does a nonlinear context-aware prioritization surface behave differently from a linear additive baseline?

Experiment:

```text
EXP-C1
```

---

# 8. Data Sources

The research pipeline combines vulnerability information from:

```text
NVD
CISA KEV
EPSS
```

The canonical processed dataset integrates information such as:

```text
CVE
CWE
CPE
CVSS
EPSS
KEV
Vendor Statements
```

The processed data are stored in Parquet.

---

# 9. Dataset Snapshot

The canonical dataset contains approximately:

```text
366,547 vulnerabilities
430,273 CWE relationships
3,133,450 CPE relationships
348,900 EPSS records
1,647 KEV records
1,486 vendor statements
```

The research dataset is frozen.

Do not imply that these numbers represent a continuously updated production database.

---

# 10. Data Pipeline

Show:

```text
NVD / CISA / EPSS
        ↓
Raw Data Verification
        ↓
Deterministic ETL
        ↓
Normalization / Joining
        ↓
Canonical Parquet
        ↓
Invariant Verification
        ↓
Frozen Dataset
        ↓
Experiments
```

The important point is reproducibility.

---

# 11. Why Freeze the Dataset?

Say:

> The dataset was frozen so that later application development could not silently alter the experimental population or invalidate previously reported results.

This establishes a separation between:

```text
research input
```

and:

```text
application development
```

---

# 12. Temporal Evaluation

The most important methodology slide should show:

```text
TRAIN        VALIDATION       TEST
2002–2022    2023–2024        2025–2026
```

Then:

```text
TRAIN + VALIDATION
        ↓
model selection / refitting
        ↓
TEST
        ↓
final evaluation
```

The test partition is not used for model selection.

---

# 13. Why Temporal Splitting?

Expected answer:

> Vulnerability information evolves over time. A random split can allow patterns from future observations to enter model development and produce an unrealistically optimistic evaluation. A chronological split better represents the direction of a real prediction task.

---

# 14. The Central Leakage Example

Use a simple example:

```text
CVE published: 2018

Prediction point:
2018

EPSS snapshot:
2026
```

Question:

> Could the 2018 prediction legitimately use the 2026 snapshot?

Answer:

```text
No.
```

Therefore:

```text
B2 → no retrospective EPSS
B1 → deliberately includes retrospective EPSS
```

B1 exists to demonstrate the problem.

---

# 15. EXP-A1

## Task

Predict:

```text
cvss_v31_base_score
```

This is regression.

### Features

- vulnerability description,
- TF-IDF features,
- CWE information,
- CPE/platform counts,
- publication metadata.

### Models

```text
Ridge Regression
XGBoost Regressor
```

Ridge is the linear baseline.

XGBoost tests nonlinear predictive structure.

---

# 16. A1 Results

| Model | MAE | RMSE | R² |
|---|---:|---:|---:|
| Ridge | 1.0954 | 1.4089 | 0.3194 |
| XGBoost | **0.9750** | **1.3059** | **0.4153** |

Main finding:

> XGBoost reduced test MAE by 0.1204 CVSS points, corresponding to approximately 10.99% relative error reduction.

Interpretation:

> There is measurable pre-scoring predictive signal, but the model is not a replacement for authoritative CVSS scoring.

---

# 17. Why TF-IDF?

Answer:

> Vulnerability descriptions contain useful linguistic information. TF-IDF converts text into numerical features that can be consumed by machine-learning models.

The project also uses unigrams and bigrams because cybersecurity concepts often occur as phrases.

Example:

```text
SQL injection
remote code execution
privilege escalation
```

---

# 18. Why Regression?

Answer:

> CVSS base score is a continuous numerical target, so predicting it is a regression problem.

---

# 19. EXP-B2

## Task

Predict:

```text
future KEV inclusion
```

using information available at publication time.

This is classification.

### Models

```text
Logistic Regression
XGBoost Classifier
```

### Primary metric

```text
PR-AUC
```

Additional metrics:

```text
ROC-AUC
Precision@500
Recall@500
F1 / threshold metrics
```

---

# 20. Why PR-AUC?

KEV positives are highly imbalanced.

A classifier could obtain high accuracy simply by predicting:

```text
not KEV
```

for almost everything.

PR-AUC is therefore more informative for evaluating positive-class retrieval under severe imbalance.

---

# 21. B2 Results

| Metric | Logistic | XGBoost |
|---|---:|---:|
| PR-AUC | 0.02077 | **0.02884** |
| ROC-AUC | 0.85857 | 0.81324 |
| Precision@500 | 3.60% | **6.40%** |
| Recall@500 | — | **10.88%** |

Random PR-AUC baseline:

```text
0.00322
```

XGBoost achieved:

```text
8.96× random Precision@500
```

Main interpretation:

> Publication-time information contains measurable signal for future KEV inclusion, but the absolute predictive performance remains limited.

---

# 22. Why ROC-AUC Decreased While PR-AUC Improved

If questioned:

> The two metrics measure different properties. ROC-AUC considers ranking across true-positive and false-positive rates, while PR-AUC focuses directly on precision and recall for the rare positive class. In an imbalanced problem, improving positive-class retrieval does not require ROC-AUC to increase.

Do not claim that the lower ROC-AUC is an error.

---

# 23. EXP-B1

B1 repeats the KEV prediction experiment with the later EPSS snapshot.

It is explicitly:

```text
RETROSPECTIVE SNAPSHOT EXPERIMENT
```

It is not the primary deployment model.

---

# 24. B1 vs B2

```text
B2 XGBoost
PR-AUC = 0.02884

B1 XGBoost
PR-AUC = 0.33153
```

Approximate inflation:

```text
11.49×
```

The key conclusion:

> Static future EPSS information can dramatically inflate historical model performance.

This is one of the project's strongest methodological findings.

---

# 25. What B1 Proves

It does **not** prove:

> EPSS is bad.

It demonstrates:

> A later EPSS snapshot cannot be treated as a publication-time feature in historical prediction experiments without introducing temporal leakage.

That distinction is important.

---

# 26. EXP-C1

C1 studies prioritization rather than supervised prediction.

The two surfaces are:

```text
Mode 1:
S_linear =
0.25x1 + 0.25x2 + 0.25x3 + 0.25x4
```

and:

```text
Mode 2:
S_nonlinear =
x4[
1 -
(1-x1)^(1+1.0x3)
(1-x2)^(1+1.5x3)
]
```

Parameters:

```text
α = 1.0
β = 1.5
```

---

# 27. Why C1 Is Not Another ML Model

C1 does not train a supervised model to predict remediation priority.

Instead, it asks:

> How does a nonlinear decision surface behave differently from a transparent equal-weight linear baseline when vulnerability/threat signals interact with controlled asset context?

This is a decision-support simulation.

---

# 28. Asset Criticality

Controlled tiers:

```text
Tier 1 = 0.25
Tier 2 = 0.50
Tier 3 = 0.75
Tier 4 = 1.00
```

These are experimental variables.

They are not observed enterprise ground truth.

---

# 29. C1 Results

Global ranking:

```text
Spearman ρ = 0.9962
Kendall τ = 0.9356
```

Top queue:

```text
Top-100 Jaccard = 0.005
Top-1000 Jaccard = 0.182
```

Interpretation:

> The overall rankings are highly correlated, yet the exact vulnerabilities selected near the top of the remediation queue can differ substantially.

---

# 30. Why Jaccard Matters

For two Top-100 sets:

```text
J(A,B) =
|A ∩ B|
---------
|A ∪ B|
```

It measures actual set overlap.

This matters operationally because security teams may care most about:

```text
Which vulnerabilities are in the first remediation queue?
```

rather than whether the complete 200,000+ ranking is globally similar.

---

# 31. SHAP

SHAP is used after the final tree models are frozen.

Conceptually:

```text
baseline prediction
        +
feature contributions
        =
final prediction
```

It answers:

> Which features contributed to this model prediction?

---

# 32. SHAP Caveat

Critical statement:

> SHAP explains model behavior; it does not establish causality.

A positive SHAP contribution means:

```text
feature contributed positively to model output
```

not:

```text
feature caused real-world exploitation
```

---

# 33. System Architecture

Show the complete system:

```text
             NVD / CISA / EPSS
                     │
                     ▼
             Deterministic ETL
                     │
                     ▼
              Frozen Parquet
                     │
          ┌──────────┼──────────┐
          │          │          │
         A1         B2         C1
          │          │          │
      CVSS ML      KEV ML    Risk Surface
          │          │          │
          └──────────┼──────────┘
                     │
                    SHAP
                     │
                     ▼
                  FastAPI
                     │
          ┌──────────┼──────────┐
          │          │          │
        Search    Predict    Prioritize
          │          │          │
          └──────────┼──────────┘
                     │
                 Auth + RBAC
                     │
                     ▼
                 Frontend
```

---

# 34. Backend Architecture

Main responsibilities:

```text
API layer
service layer
data layer
model layer
scoring layer
explanation layer
provenance layer
```

Important services:

### Vulnerability Service

Search, filters, pagination, details.

### Inference Service

Loads A1/B2 model artifacts and preprocessing.

### Scoring Service

Calculates linear/nonlinear prioritization.

### Explanation Service

Calculates SHAP feature attribution.

### Provenance Service

Exposes dataset/model/experiment metadata.

---

# 35. Why FastAPI?

FastAPI provides the REST interface between the application and the research backend.

Conceptually:

```text
HTTP
 ↓
FastAPI
 ↓
validated request
 ↓
service
 ↓
research artifact
 ↓
JSON response
```

It also provides automatic API documentation through OpenAPI.

---

# 36. Why the Backend Must Enforce B2 Boundaries

The frontend can say:

```text
"Do not provide EPSS."
```

but users can bypass frontend code.

Therefore the backend independently validates the request.

The research boundary must survive:

```text
malicious client
manual HTTP request
modified frontend
```

The backend is authoritative.

---

# 37. Authentication / RBAC

Roles:

```text
Security Analyst
Researcher
Administrator
```

The roles provide different application access.

Authentication is demonstration-level application infrastructure.

It should not be presented as a contribution to cybersecurity identity management.

---

# 38. Frontend

The frontend provides:

```text
Home
Dashboard
Explorer
Predictions
Prioritization
Explainability
Provenance
Documentation
FAQ
Contact
Profile
Admin
```

The frontend is a human interaction layer over the backend.

It does not own the research logic.

---

# 39. Deployment

The public demonstration uses:

```text
https://vuln-triage.seucra.tech
```

for the frontend.

The backend API is:

```text
https://vuln-triage-api.seucra.tech
```

The architecture is:

```text
Browser
   ↓
GitHub Pages
   ↓
Static Frontend
   ↓
HTTPS API request
   ↓
Cloudflare Tunnel
   ↓
localhost:5002
   ↓
FastAPI
   ↓
Models + Frozen Dataset
```

This is a:

> Research Prototype / Public Demonstration Deployment

---

# 40. Why This Deployment Is Acceptable for the Project

The goal is an academic demonstration, not a production SaaS platform.

The architecture allows:

- public frontend access,
- public API routing,
- local model execution,
- local dataset access,
- no publication of research datasets/model binaries through GitHub Pages.

The backend machine must remain running for the live demonstration.

---

# 41. Testing

Final automated suite:

```text
39 / 39 PASSED
```

Coverage includes:

```text
authentication
RBAC
REST API
dataset invariants
```

Browser E2E verification covered:

```text
authentication
dashboard
prioritization
SHAP
mobile behavior
tunneled backend integration
```

---

# 42. Important Implementation Bugs That Were Found

These are useful only if asked about development/debugging.

### CI dependency-cache issue

GitHub Actions expected:

```text
requirements.txt
or
pyproject.toml
```

because pip caching was enabled.

The repository intentionally had no such manifest.

The cache option was removed and CI dependencies were installed explicitly.

### Missing typing import

Python 3.10 CI exposed missing:

```python
Dict
Any
Optional
```

imports in the security module.

The missing imports were added.

### Missing model artifact handling

CI did not contain local model binaries.

Explanation code attempted:

```text
None.transform()
```

instead of returning the standard model-unavailable response.

The explanation service was corrected to detect missing artifacts.

### Frontend authentication hydration

The frontend initially persisted the token but not the current user.

This caused incorrect first-frame dashboard state.

The user state was persisted and synchronously hydrated.

### Duplicate state singleton

Different module URLs created separate state instances.

The imports were normalized so all components use one state singleton.

These bugs were implementation issues discovered through testing. They are not research findings.

---

# 43. What Is Complete

The project currently has:

```text
✓ deterministic ETL
✓ canonical dataset
✓ reproducibility verification
✓ frozen research data
✓ temporal experiments
✓ A1
✓ B2
✓ B1
✓ C1
✓ SHAP
✓ serialized model artifacts
✓ FastAPI backend
✓ API boundary validation
✓ authentication
✓ RBAC
✓ frontend
✓ responsive/mobile UI
✓ exports
✓ printable reports
✓ documentation
✓ FAQ
✓ GitHub Pages deployment
✓ Cloudflare Tunnel
✓ automated CI
✓ 39/39 tests
✓ live tunneled E2E verification
```

Do not present these as remaining work.

---

# 44. Things That Are Not Remaining Implementation Work

The following are future improvements rather than missing current requirements:

```text
production identity provider
production database
cloud-hosted ML inference
enterprise asset inventory
real remediation outcomes
continuous data ingestion
automated model retraining
advanced observability
high-availability deployment
production-scale authentication infrastructure
```

The current system is intentionally a research prototype.

---

# 45. Limitations Slide

Use these explicitly.

### KEV limitation

KEV is not complete ground truth for all exploitation.

### C1 limitation

Asset tiers are synthetic.

### B2 limitation

Predictive performance is limited.

### Dataset limitation

The study uses a frozen historical snapshot.

### Outcome limitation

No real organizational remediation outcomes are measured.

### Generalization limitation

Future vulnerability distributions may differ.

### Explainability limitation

SHAP explains model behavior, not causality.

---

# 46. What the Project Actually Proves

The strongest defensible conclusions are:

### Finding 1

Pre-scoring vulnerability information contains measurable signal for estimating CVSS v3.1 severity.

### Finding 2

Publication-time vulnerability information contains measurable signal for future KEV inclusion.

### Finding 3

Using a later EPSS snapshot can dramatically inflate historical prediction performance.

### Finding 4

A nonlinear prioritization surface can substantially change the highest-priority remediation set relative to a linear additive baseline.

---

# 47. What It Does Not Prove

Do not overclaim.

It does not prove:

```text
XGBoost is universally best.
The model predicts all exploitation.
KEV equals exploitation probability.
The nonlinear score is optimal.
Synthetic tiers represent real organizations.
SHAP establishes causality.
The system improves enterprise remediation outcomes.
The application is enterprise production software.
```

---

# 48. Demonstration Flow

Use a predictable live sequence:

```text
1. Landing Page
       ↓
2. Login
       ↓
3. Role-specific Dashboard
       ↓
4. Vulnerability Explorer
       ↓
5. Open a known CVE
       ↓
6. Inspect authoritative metadata
       ↓
7. Run A1 prediction
       ↓
8. Run B2 prediction
       ↓
9. Open Prioritization
       ↓
10. Compare Mode 1 / Mode 2
       ↓
11. Open SHAP explanation
       ↓
12. Show Provenance
       ↓
13. Show Research/Documentation
       ↓
14. Logout
```

Use a known seeded vulnerability during demonstration rather than depending on unpredictable search behavior.

---

# 49. What to Say During the Demo

Do not narrate every button.

Explain the research distinction behind each screen.

### Explorer

> This is the read-only vulnerability exploration layer over the frozen research dataset.

### Detail

> These are authoritative vulnerability records. The predicted values are kept visually and semantically separate from authoritative metadata.

### A1

> This model estimates CVSS before formal scoring using publication-time vulnerability information.

### B2

> This predicts future KEV inclusion while deliberately rejecting retrospective EPSS information.

### Prioritization

> This is not another trained classifier. It is a controlled decision-support simulation comparing an equal-weight linear baseline with a nonlinear interaction surface across asset criticality tiers.

### SHAP

> This explains how the frozen tree model arrived at its prediction. It is not causal analysis.

### Provenance

> This exposes the dataset and experiment metadata so the application does not become a black box disconnected from the research.

---

# 50. Likely Viva Question: Why Is the Project Novel?

Best defensible answer:

> The contribution is not simply using XGBoost on vulnerability data. The project combines strict temporal feature-availability discipline, a controlled retrospective leakage experiment, and an explicit investigation of nonlinear prioritization under asset context. The B1/B2 comparison is particularly important because it empirically demonstrates how historical performance can be inflated when future information is incorrectly included.

Do not claim publication-level novelty unless the formal research literature review establishes it.

---

# 51. Likely Viva Question: Why XGBoost?

> XGBoost provides a nonlinear tree-based model capable of capturing feature interactions, while Ridge and Logistic Regression provide simpler linear baselines. The comparison tests whether nonlinear structure provides additional predictive value.

---

# 52. Likely Viva Question: Why Not Deep Learning?

> The research questions did not require a deep neural architecture. The selected models provide a useful balance of nonlinear capacity, computational practicality, reproducibility, and explainability for the available structured and text-derived features.

Do not say deep learning is inherently unnecessary.

---

# 53. Likely Viva Question: Why Not Use Random Split?

> Because the prediction task is temporal. A random split does not preserve the historical direction of information and can produce an evaluation that is less representative of deployment at publication time.

---

# 54. Likely Viva Question: Why No EPSS in B2?

> The available EPSS snapshot is later than many of the historical prediction points. Including it would give the model information that was unavailable at those points and therefore introduce temporal leakage.

---

# 55. Likely Viva Question: Why Did You Include B1?

> B1 is deliberately retrospective. It quantifies how much apparent predictive performance changes when future EPSS information is allowed. It is a sensitivity/leakage demonstration, not the deployment model.

---

# 56. Likely Viva Question: Why Is B2 Performance So Low?

> Future KEV inclusion is a difficult and highly imbalanced target. The model has measurable signal, but many real-world factors affecting exploitation are not available in the publication-time feature set. The result therefore should be interpreted as ranking signal rather than a highly accurate exploitation predictor.

---

# 57. Likely Viva Question: Why PR-AUC?

> Because the positive class is rare. Accuracy can be dominated by the majority negative class, while PR-AUC directly reflects the precision-recall tradeoff for identifying rare positive cases.

---

# 58. Likely Viva Question: Why Is ROC-AUC Higher for Logistic Regression?

> ROC-AUC and PR-AUC measure different aspects of ranking performance. The logistic model can have stronger overall ROC ranking while XGBoost performs better in the precision-recall regime that is more relevant for the rare KEV positives and the top candidate queue.

---

# 59. Likely Viva Question: Why Synthetic Asset Tiers?

> We did not have real enterprise asset criticality or remediation outcome data. Rather than fabricate such data, we treated asset criticality as a controlled experimental variable with four predefined levels.

---

# 60. Likely Viva Question: Is the Nonlinear Model Better?

Correct answer:

> The experiment demonstrates that it behaves differently and substantially changes the top remediation queue. It does not establish that it is superior in real enterprise environments because there is no real enterprise remediation ground truth in the experiment.

---

# 61. Likely Viva Question: Why Is Global Correlation So High but Top-100 Overlap So Low?

> Correlation evaluates the relationship between the complete rankings, while Jaccard evaluates which specific elements are shared in the selected sets. Small score differences across a large population can produce major changes around the ranking boundary, especially when only the top 100 are selected.

---

# 62. Likely Viva Question: What Does SHAP Tell You?

> SHAP tells us how individual features contributed to a particular model prediction relative to the model's baseline output.

---

# 63. Likely Viva Question: Does SHAP Prove Causality?

> No. It explains the model's prediction. It does not establish that a feature caused exploitation or severity in the real world.

---

# 64. Likely Viva Question: Why DuckDB?

> The core dataset is analytical and largely immutable. DuckDB can query Parquet directly, so the application can retrieve required data without introducing a mutable transactional database for the research dataset.

---

# 65. Likely Viva Question: Why FastAPI?

> It provides a lightweight typed REST API layer that separates HTTP concerns from the vulnerability, inference, scoring, explanation, and provenance services.

---

# 66. Likely Viva Question: Why Enforce Rules in the Backend?

> Because frontend validation can be bypassed. If a temporal research boundary is scientifically important, the backend must independently reject invalid inputs.

---

# 67. Likely Viva Question: Why Authentication?

> Authentication and RBAC were added to satisfy the application-layer requirements and demonstrate role-specific workflows. They are not part of the research contribution.

---

# 68. Likely Viva Question: Why Three Roles?

> The roles correspond to different intended workflows: security analysts use triage and prediction capabilities, researchers inspect methodology and explanations, and administrators access administrative and provenance functions.

---

# 69. Likely Viva Question: Why Did the UI Come Last?

> Because the UI should expose validated research capabilities. Building the UI first would risk allowing presentation requirements to determine the underlying research methodology.

---

# 70. Likely Viva Question: What Happens If the Backend Is Down?

> The static frontend can still load its public shell and navigation, but backend-dependent operations cannot execute. The application exposes appropriate loading/offline/error states rather than pretending that research data or model inference are available.

---

# 71. Likely Viva Question: Is This Production Ready?

> No. It is explicitly a research prototype and public demonstration deployment. It demonstrates the complete research-to-application pipeline, but it does not claim enterprise-grade availability, identity infrastructure, asset integration, or remediation validation.

---

# 72. Likely Viva Question: What Would You Do Next?

The highest-value future directions are:

1. Integrate real enterprise asset inventories.
2. Validate C1 against real remediation decisions.
3. Incorporate historical EPSS snapshots aligned to each prediction date.
4. Expand exploitation labels beyond KEV.
5. Evaluate calibration and decision-curve behavior.
6. Study model drift over future vulnerability distributions.
7. Add continuous data/version management.
8. Evaluate additional model families.
9. Validate the system with security practitioners.
10. Move inference/runtime infrastructure to production-grade hosting if deployment requirements justify it.

---

# 73. Strong Final Conclusion

Use:

> This project demonstrates a complete research-to-application pipeline for vulnerability prioritization. The experimental results show measurable predictive signal for pre-scoring CVSS estimation and publication-time KEV prediction, while the B1/B2 comparison demonstrates how severely retrospective information can distort historical evaluation. The C1 experiment further shows that nonlinear interaction between vulnerability signals and asset context can materially change the highest-priority remediation queue. These findings are exposed through a role-aware research prototype while preserving the frozen dataset and enforcing key methodological boundaries at the backend.

---

# 74. Final 30-Second Version

If the professor asks:

> "Explain your project briefly."

Answer:

> This project is a vulnerability prioritization and triage system built around a research study of three related problems. First, EXP-A1 estimates CVSS severity from pre-scoring vulnerability information using Ridge and XGBoost. Second, EXP-B2 predicts future KEV inclusion using only publication-time information, with temporal splitting to avoid leakage. We then deliberately run EXP-B1 with a later EPSS snapshot to show how retrospective information can inflate performance by about 11.5 times. Finally, EXP-C1 compares a transparent linear prioritization baseline with a nonlinear interaction surface under controlled asset criticality tiers. The research artifacts are then exposed through a FastAPI backend and role-aware frontend, with SHAP explanations and provenance information. The system is explicitly presented as a research prototype rather than an enterprise production platform.

---

# 75. Presentation Rules

Keep these principles throughout the presentation.

### Rule 1 — Distinguish authoritative data from predictions

Always distinguish:

```text
Authoritative CVSS
Predicted CVSS
```

and:

```text
Current EPSS snapshot
Publication-time prediction
```

### Rule 2 — Never call B1 the primary model

B2 is primary.

B1 is retrospective sensitivity analysis.

### Rule 3 — Never call synthetic asset tiers real enterprise data

They are controlled experimental inputs.

### Rule 4 — Never call SHAP causal

It explains model behavior.

### Rule 5 — Do not overclaim C1

It demonstrates ranking behavior, not real-world remediation superiority.

### Rule 6 — Do not overclaim B2

Measurable signal does not mean highly accurate exploitation prediction.

### Rule 7 — Call the deployment a research prototype

Do not describe it as enterprise production infrastructure.

### Rule 8 — Keep the research before the UI

The UI demonstrates the research; it is not the contribution by itself.

---

# 76. Numbers Worth Memorizing

At minimum, remember:

```text
Dataset:
366,547 canonical CVEs

Temporal split:
Train      2002–2022
Validation 2023–2024
Test       2025–2026

A1:
Ridge MAE       1.0954
XGBoost MAE     0.9750
Error reduction 10.99%

B2:
Logistic PR-AUC 0.02077
XGBoost PR-AUC   0.02884
Precision@500    6.40%
Recall@500       10.88%
Random PR-AUC    0.00322
Random multiplier ≈ 8.96×

B1:
XGBoost PR-AUC   0.33153
Inflation        ≈ 11.49×

C1:
Spearman ρ       0.9962
Kendall τ        0.9356
Top-100 Jaccard  0.005
Top-1000 Jaccard 0.182

Asset tiers:
0.25 / 0.50 / 0.75 / 1.00

C1:
α = 1.0
β = 1.5

Tests:
39 / 39 passed
```

---

# 77. Final Defense Mental Model

If you remember only one architecture:

```text
                 WHY?
                  │
            Research Questions
                  │
                 HOW?
                  │
             Methodology
                  │
          Information Boundary
                  │
                DATA
                  │
             EXPERIMENTS
          ┌───────┼───────┐
          A1      B1/B2    C1
          │        │       │
          └────────┼───────┘
                   │
                RESULTS
                   │
              INTERPRETATION
                   │
                 SHAP
                   │
              APPLICATION
                   │
        ┌──────────┴──────────┐
        │                     │
     FastAPI              Frontend
        │                     │
        └──────────┬──────────┘
                   │
              Public Demo
```

The intellectual center is:

```text
temporal validity
+
predictive signal
+
nonlinear prioritization
+
careful interpretation
```

The application demonstrates those results; it does not replace them.
