# Deliverable 1/4 — Consolidated Project History, Research Decisions & Architecture

## Vulnerability Prioritization & Triage System

**Repository:** `seucra/vulnarability-prioritization-triage-system`
**Project context:** Web Design Lab / research-oriented cybersecurity system
**Current state:** Research, backend, frontend, authentication/RBAC, documentation, testing, repository cleanup, and public-demonstration deployment preparation completed.

---

# 1. Project Overview

The project is a **research-oriented vulnerability prioritization and triage system** investigating whether machine learning and nonlinear decision-support methods can improve vulnerability assessment while maintaining strict temporal and methodological validity.

The central research problem is:

> Can vulnerability severity, exploitation-related signals, and controlled asset context be combined to produce more useful vulnerability prioritization than severity-only or simple linear approaches?

The system therefore combines:

* NVD vulnerability information
* CWE weakness information
* CPE/platform information
* CISA Known Exploited Vulnerabilities (KEV)
* EPSS exploitation-prediction data
* vendor statements
* machine-learning models
* controlled asset criticality
* nonlinear prioritization
* SHAP-based explainability
* research provenance
* analyst-facing application workflows

The project was deliberately developed as a **research system first and application second**. This distinction drove many later architectural decisions. 

---

# 2. Initial Implementation and Decision to Rebuild

The project did not begin from the final architecture.

The initial implementation already contained:

* React/TypeScript frontend
* FastAPI backend
* machine-learning models
* NVD data
* CISA KEV data
* EPSS data
* vulnerability prioritization
* perturbation-based explanations

The initial explanation mechanism used a **Leave-One-Out perturbation approach** rather than actual SHAP.

During the research review, this was identified as insufficiently rigorous because:

* unigram perturbation did not correctly represent the unigram+bigram feature space
* feature interactions were not properly handled
* phrase-level attribution could become misleading
* the method was not equivalent to Shapley-based explanation

The project was therefore substantially rebuilt instead of simply patched.

The guiding decision became:

> Preserve the project concept, but rebuild the underlying research and data pipeline so that the resulting claims could be defended academically. 

---

# 3. Research Data Foundation

The raw data collection incorporated:

* NVD CVE records from 2002–2026
* NVD CPE information
* CPE matching data
* CISA KEV
* EPSS
* vendor statements

Raw inputs were kept under:

```text
data/raw/
```

and transformed into canonical processed datasets under:

```text
data/processed/
```

The principal processed tables are:

```text
vulnerabilities.parquet
cve_cwe.parquet
cve_cpe.parquet
epss.parquet
kev.parquet
vendor_statements.parquet
```

The canonical vulnerability population contains approximately:

```text
366,547 CVEs
```

The project's data-audit work subsequently established authoritative source counts and verified the raw dataset structure. 

---

# 4. Phase 0 — Raw Data Verification

Before modeling, the project established a dedicated raw-data verification stage.

The principle was:

> Research results are difficult to defend if the underlying source data cannot first be demonstrated to be identifiable and intact.

Phase 0 therefore established:

* source files
* expected datasets
* file integrity
* provenance
* verification scripts
* deterministic measurements

No machine-learning experiments were performed at this stage.

This created a clear boundary between:

```text
Raw-source verification
        ↓
Research dataset construction
        ↓
Experiments
```

rather than allowing modeling assumptions to contaminate data validation. 

---

# 5. Phase 1 — Deterministic ETL

The raw sources were transformed through a deterministic ETL pipeline.

ETL performed:

* parsing
* normalization
* joining
* vulnerability attribute extraction
* CVE/CWE relationships
* CPE relationships
* KEV integration
* EPSS integration
* vendor-statement integration
* Parquet generation

The resulting processed data became an **immutable research input**.

The fundamental architecture became:

```text
Raw Sources
    ↓
Deterministic ETL
    ↓
Canonical Processed Dataset
    ↓
FREEZE
    ↓
Experiments
    ↓
Application
```

Neither the experiments nor the application were allowed to silently modify the research dataset. 

---

# 6. Reproducibility Problem and Resolution

A major engineering lesson emerged during reproducibility testing.

Independent processed datasets initially produced different fingerprints.

The investigation showed that the ETL itself was not nondeterministic. The problem was the **fingerprinting method**.

Some child tables contained multiple rows with the same partial key, for example:

```text
CVE ID
+
CPE URI
```

while differing in other fields.

Sorting only by the partial key allowed equivalent logical rows to appear in different serialized orders:

```text
Same logical dataset
        ≠
Same serialized row order
```

Consequently, SHA-256 fingerprints could differ even though the underlying logical datasets were equivalent.

The canonicalization procedure was therefore strengthened to use:

* alphabetically sorted columns
* all columns as the row-ordering key
* normalized NULL representation
* deterministic float formatting
* deterministic timestamps
* standardized line endings
* SHA-256 over canonical bytes

Two independent clean rebuilds subsequently produced:

```text
0 differing logical rows
```

across all six processed tables, with the generated Parquet files also matching bit-for-bit.

This established the reproducibility of the ETL pipeline. 

---

# 7. Dataset Freeze

The processed dataset was formally treated as a frozen research artifact.

This separation was critical because otherwise:

```text
Application development
        ↓
Data changes
        ↓
Different experiment inputs
```

could silently invalidate reported results.

The resulting architecture deliberately separates:

```text
Research Data
     ≠
Application State
```

The application therefore queries the frozen data rather than maintaining an independently modified copy. 

---

# 8. Phase 2 — Experimental Protocol

The project did not follow a:

> train → inspect result → modify methodology → report

workflow.

Instead, the protocol was defined first:

```text
Research question
      ↓
Target definition
      ↓
Feature-availability boundary
      ↓
Temporal split
      ↓
Models
      ↓
Metrics
      ↓
Experiment
```

Three principal research areas were established:

1. **A1 — CVSS estimation**
2. **B-series — KEV prediction and EPSS leakage analysis**
3. **C1 — contextual nonlinear prioritization**

This separation also prevented the C1 simulation from being incorrectly presented as another supervised-learning experiment. 

---

# 9. Temporal Experimental Design

The most important methodological decision was the temporal split:

```text
2002 ───────────── 2022 | 2023 ───── 2024 | 2025 ───────── 2026
        TRAIN                  VALIDATION              TEST
```

Specifically:

* **Training:** 2002–2022
* **Validation:** 2023–2024
* **Testing:** 2025–2026

The test partition remained untouched during model selection.

The reason was that random splitting can allow later vulnerability information and patterns to influence the training process while older vulnerabilities are used as evaluation examples.

The temporal split instead approximates chronological deployment:

```text
Past
 ↓
Model development
 ↓
Future-like data
 ↓
Evaluation
```

The final configuration was selected using training/validation data, then refit using the combined training and validation period before evaluation on the untouched test period. 

---

# 10. EXP-A1 — CVSS v3.1 Estimation

A1 asks:

> Can vulnerability information available before formal scoring be used to estimate the authoritative CVSS v3.1 base score?

### Target

```text
cvss_v31_base_score
```

### Task

Regression.

### Models

```text
Ridge Regression
       vs
XGBoost Regressor
```

### Feature categories

The experiment uses information such as:

* vulnerability description text
* CWE information
* CPE/platform information
* appropriate publication-time metadata

Features that would directly leak the target were excluded.

### Metrics

Primary:

```text
MAE
```

Secondary:

```text
RMSE
R²
```

---

# 11. EXP-A1 Results

The untouched test results were:

| Model   |        MAE |       RMSE |         R² |
| ------- | ---------: | ---------: | ---------: |
| Ridge   |     1.0954 |     1.4089 |     0.3194 |
| XGBoost | **0.9750** | **1.3059** | **0.4153** |

XGBoost reduced MAE by:

```text
0.1204 CVSS points
```

or approximately:

```text
10.99% relative error reduction
```

The appropriate conclusion is that the nonlinear model captured additional predictive structure relative to the linear baseline.

It does **not** mean that XGBoost produces authoritative CVSS scores or replaces CVSS scoring. 

---

# 12. EXP-B2 — Publication-Time KEV Prediction

B2 asks:

> Can information available around vulnerability publication/initial triage identify vulnerabilities that will subsequently enter the CISA KEV catalog?

### Target

```text
is_kev
```

### Task

Binary classification.

### Models

```text
Logistic Regression
       vs
XGBoost Classifier
```

A crucial methodological decision was made:

> **EPSS was excluded from the primary B2 experiment.**

Also excluded were post-publication signals such as:

* later EPSS values
* KEV `date_added`
* ransomware campaign information
* future modification information

The purpose was to maintain a genuine publication-time prediction boundary. 

---

# 13. EXP-B2 Metrics

KEV membership is highly imbalanced.

Therefore accuracy was not treated as the primary metric.

The primary metric became:

```text
PR-AUC
```

with additional evaluation including:

* ROC-AUC
* Precision@500
* Recall@500
* F1 where appropriate

This better reflects the problem of identifying a small minority of high-priority vulnerabilities.

---

# 14. EXP-B2 Results

| Model               |      PR-AUC | ROC-AUC | Precision@500 | Recall@500 |
| ------------------- | ----------: | ------: | ------------: | ---------: |
| Logistic Regression |     0.02077 | 0.85857 |         3.60% |          — |
| XGBoost             | **0.02884** | 0.81324 |     **6.40%** | **10.88%** |

Random-selection PR-AUC was approximately:

```text
0.00322
```

XGBoost therefore produced approximately:

```text
8.96×
```

random Precision@500 enrichment.

It captured:

```text
10.88%
```

of future KEV vulnerabilities within the top 500 candidates.

The result is intentionally interpreted conservatively:

> Publication-time KEV prediction contains measurable predictive signal, but remains difficult.



---

# 15. EXP-B1 — Retrospective EPSS Sensitivity Experiment

B1 was deliberately created as a **retrospective sensitivity experiment**, not as the legitimate historical prediction model.

It used the:

```text
2026-07-16 EPSS snapshot
```

as an additional feature.

This allowed the project to demonstrate experimentally what happens when later information is incorrectly made available to a historical prediction task.

---

# 16. B1 vs B2 — Temporal Leakage Finding

Primary B2:

```text
PR-AUC = 0.02884
```

Retrospective B1:

```text
PR-AUC = 0.33153
```

Difference:

```text
+0.30269 PR-AUC
```

or approximately:

```text
11.49× B2 PR-AUC
```

The result demonstrated how dramatically retrospective information can inflate apparent historical predictive performance.

The central methodological finding became:

> A later EPSS snapshot cannot legitimately be treated as though it had been available at the original prediction time.

The application therefore explicitly separates:

```text
Publication-Time Prediction
```

from:

```text
Current / Retrospective EPSS Snapshot
```



---

# 17. EXP-C1 — Nonlinear Prioritization

C1 addresses a different question.

A1 asks:

> What can be predicted about CVSS?

B2 asks:

> Can future KEV membership be predicted?

C1 asks:

> How can vulnerability and contextual signals be combined for prioritization?

C1 is **not supervised machine learning**.

It is a controlled decision-support simulation investigating how asset context and nonlinear interactions can alter prioritization.

---

# 18. C1 Linear Baseline

The project-controlled linear baseline is:

[
S_{linear}=0.25x_1+0.25x_2+0.25x_3+0.25x_4
]

The equal weights were explicitly treated as **project-controlled experimental assumptions**, rather than being falsely attributed as universally optimal or directly prescribed by the reference research.

---

# 19. C1 Nonlinear Surface

The nonlinear model uses an interaction surface of the form:

[
S_{nonlinear}
=============

x_4
\left[
1-
(1-x_1)^{1+x_3}
(1-x_2)^{1+1.5x_3}
\right]
]

with:

```text
α = 1.0
β = 1.5
```

The purpose is to permit contextual interaction rather than treating every signal as an independent additive contribution.

---

# 20. Controlled Asset Criticality

The experiment introduced controlled asset criticality tiers:

| Tier   | Meaning  | Normalized value |
| ------ | -------- | ---------------: |
| Tier 1 | Low      |             0.25 |
| Tier 2 | Medium   |             0.50 |
| Tier 3 | High     |             0.75 |
| Tier 4 | Critical |             1.00 |

These are **controlled experimental inputs**, not measurements of real enterprise asset criticality.

This distinction is maintained throughout the project.

---

# 21. C1 Results

The two prioritization approaches produced:

```text
Spearman ρ = 0.9962
Kendall τ = 0.9356
```

However:

```text
Top-100 Jaccard  = 0.005
Top-1000 Jaccard = 0.182
```

Thus, the overall rankings were strongly correlated while the highest-priority candidate sets differed substantially.

This demonstrates an important triage property:

> High global rank correlation does not guarantee agreement about which vulnerabilities should actually enter a limited remediation queue.

The result is limited to the controlled simulation and is not evidence that the nonlinear surface is superior in real organizations. 

---

# 22. Explainability — From Perturbation to SHAP

The original implementation's perturbation-based explanation approach was replaced with **SHAP-based post-hoc explainability** for the frozen tree models.

The original approach had limitations involving:

* unigram/bigram mismatch
* phrase attribution
* feature interaction handling
* lack of equivalence to Shapley-based attribution

SHAP was therefore adopted as the more appropriate explanation mechanism.

The project maintains the distinction:

```text
SHAP
 ↓
Explains model behavior
```

not:

```text
SHAP
 ↓
Proves causality
```



---

# 23. Phase 3 — Research Artifact Reproducibility

Phase 3 generated reproducible research artifacts under:

```text
data/experiments/phase3/
```

including:

```text
exp_a1/
exp_b1/
exp_b2/
exp_c1/
shap/
```

Research documentation included:

```text
docs/research/PHASE_3_EXPERIMENT_REPORT.md
docs/research/PHASE_3_RESULTS.md
```

Artifacts included:

* actual-vs-predicted CVSS plots
* residual analysis
* PR curves
* ROC curves
* B1/B2 comparisons
* C1 ranking comparisons
* C1 risk surface
* SHAP feature-importance outputs



---

# 24. Model Serialization and Research/Application Consistency

When application development began, a further issue emerged.

The Phase 3 experiment scripts contained:

* metrics
* configurations
* feature information

but the binary model objects had not originally been persisted.

The project did **not** simply train unrelated application models.

Instead, the final Phase 3 configurations were deterministically reconstructed using:

* identical training population
* identical preprocessing
* identical feature pipeline
* identical hyperparameters
* identical seed
* identical model configuration

The resulting serialized models reproduced the recorded Phase 3 final metrics with effectively zero difference.

This established that application inference was based on the research models rather than a second, unrelated model implementation. 

---

# 25. Phase 4 — FastAPI Backend

The backend was implemented with FastAPI using a service-oriented structure:

```text
API
 ↓
Services
 ↓
Data / ML / Scoring / Explanation
```

Major services include:

```text
vulnerability_service
inference_service
scoring_service
explanation_service
provenance_service
```

Frozen Parquet data is queried using DuckDB/read-only mechanisms rather than copied into a mutable application database.

This preserves the research-data boundary. 

---

# 26. Backend API

The backend exposes capabilities including:

```text
GET  /api/v1/vulnerabilities
GET  /api/v1/vulnerabilities/{cve_id}

POST /api/v1/predict/cvss
POST /api/v1/predict/kev

POST /api/v1/prioritize

POST /api/v1/explain/cvss
POST /api/v1/explain/kev

GET  /api/v1/provenance
```

These provide:

* vulnerability retrieval
* filtering
* pagination
* CVSS estimation
* publication-time KEV prediction
* prioritization
* explainability
* research provenance



---

# 27. Publication-Time Boundary Enforcement

One of the most important backend safeguards is that B2 constraints are enforced at the API boundary.

The backend rejects forbidden inputs rather than trusting the frontend.

For example:

```text
Frontend:
"Do not send EPSS to B2."
```

is insufficient by itself.

Instead:

```text
Frontend validation
       +
Backend validation
       ↓
Publication-time boundary
```

The backend rejects post-publication information such as forbidden EPSS/CVSS inputs for the B2 prediction workflow.

This turns temporal validity from documentation into an enforceable application constraint. 

---

# 28. Provenance Architecture

The backend exposes research provenance including:

* dataset version
* dataset freeze
* model identity
* experiment identity
* training period
* prediction boundary
* EPSS snapshot
* research limitations
* benchmark metrics

This ensures the frontend does not become an independent source of research truth.



---

# 29. Phase 5 — Frontend Foundation

The frontend was deliberately postponed until the research and backend layers were complete.

This decision prevented presentation requirements from influencing research methodology.

The original frontend structure included:

```text
frontend/
├── index.html
├── css/
├── js/
│   ├── config.js
│   ├── api.js
│   ├── state.js
│   ├── app.js
│   └── components/
```

Core research views included:

* vulnerability explorer
* CVE detail drawer
* A1 prediction workspace
* B2 prediction workspace
* prioritization sandbox
* SHAP explanation view
* research provenance view



---

# 30. WDL-3 — Role-Specific Application Architecture

The application was subsequently expanded beyond the original generic dashboard.

WDL-3 introduced three distinct application roles:

```text
Security Analyst
Academic Researcher
Administrator
```

A shared dashboard shell determines the authenticated user's role and delegates to the appropriate dashboard implementation.

The three role-specific renderers are:

```text
renderAnalystDashboard
renderResearcherDashboard
renderAdminDashboard
```

This transformed the application from a generic dashboard into role-specific workflows. 

The Security Analyst workspace focuses on operational vulnerability triage and threat discovery, while the Researcher and Administrator roles provide different research/management-oriented workflows. 

---

# 31. Authentication and RBAC

Authentication was initially excluded from the academic research prototype.

That decision is now **obsolete as a description of the final application state**.

Authentication and role-based access control were subsequently implemented as part of the application layer.

The important distinction is:

```text
Research methodology
        ≠
Application authentication
```

Authentication/RBAC was added without altering the frozen research datasets, experimental models, or scoring methodology.

The final application therefore has authenticated role-specific workflows, while production-grade security hardening remains a separate future concern.

---

# 32. WDL-4 — Application Completion

WDL-4 added the supporting application features required to make the system a complete usable demonstration.

Implemented capabilities include:

### Application states

* loading states
* explicit empty states
* API-unavailable handling
* input validation
* 404 handling

### Export

* CSV export
* JSON export

### Printable reports

The CVE detail workflow can produce a print-oriented report containing:

1. authoritative NVD metadata
2. threat-intelligence context
3. explicit distinction between authoritative information and predictive inference
4. research-prototype disclaimer

### FAQ

A dedicated factual academic FAQ covers:

* system scope
* methodology
* A1
* B2
* B1 leakage
* temporal split
* prioritization
* asset tiers
* SHAP
* roles/access control

### Feedback

A prototype feedback workflow was added.

### Documentation Center

The application documentation center contains seven sections:

1. User & Triage Workflow Manual
2. REST API Endpoint Specification
3. System Requirements & Constraints
4. System Architecture & Data Layer
5. Setup & Installation Guide
6. Testing & Quality Assurance
7. Research Limitations & Future Scope

### Accessibility and responsive behavior

Accessibility focus indicators and mobile-responsive behavior were also implemented.



---

# 33. WDL-5 — Repository and Deployment Preparation

The final application/repository preparation phase focused on:

* repository audit
* removal of legacy prototype files
* environment-aware configuration
* deployment documentation
* configuration cleanup
* test verification
* README updates
* research-data immutability verification
* final commit and push to `main`

The phase explicitly stopped before actually performing public deployment.

The repository was therefore left **deployment-ready**, with manual Cloudflare Tunnel/DNS configuration remaining outside the completed phase. 

---

# 34. Final Verification

The final application was verified using automated tests.

The final documented test command produced:

```text
39 / 39 PASSED
```

consisting of:

```text
15 Auth & RBAC tests
9 REST API tests
15 ETL invariant tests
```

Local application verification also confirmed:

* FastAPI startup
* SPA loading
* `/health`
* authentication flows
* role-based behavior



The research data and model layers were separately checked to ensure application work had not modified the frozen research artifacts. 

---

# 35. Deployment Architecture Prepared

The project is prepared for **public demonstration deployment**, not presented as an enterprise production cybersecurity service.

The intended topology is:

```text
                Public Users
                     │
          ┌──────────┴──────────┐
          │                     │
          ▼                     ▼
vuln-triage.seucra.tech   vuln-triage-api.seucra.tech
       Frontend                  FastAPI
          │                     │
          └──────────┬──────────┘
                     ▼
             Cloudflare Tunnel
                     │
                     ▼
               Local Backend
```

The deployment documentation explicitly identifies the system as a:

> Research Prototype / Public Demonstration Deployment

rather than an enterprise production service. 

The final repository configuration includes environment-aware frontend/backend configuration and CORS preparation for the demonstration domains. 

---

# 36. Repository Finalization

The final repository state was committed and pushed to:

```text
main
```

with commit:

```text
6d56880
```

and message:

```text
chore: finalize application, documentation, and configuration for public demonstration deployment
```

The push completed successfully. 

The project therefore reached a state in which:

```text
Research
    +
Backend
    +
Frontend
    +
Authentication/RBAC
    +
Documentation
    +
Testing
    +
Deployment Preparation
```

are all represented in the repository.

---

# 37. Final Architecture

The complete system can now be represented as:

```text
                         ┌──────────────────────┐
                         │     Raw Sources      │
                         │ NVD / CISA / EPSS    │
                         │ CPE / CWE / Vendor   │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Deterministic ETL    │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │ Frozen Canonical     │
                         │ Parquet Dataset      │
                         └──────────┬───────────┘
                                    │
                  ┌─────────────────┴─────────────────┐
                  │                                   │
                  ▼                                   ▼
        ┌───────────────────┐             ┌───────────────────┐
        │ Research Models   │             │ Decision Support  │
        │                   │             │                   │
        │ A1 XGBoost        │             │ Linear Baseline   │
        │ B2 XGBoost        │             │ Nonlinear Surface │
        │ B1 Sensitivity    │             │ Asset Tiers       │
        │ SHAP              │             └─────────┬─────────┘
        └─────────┬─────────┘                       │
                  └─────────────────┬───────────────┘
                                    ▼
                         ┌──────────────────────┐
                         │    FastAPI Backend   │
                         │                      │
                         │ Authentication/RBAC  │
                         │ Vulnerability Data   │
                         │ Prediction           │
                         │ Prioritization       │
                         │ Explanation          │
                         │ Provenance           │
                         └──────────┬───────────┘
                                    │
                                    ▼
                         ┌──────────────────────┐
                         │    Frontend SPA      │
                         │                      │
                         │ Analyst              │
                         │ Researcher           │
                         │ Administrator        │
                         │ Explorer             │
                         │ Predictions          │
                         │ Prioritization       │
                         │ SHAP                 │
                         │ Documentation        │
                         │ FAQ / Feedback       │
                         └──────────────────────┘
```

---

# 38. Major Decisions — Final Record

| Decision                                         | Reason                                                                       |
| ------------------------------------------------ | ---------------------------------------------------------------------------- |
| Rebuild original implementation                  | Original implementation was not sufficiently rigorous                        |
| Verify raw data before modeling                  | Establish trustworthy research inputs                                        |
| Deterministic ETL                                | Reproducibility                                                              |
| Freeze canonical dataset                         | Prevent experiment/application mutation                                      |
| Canonical all-column fingerprinting              | Resolve duplicate-key ordering ambiguity                                     |
| Temporal train/validation/test split             | Prevent chronological leakage                                                |
| B2 without EPSS                                  | Preserve legitimate publication-time prediction                              |
| B1 with retrospective EPSS                       | Quantify leakage effect                                                      |
| PR-AUC for KEV                                   | Handle extreme class imbalance                                               |
| Ridge/Logistic baselines                         | Establish interpretable baselines                                            |
| XGBoost candidates                               | Investigate nonlinear predictive structure                                   |
| C1 as controlled simulation                      | Avoid circular learning against synthetic priorities                         |
| Controlled asset tiers                           | Study contextual effects without claiming enterprise ground truth            |
| SHAP post-hoc explanations                       | More rigorous model attribution                                              |
| Separate current EPSS from historical prediction | Prevent misleading interpretation                                            |
| DuckDB + immutable Parquet                       | Analytical querying without mutable research-state duplication               |
| Backend as source of truth                       | Prevent UI/research divergence                                               |
| API-level temporal enforcement                   | Make methodological constraints enforceable                                  |
| Provenance endpoint                              | Preserve research transparency                                               |
| Frontend after research/backend                  | Prevent UI requirements from determining methodology                         |
| Role-specific dashboards                         | Support distinct analyst/researcher/admin workflows                          |
| Authentication/RBAC                              | Secure and separate application workflows                                    |
| WDL-4 application hardening                      | Make the prototype usable and demonstrable                                   |
| Deployment preparation                           | Enable public demonstration without claiming enterprise production readiness |

---

# 39. Central Research Story

The entire project can now be summarized through four primary research findings.

### Finding 1 — Nonlinear modeling provides measurable value

A1:

```text
Ridge MAE       = 1.0954
XGBoost MAE     = 0.9750
```

The nonlinear model improved upon the linear baseline.

### Finding 2 — Publication-time KEV prediction contains signal but remains difficult

B2:

```text
PR-AUC = 0.02884
Precision@500 = 6.40%
Recall@500 = 10.88%
```

The model performs above the random baseline but does not make KEV prediction trivial.

### Finding 3 — Retrospective information can dramatically inflate apparent performance

B1:

```text
B2 PR-AUC = 0.02884
B1 PR-AUC = 0.33153
```

This produced approximately:

```text
11.49×
```

the B2 PR-AUC.

The leakage experiment therefore became one of the project's strongest methodological findings.

### Finding 4 — Global ranking correlation does not imply triage-queue agreement

C1:

```text
Spearman ρ = 0.9962
```

but:

```text
Top-100 Jaccard = 0.005
```

Thus, two rankings can look nearly identical globally while producing substantially different highest-priority remediation candidates.

---

# 40. What the Project Deliberately Does Not Claim

The project deliberately does **not** claim that:

* XGBoost produces authoritative CVSS scores.
* predicted CVSS replaces authoritative CVSS.
* KEV prediction is equivalent to exploitation prediction.
* the retrospective B1 result represents valid historical deployment performance.
* EPSS was historically available at publication time.
* synthetic asset tiers represent real enterprise assets.
* the nonlinear C1 surface is proven superior in real organizations.
* SHAP establishes causality.
* model ranking guarantees exploitation.
* the system replaces human security analysts.
* the project has validated remediation outcomes against real enterprise ground truth.
* the current demonstration deployment constitutes an enterprise production cybersecurity service.

These boundaries are part of the research design, not details to hide. The project explicitly preserves these distinctions. 

---

# 41. Current Project State

The project has progressed from an initial dashboard implementation to a research-backed application system.

The completed layers are:

```text
Phase 0    Raw Data Verification       COMPLETE
Phase 1    Deterministic ETL           COMPLETE
Phase 1.1  Reproducibility/Frozen Data COMPLETE
Phase 2    Experimental Protocol       COMPLETE
Phase 3    Research Experiments        COMPLETE
Phase 4    Backend/API                 COMPLETE
Phase 5    Frontend/UI                 COMPLETE
WDL-3      Role Dashboards/RBAC        COMPLETE
WDL-4      Application Features        COMPLETE
WDL-5      Repository/Deployment Prep  COMPLETE
```

The project is therefore no longer accurately described as merely a vulnerability dashboard.

It is a:

```text
Canonical research dataset
        +
Reproducible ETL
        +
Temporal ML experiments
        +
Leakage analysis
        +
Decision-support simulation
        +
SHAP explainability
        +
FastAPI backend
        +
Authentication/RBAC
        +
Role-specific analyst/researcher/admin workflows
        +
Research provenance
        +
Tested frontend application
        +
Public-demonstration deployment preparation
```

---

# 42. Final Project Position

The project's strongest characteristic is not simply that it contains machine learning.

Its central contribution is the **discipline with which the different layers are separated**:

```text
Authoritative vulnerability data
              ≠
Machine-learning prediction
              ≠
Retrospective threat intelligence
              ≠
Controlled prioritization simulation
              ≠
Enterprise ground truth
              ≠
Human analyst decision
```

The architecture reflects the same principle:

```text
Immutable Research Data
        ↓
Validated Experiments
        ↓
Frozen Model Artifacts
        ↓
Backend Enforcement
        ↓
Application Workflows
```

The later application work adds usability, authentication, role-specific workflows, documentation, testing, and deployment preparation **without changing the underlying research boundary**.

That separation is the final architectural and methodological principle of the project.

