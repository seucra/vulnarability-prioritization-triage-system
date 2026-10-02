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

The final application provides:

* registration
* login
* logout
* JWT/token-based session handling
* authenticated `/auth/me` verification
* persisted frontend authentication state
* role-specific dashboards
* protected API requests
* role-based access control for Analyst, Researcher, and Administrator workflows

A later frontend verification pass identified three implementation issues:

1. asynchronous user hydration could cause an unauthenticated first-frame dashboard;
2. versioned ES-module imports could instantiate duplicate frontend `state` singletons;
3. prioritization and explainability were incorrectly classified as globally protected routes rather than neutral sandboxes requiring authentication at submission time.

These were corrected by synchronously hydrating `wdl_user` from `localStorage`, removing internal module version mismatches, centralizing `state.isAuthenticated()`, attaching bearer tokens through the API client, and moving authorization checks to the appropriate interaction boundary.

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

The final frontend was checked across desktop and mobile viewport sizes, including 320px, 375px, 390px, 430px, and 768px. Tables use constrained horizontal scrolling where necessary, technical identifiers/formulas wrap, and the mobile navigation collapses appropriately.

### Final application-state distinction

The frontend intentionally remains capable of rendering its public/static shell when the backend is unavailable. In that state, the public navigation remains available:

```text
Home
About
Docs
FAQ
Contact
```

This is **not remaining implementation work**. It is an intentional consequence of the decoupled static frontend architecture: backend-dependent dashboards, predictions, prioritization, authentication, and research workflows require the API, while public/static content remains renderable independently.



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


# 35. WDL-6 — Public Demonstration Deployment & Production Integration

WDL-6 completed the public-demonstration deployment architecture.

The final deployment deliberately uses a decoupled topology:

```text
Public Browser
      ↓
vuln-triage.seucra.tech
      ↓
GitHub Pages
      ↓
Static Frontend SPA
      ↓
vuln-triage-api.seucra.tech
      ↓
Cloudflare Tunnel
      ↓
localhost:5002
      ↓
FastAPI Backend
      ↓
Frozen Dataset + Serialized Research Models
```

The frontend is therefore publicly hosted through GitHub Pages, while the research backend continues to run on the local machine and is exposed for demonstration through Cloudflare Tunnel.

The deployment is explicitly classified as:

> **Research Prototype / Public Demonstration Deployment**

It is not presented as an enterprise production cybersecurity service.

### GitHub Pages

The frontend deployment includes:

* `frontend/CNAME`
* custom domain `vuln-triage.seucra.tech`
* GitHub Actions deployment workflow
* `frontend/` as the static deployment artifact
* exclusion of backend source, datasets, model binaries, and tests from the Pages artifact

### Backend Tunnel

The public backend endpoint is:

```text
vuln-triage-api.seucra.tech
```

and the tunnel forwards to:

```text
http://localhost:5002
```

The local FastAPI service is therefore not directly exposed as a public server; the Cloudflare Tunnel provides the public HTTPS edge.

### Environment-aware API configuration

The frontend distinguishes local development from the public deployment environment:

```text
Local:
http://localhost:5002/api/v1

Public:
https://vuln-triage-api.seucra.tech/api/v1
```

CORS configuration was updated to permit the demonstration frontend/backend origins.

### CI/CD integration

The GitHub Actions workflow validates the application and deploys the frontend to GitHub Pages on pushes to `main`.

The repository does not introduce an artificial dependency manifest merely to satisfy pip caching. The workflow instead installs the explicit CI dependencies required for the test suite.

### Deployment-related CI corrections

The deployment process exposed several real environment-specific issues.

#### Missing dependency manifest for pip cache

`actions/setup-python@v5` had initially been configured with pip caching, but the repository intentionally had no `requirements.txt` or `pyproject.toml`. The cache step therefore failed while attempting to resolve a cache key.

The fix was to remove the pip cache parameter and install the required CI dependencies explicitly.

#### Missing typing imports

The security module used `Dict`, `Any`, and `Optional` in runtime-evaluated annotations without importing them. Python 3.10 CI exposed the resulting `NameError`.

The fix was:

```python
from typing import Any, Dict, Optional
```

#### Missing serialized models in CI

The large Phase 3 model binaries are intentionally not committed to the repository. Consequently, CI environments can have no loaded model/vectorizer artifacts.

The explanation service initially attempted to call `.transform()` on a missing vectorizer. The service was corrected to raise the standard `ModelNotLoadedException`, producing HTTP 503 rather than an unhandled HTTP 500.

The RBAC test was correspondingly made environment-aware: it continues to verify researcher authorization while accepting either a successful explanation when artifacts exist or the expected 503 model-unavailable response when they do not.

These fixes preserved the research boundary and did not modify datasets, model definitions, scoring equations, or experimental results.

### Final public-demonstration verification

After CI stabilization, the actual deployed frontend was exercised with the tunneled backend rather than being treated as deployment-complete solely from local tests.

The verified system therefore consists of:

```text
GitHub Pages frontend
        +
Cloudflare-tunneled FastAPI backend
        +
Frozen research dataset
        +
Serialized Phase 3 models
```



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

# 37. Deployment Architecture

The project has reached a **public demonstration deployment**, not an enterprise production cybersecurity service.

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

The final repository configuration includes environment-aware frontend/backend configuration, GitHub Pages deployment, CORS configuration, and Cloudflare Tunnel integration for the demonstration domains. 

---

# 37. Repository Finalization

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

# 38. Final Architecture

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

# 39. Major Decisions — Final Record

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
| GitHub Pages + Cloudflare Tunnel                 | Decouple public static frontend from locally hosted research backend |
| JWT authentication + RBAC                        | Provide role-specific application workflows without changing research methodology |
| LocalStorage auth hydration                      | Prevent first-frame authentication state contradictions |
| Single frontend state singleton                  | Prevent divergent application state caused by duplicate ES-module instances |
| API-level bearer-token propagation               | Keep protected backend operations aligned with frontend session state |
| Missing-model 503 handling                       | Make deployment/CI artifact absence an explicit service-unavailable condition |


---

# 40. Central Research Story

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

# 41. What the Project Deliberately Does Not Claim

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

# 42. Current Project State

The project has progressed from an initial dashboard implementation to a research-backed application system.

The completed layers are:

```text
Phase 0    Raw Data Verification       COMPLETE
Phase 1    Deterministic ETL           COMPLETE
Phase 1.1  Reproducibility/Frozen Data COMPLETE
Phase 2    Experimental Protocol       COMPLETE
Phase 3    Research Experiments        COMPLETE
Phase 4    Backend/API                 COMPLETE
Phase 5    Frontend/UI Foundation          COMPLETE
WDL-3      Role Dashboards/RBAC             COMPLETE
WDL-4      Application Features             COMPLETE
WDL-5      Repository/Deployment Prep       COMPLETE
WDL-6      Public Demonstration Deployment  COMPLETE
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

# 43. Final Project Position

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

# Vulnerability Prioritization & Triage System
## Deep Understanding & Reconstruction Guide

**Repository:** `seucra/vulnarability-prioritization-triage-system`  
**Purpose:** Personal technical understanding, reconstruction, viva preparation, and formal project defense.  
**Status:** Final application state after research, backend, frontend, authentication, deployment, and E2E verification.

---

# 0. The Project in One Sentence

The project investigates **risk-based vulnerability prioritization under realistic information-availability constraints**, using temporally disciplined machine-learning experiments and a controlled nonlinear prioritization surface, and exposes the resulting research capabilities through a web application.

The website is therefore the **application layer of a research system**, not the intellectual core of the project.

The central chain is:

```text
Research Question
       ↓
Methodological Definition
       ↓
Information Availability Rule
       ↓
Temporal Experiment
       ↓
Model
       ↓
Evaluation
       ↓
Interpretation
       ↓
Application
```

---

# 1. What Problem Is Being Studied?

A vulnerability-management system may contain thousands of vulnerabilities, but an organization cannot remediate all of them simultaneously.

The practical problem is therefore:

> Given limited remediation capacity, which vulnerabilities should receive attention first?

A simplistic answer might use only CVSS severity.

This project investigates whether prioritization can be improved by considering:

- vulnerability characteristics,
- exploitation-related signals,
- asset criticality,
- nonlinear interactions between those signals,
- and, crucially, **what information was actually available at the time a prediction would have been made**.

The project therefore separates three related but different tasks:

```text
A1 → estimate severity
B2 → estimate future KEV inclusion
C1 → study prioritization/ranking behavior
```

They are not the same prediction problem.

---

# 2. Core Security Concepts

## 2.1 CVE

A CVE is a standardized identifier assigned to a publicly disclosed vulnerability.

Example:

```text
CVE-2021-44228
```

The CVE identifies the vulnerability.

It does not itself mean:

- severity,
- exploit probability,
- business impact,
- or remediation priority.

---

## 2.2 CVSS

CVSS is the **Common Vulnerability Scoring System**, a standardized framework for expressing vulnerability severity.

This project uses CVSS v3.1 base scores.

A CVSS score represents severity characteristics such as attack vector, attack complexity, privileges required, user interaction, and impact characteristics.

Important distinction:

```text
CVE = identifier
CVSS = severity assessment
```

The project distinguishes an authoritative CVSS score from the A1 model's predicted CVSS score.

```text
Authoritative CVSS v3.1
        ≠
Predicted CVSS v3.1 (A1)
```

---

## 2.3 EPSS

EPSS is an exploit prediction signal.

The important research issue is **time alignment**.

A modern EPSS snapshot may contain information that was not available when an old vulnerability was published.

Therefore:

```text
historical prediction
        +
future EPSS snapshot
        =
temporal leakage
```

This is why the primary B2 experiment excludes the retrospective EPSS snapshot.

---

## 2.4 KEV

KEV refers to the CISA Known Exploited Vulnerabilities catalog.

In this project, KEV membership is used as the target/proxy for a vulnerability being known to have been exploited.

It is important not to say:

> KEV = exploitation probability.

KEV is a catalog of known exploited vulnerabilities. It is not a complete ground truth for every real-world exploitation event.

---

# 3. The Central Research Problem: Time

Cybersecurity data changes over time.

Consider a vulnerability published in 2015.

If a model predicting something at publication time is given an EPSS snapshot from 2026, it is being given information that did not exist at the prediction point.

That makes the historical evaluation unrealistic.

The project therefore uses a fixed temporal partition:

```text
TRAIN       2002–2022
VALIDATION  2023–2024
TEST        2025–2026
```

The test partition is kept untouched during model selection.

Final configurations are selected using training and validation data, then refit on:

```text
TRAIN + VALIDATION = 2002–2024
```

and evaluated once on:

```text
TEST = 2025–2026
```

This preserves chronological prediction direction.

---

# 4. Why Random Train/Test Splitting Is Wrong Here

A random split can place older and newer observations in both training and test sets.

That can allow the model-development process to indirectly learn patterns from future distributions.

For ordinary IID datasets this may sometimes be reasonable.

For evolving cybersecurity data, chronology matters.

The project therefore asks:

> Could this information legitimately have existed at the prediction point?

That question is more important than simply asking whether a column exists in the dataset.

---

# 5. The Frozen Dataset

The project uses a canonical processed dataset generated from vulnerability data sources including:

- NVD,
- CISA KEV,
- EPSS.

The processed representation is stored as Parquet.

The canonical tables include:

```text
vulnerabilities.parquet
cve_cwe.parquet
cve_cpe.parquet
epss.parquet
kev.parquet
vendor_statements.parquet
```

The Phase 1 canonical dataset contains:

```text
366,547 vulnerabilities
430,273 CWE relationships
3,133,450 CPE relationships
348,900 EPSS records
1,647 KEV records
1,486 vendor statements
```

The dataset is treated as frozen research input.

The application must not silently rewrite it.

---

# 6. Why Freeze the Dataset?

Without freezing the input:

```text
dataset changes
     ↓
models/results may change
     ↓
old research numbers become unreproducible
```

Freezing establishes a boundary:

```text
Research Dataset
      ↓
Immutable
      ↓
Experiments
      ↓
Frozen Results
      ↓
Application
```

Later application development should not alter the historical experiment.

---

# 7. Deterministic ETL

The raw sources are transformed into a canonical dataset through deterministic ETL.

Conceptually:

```text
Raw NVD / KEV / EPSS
        ↓
Parsing
        ↓
Normalization
        ↓
Validation
        ↓
Joins
        ↓
Canonical Parquet
```

The ETL was explicitly tested for reproducibility.

Independent clean rebuilds produced:

```text
0 differing logical rows
```

across all six processed tables.

The project also verified binary Parquet equality for the rebuilds.

---

# 8. Why Fingerprinting Required Canonicalization

An early fingerprinting approach sorted child tables using incomplete key subsets.

That was insufficient because some tables contain duplicate values in those key subsets.

For example, multiple rows may share:

```text
(cve_id, cpe23_uri)
```

while differing in other columns.

Therefore sorting only on those columns can leave duplicate rows in different relative orders.

The final fingerprinting process uses:

1. alphabetically sorted columns,
2. complete multi-column sorting,
3. normalized null representation,
4. deterministic float/timestamp serialization,
5. direct SHA-256 hashing of canonical bytes.

This distinguishes:

```text
same logical data
```

from:

```text
same arbitrary row ordering
```

and makes logical reproducibility independently verifiable.

---

# 9. Why Parquet?

Parquet is a columnar analytical storage format.

It fits this project because the research dataset is:

```text
large
analytical
mostly immutable
```

The application does not need a mutable transactional database for the core research data.

---

# 10. Why DuckDB?

DuckDB can query Parquet directly.

Instead of:

```text
load entire dataset
        ↓
Python memory
        ↓
filter
```

the application can conceptually do:

```text
Parquet
   ↓
DuckDB query
   ↓
required rows/columns
   ↓
FastAPI
```

This keeps the research dataset immutable while allowing the application to search and filter it.

A future production architecture could use another database, but DuckDB + Parquet is appropriate for this research prototype.

---

# 11. EXP-A1 — CVSS Estimation

## Research Question

> Can vulnerability severity be estimated before formal CVSS scoring using information available from the vulnerability record?

The target is:

```text
cvss_v31_base_score
```

This is a regression problem because the target is continuous.

---

# 12. Regression

Regression means predicting a continuous numerical value.

For A1:

```text
input vulnerability information
        ↓
model
        ↓
predicted CVSS score
```

Example conceptually:

```text
Actual CVSS = 8.2
Predicted CVSS = 7.4
```

The difference contributes to regression error.

---

# 13. A1 Features

The A1 feature pipeline uses information including:

- TF-IDF text features from vulnerability descriptions,
- CWE information,
- CPE/platform counts,
- publication metadata.

The text representation uses TF-IDF with unigram and bigram features.

---

# 14. TF-IDF

TF-IDF represents text numerically based on how important terms are within documents relative to the corpus.

The intuition is:

```text
common word → less discriminative
distinctive word → potentially more informative
```

The model can therefore receive numerical representations of vulnerability descriptions.

---

# 15. What Is an N-Gram?

An n-gram is a contiguous sequence of n tokens.

Examples:

```text
unigram:
"authentication"

bigram:
"SQL injection"
```

The use of bigrams matters because cybersecurity phrases often have meaning as a unit.

For example:

```text
SQL injection
remote code execution
privilege escalation
```

can carry more information together than their individual words.

---

# 16. Why Ridge Regression?

Ridge provides a linear baseline.

Conceptually:

```text
prediction =
w1(feature1)
+ w2(feature2)
+ ...
+ intercept
```

Ridge adds regularization to reduce excessive coefficient magnitude and help with high-dimensional correlated features.

It gives the project a baseline against which the nonlinear model can be compared.

---

# 17. Why XGBoost?

XGBoost is a gradient-boosted tree framework.

The project hypothesis concerns nonlinear relationships and interactions.

Therefore:

```text
Ridge
→ linear baseline

XGBoost
→ nonlinear model
```

The point is not simply:

> XGBoost is better.

The actual experimental question is whether a nonlinear model captures predictive structure that a linear baseline cannot.

---

# 18. A1 Results

Final test results:

| Model | Test MAE | Test RMSE | Test R² |
|---|---:|---:|---:|
| Ridge | 1.0954 | 1.4089 | 0.3194 |
| XGBoost | **0.9750** | **1.3059** | **0.4153** |

XGBoost reduced MAE by:

```text
0.1204 CVSS points
```

or approximately:

```text
10.99% relative error reduction
```

The result supports the existence of predictive signal, but does not mean the model can replace authoritative CVSS scoring.

---

# 19. EXP-B2 — Future KEV Prediction

## Research Question

> Can information available at publication time predict future KEV inclusion?

Target:

```text
is_kev
```

This is a classification problem.

---

# 20. Classification

Classification predicts a class or probability.

Here:

```text
publication-time information
        ↓
model
        ↓
probability of future KEV inclusion
```

The output is not:

> "This vulnerability will definitely be exploited."

It is a model probability associated with the defined KEV target.

---

# 21. B2 Feature Boundary

The primary B2 experiment excludes:

```text
EPSS snapshot
date_added
known_ransomware_campaign_use
last_modified
```

It also excludes post-publication CVSS components from the publication-time prediction interface.

The important principle is:

> The prediction must use only information legitimately available at the defined prediction point.

---

# 22. Logistic Regression

Logistic regression provides the linear classification baseline.

It estimates class probability through a logistic transformation of a weighted feature combination.

It is appropriate here as an interpretable baseline.

---

# 23. XGBoost Classifier

The nonlinear B2 model is XGBoost.

Because KEV membership is highly imbalanced, class weighting / `scale_pos_weight` is used.

The model is evaluated using metrics appropriate to rare positive events.

---

# 24. Why Accuracy Is Bad Here

Suppose almost every vulnerability is non-KEV.

A model predicting:

```text
NOT KEV
```

for everything could obtain high accuracy while being useless for finding the vulnerabilities we care about.

Therefore the project emphasizes:

```text
PR-AUC
Precision
Recall
Precision@500
```

rather than accuracy alone.

---

# 25. Precision

Precision answers:

> Of the vulnerabilities predicted as positive, how many were actually positive?

```text
Precision =
True Positives
----------------------------
True Positives + False Positives
```

---

# 26. Recall

Recall answers:

> Of all actual positive vulnerabilities, how many did the model find?

```text
Recall =
True Positives
----------------------------
True Positives + False Negatives
```

---

# 27. PR-AUC

PR-AUC is the area under the precision-recall curve.

It is particularly useful for highly imbalanced classification because it focuses on the positive class and the precision/recall tradeoff.

---

# 28. B2 Results

Test results:

| Metric | Logistic | XGBoost |
|---|---:|---:|
| PR-AUC | 0.02077 | **0.02884** |
| ROC-AUC | 0.85857 | 0.81324 |
| Precision@500 | 3.60% | **6.40%** |
| Recall@500 | — | **10.88%** |

Random baseline PR-AUC:

```text
0.00322
```

XGBoost achieved approximately:

```text
8.96× random Precision@500
```

The result indicates measurable predictive signal, but the absolute performance remains limited.

That limitation matters.

---

# 29. EXP-B1 — Retrospective EPSS Sensitivity

B1 deliberately introduces the later EPSS snapshot.

It is not the primary deployment experiment.

It exists to answer:

> What happens to historical evaluation if future/static EPSS information is accidentally allowed into the feature set?

This makes B1 a methodological demonstration.

---

# 30. B1 vs B2

Primary B2:

```text
XGBoost PR-AUC = 0.02884
```

Retrospective B1:

```text
XGBoost PR-AUC = 0.33153
```

The retrospective result is approximately:

```text
11.49×
```

the B2 PR-AUC.

The difference is enormous.

The conclusion is not:

> EPSS makes the model amazing.

The conclusion is:

> A later EPSS snapshot can create severe retrospective inflation when used as though it were available at historical prediction time.

This is why temporal feature boundaries are a methodological requirement rather than a documentation preference.

---

# 31. EXP-C1 — Prioritization

Prediction and prioritization are different.

A prediction model asks something like:

```text
What is the probability of future KEV inclusion?
```

A prioritization system asks:

```text
Given vulnerability signals and asset context,
what should be remediated first?
```

C1 studies this second problem.

---

# 32. Linear Baseline

The project-controlled linear baseline is:

```text
S_linear =
0.25x1 +
0.25x2 +
0.25x3 +
0.25x4
```

The equal weights are explicitly a project-controlled baseline.

They should not be described as industry-standard weights.

---

# 33. Nonlinear Surface

The nonlinear surface is:

```text
S_nonlinear =
x4 · [
  1 -
  (1-x1)^(1+1.0x3)
  ·
  (1-x2)^(1+1.5x3)
]
```

with:

```text
α = 1.0
β = 1.5
```

The important concept is interaction.

The effect of one factor can depend on another factor.

---

# 34. What Interaction Means

In an additive model:

```text
effect of x1
```

is largely independent of the other terms.

In an interaction model:

```text
effect of x1
```

can depend on:

```text
x3
```

and similarly for other signals.

This is the mathematical motivation for the nonlinear surface.

---

# 35. Asset Criticality

Asset criticality is represented experimentally as:

```text
Tier 1 = 0.25
Tier 2 = 0.50
Tier 3 = 0.75
Tier 4 = 1.00
```

The same vulnerability can therefore receive a different prioritization depending on the controlled asset context.

This is closer to risk-based prioritization than treating every vulnerability as affecting an identical environment.

---

# 36. Why Synthetic Asset Tiers?

The project does not have real enterprise asset/remediation data.

Therefore it must not claim:

> Tier 4 corresponds to actual enterprise risk.

The correct statement is:

> Asset criticality was controlled as an experimental variable.

This lets the project investigate mathematical behavior without fabricating enterprise evidence.

---

# 37. C1 Results

Across the intersected population:

```text
Spearman ρ = 0.9962
Kendall τ = 0.9356
```

Yet:

```text
Top-100 Jaccard overlap = 0.005
Top-1000 Jaccard overlap = 0.182
```

This is one of the most important results to understand.

---

# 38. Why High Correlation and Low Top-100 Overlap Can Coexist

Correlation measures the overall ranking relationship.

Jaccard measures set overlap.

For two Top-100 sets:

```text
J(A,B) =
|A ∩ B|
---------
|A ∪ B|
```

Two systems can therefore have:

```text
very similar global ordering
```

while selecting:

```text
very different specific vulnerabilities
```

for the highest-priority remediation queue.

This matters because a security team may care much more about the first 100 vulnerabilities than about the exact ordering of hundreds of thousands of low-priority records.

---

# 39. SHAP

SHAP is a post-hoc feature attribution method based on Shapley-value ideas.

The conceptual question is:

> How much did each feature contribute to this particular prediction?

Conceptually:

```text
baseline prediction
        +
feature contributions
        =
model prediction
```

The project uses SHAP after the final tree models are frozen.

---

# 40. SHAP Is Not Causality

If SHAP says:

```text
feature X → +0.8
```

the correct interpretation is:

> Feature X contributed positively to the model prediction.

It does **not** prove:

> Feature X caused the real-world vulnerability outcome.

This distinction must be maintained in both documentation and presentation.

---

# 41. Why the Original LOO Explainer Was Replaced

The initial implementation used Leave-One-Out token perturbation.

Example:

```text
"remote unauthenticated SQL injection"
```

Remove:

```text
SQL
```

and measure the prediction change.

The problem is that the actual model representation contained:

```text
unigrams + bigrams
```

so:

```text
SQL injection
```

could itself be an important feature.

Removing one token can therefore destroy a meaningful bigram and produce an attribution that does not correspond cleanly to the actual feature representation.

The final system moved to SHAP for the tree models.

---

# 42. Backend Architecture

The backend turns research artifacts into a usable application.

Conceptually:

```text
HTTP request
      ↓
FastAPI
      ↓
API router
      ↓
service layer
      ↓
data / model / scoring layer
      ↓
response
```

The major responsibilities are separated rather than placing all logic inside route handlers.

---

# 43. Vulnerability Service

Responsible for:

- search,
- filtering,
- pagination,
- vulnerability details.

It queries the frozen processed dataset.

---

# 44. Inference Service

Responsible for loading:

```text
A1 XGBoost
B2 XGBoost
```

and their preprocessing/vectorizers.

This keeps ML implementation details out of the HTTP endpoint layer.

The model artifacts are reconstructed/serialized from the frozen Phase 3 configuration rather than changing the Phase 3 results.

---

# 45. Scoring Service

Responsible for:

```text
Linear baseline
Nonlinear surface
Asset tiers
```

The mathematical logic therefore remains separate from HTTP request handling.

---

# 46. Explanation Service

Responsible for SHAP explanations and feature contributions.

The architectural distinction is:

```text
API
≠
SHAP implementation
```

This makes the explanation logic independently testable.

---

# 47. Provenance Service

Research systems need to answer:

> Where did this number come from?

The provenance layer exposes information such as:

- dataset state,
- model version,
- experiment,
- temporal boundaries,
- EPSS snapshot,
- limitations.

This prevents the frontend from becoming an independent source of research truth.

---

# 48. API Research Boundary

A particularly important rule is:

> The frontend cannot be trusted to enforce research constraints.

For example, a frontend can display:

```text
"Do not provide EPSS to B2."
```

but that is not a methodological safeguard.

The backend independently validates the request.

Forbidden or invalid requests are rejected at the API boundary.

This turns a documented rule into an enforceable rule.

---

# 49. Authentication and RBAC

The final web application includes demonstration-level authentication.

The intended flow is:

```text
Register
   ↓
Login
   ↓
Authenticated session
   ↓
Role-specific access
   ↓
Application features
   ↓
Logout
```

The roles are:

```text
Security Analyst
Researcher
Administrator
```

Role permissions are enforced by the backend.

Authentication is a **web-application feature**, not a research contribution.

It should not be presented as enterprise-grade identity infrastructure.

---

# 50. Authentication State

The frontend maintains:

```text
wdl_auth_token
wdl_user
```

in local storage.

The purpose is to prevent the UI from forgetting the session on refresh.

At startup:

```text
localStorage
     ↓
synchronous state hydration
     ↓
initial rendering
```

Then the frontend performs server verification through:

```text
/auth/me
```

If the token is invalid or expired:

```text
clear credentials
     ↓
clear current user
     ↓
redirect protected application routes
```

---

# 51. The Authentication Hydration Bug

An important implementation bug occurred during E2E verification.

Initially:

```text
token persisted
user only in memory
```

After page refresh:

```text
token exists
currentUser = null
```

The dashboard therefore briefly behaved as though the user were unauthenticated.

The fix persisted the user state and hydrated it synchronously before the first meaningful render.

This is a useful example of why authentication is both:

```text
server state
```

and:

```text
client application state
```

---

# 52. The Duplicate Module Singleton Bug

Another subtle frontend issue occurred because:

```text
app.js
```

imported:

```text
./state.js?v=3
```

while other modules imported:

```text
../state.js
```

The browser treated the different module URLs as separate module identities.

That produced two `AppState` instances.

Conceptually:

```text
Router → State A

Login → State B
```

Login could therefore update one state while the router observed another.

Removing version query parameters from internal module imports restored a single shared state singleton.

This is a frontend module-system issue, not a backend authentication issue.

---

# 53. Route Authorization

The final application distinguishes between:

```text
authentication-required application features
```

and:

```text
neutral/public sandbox views
```

Unauthenticated users attempting a protected application route are redirected appropriately.

For neutral sandbox functionality such as prioritization/explanation initial states, the UI can render the controls without immediately forcing a login.

When a protected operation is attempted, the UI can display an inline sign-in requirement.

The backend remains authoritative.

---

# 54. Bearer Token Propagation

The centralized API client attaches:

```text
Authorization: Bearer <token>
```

when an authenticated session exists.

This avoids every individual frontend component having to implement authorization-header logic independently.

---

# 55. Final Frontend Architecture

The frontend is a static SPA.

Major areas include:

```text
Home
About
Dashboard
Vulnerability Explorer
Predictions
Prioritization
Explainability
Provenance
FAQ
Contact
Documentation
Profile
Admin
Login
Register
```

The frontend is intentionally not responsible for research calculations.

It is the human interaction layer.

---

# 56. The Frontend's Job

The application lets a user:

```text
find vulnerability
       ↓
inspect vulnerability
       ↓
understand authoritative metadata
       ↓
run prediction
       ↓
evaluate asset context
       ↓
compare prioritization
       ↓
inspect SHAP explanation
       ↓
inspect provenance
```

The frontend does not redefine the underlying research.

---

# 56A. Layer Responsibilities and Boundaries

A useful way to understand the entire system is to ask what each layer is responsible for—and what it must not decide.

```text
Dataset Layer
    → stores the canonical research data

Experiment Layer
    → defines scientific methodology and evaluation

Model Layer
    → produces predictions from defined inputs

Scoring Layer
    → computes the controlled prioritization formulations

Backend/API Layer
    → exposes research capabilities and enforces application/research boundaries

Authentication/RBAC Layer
    → controls application access

Frontend Layer
    → presents the system and provides user interaction

Deployment Layer
    → makes the application publicly accessible
````

The important architectural principle is:

> Application layers expose and enforce the research; they do not redefine the research.

For example:

* The frontend must not redefine the B2 feature boundary.
* Authentication must not alter model methodology.
* The API must not silently change experiment formulas.
* The deployment layer must not modify research artifacts.
* The prioritization UI must not turn synthetic asset tiers into claims about real enterprise risk.

This separation is what allows the final web application to remain an application layer over a frozen research system rather than becoming a new source of research truth.

---

# 57. Why the Frontend Came Last

The project deliberately followed:

```text
data
 ↓
research
 ↓
models
 ↓
backend
 ↓
UI
```

rather than:

```text
pretty dashboard
 ↓
invent requirements
 ↓
build ML around dashboard assumptions
```

This matters because the application should expose validated research capabilities.

The UI should not determine what the research means.

---

# 58. Supporting Web Features

The final application includes:

- loading states,
- error states,
- empty states,
- CSV export,
- JSON export,
- printable vulnerability reports,
- FAQ,
- contact/feedback prototype,
- documentation center,
- keyboard focus indicators,
- responsive layouts.

The documentation center covers:

1. user/triage workflow,
2. REST API,
3. system requirements,
4. architecture/data layer,
5. setup,
6. testing,
7. limitations/future scope.

---

# 59. Responsive Behavior

The frontend was checked across small viewport sizes including:

```text
320px
375px
390px
430px
768px
```

The application uses:

- responsive layout rules,
- mobile navigation,
- constrained table scrolling,
- wrapping for technical strings,
- visible keyboard focus states.

Mobile usability is therefore not a remaining implementation task.

---

# 60. Deployment Architecture

The final public demonstration uses a decoupled deployment:

```text
Browser
   │
   ├── https://vuln-triage.seucra.tech
   │          ↓
   │     GitHub Pages
   │          ↓
   │       Frontend
   │
   └── https://vuln-triage-api.seucra.tech
              ↓
        Cloudflare Tunnel
              ↓
        localhost:5002
              ↓
           FastAPI
              ↓
       Models + Parquet
```

The frontend is deployed through GitHub Pages.

The backend remains on the local machine and is exposed through the configured Cloudflare Tunnel.

This is explicitly a:

> Research Prototype / Public Demonstration Deployment

It is not an enterprise production deployment.

---

# 60A. Frontend Behavior When the Backend Is Unavailable

The public frontend is a static GitHub Pages application, while the research/application backend runs separately through the Cloudflare Tunnel.

Therefore, if the backend is unavailable, the frontend itself can still load.

In that state, the application intentionally falls back to its public/static navigation:

```text
Home
About
Docs
FAQ
Contact
```

Authenticated and backend-dependent functionality cannot operate without the API.

This is an expected consequence of the decoupled deployment architecture, not incomplete frontend implementation.

The distinction is:

```text
Frontend unavailable
    → deployment/frontend problem

Frontend available + backend unavailable
    → static public shell remains available
    → authenticated/research functionality unavailable
```

For the live demonstration, the backend and Cloudflare Tunnel must therefore be running so that the complete application workflow is available.

---

# 61. GitHub Pages Boundary

GitHub Pages serves the static frontend.

It does not contain:

- backend source,
- raw datasets,
- processed Parquet datasets,
- model binaries,
- local account database,
- backend test infrastructure.

The deployment therefore keeps the public static artifact separate from the research/backend runtime.

---

# 62. Backend Runtime

The local backend runs on:

```text
127.0.0.1:5002
```

The tunnel maps:

```text
vuln-triage-api.seucra.tech
        ↓
localhost:5002
```

The backend loads the reconstructed Phase 3 models into memory.

A startup message confirming:

```text
EXP-A1 model & vectorizer loaded successfully.
EXP-B2 model & vectorizer loaded successfully.
```

means the model artifacts loaded successfully.

An XGBoost warning about the `.xgb` file being interpreted as UBJSON is a file-format compatibility warning, not evidence that model loading failed, provided the subsequent successful-load messages appear.

---

# 63. Port 5002 Already in Use

If Uvicorn reports:

```text
[Errno 98] address already in use
```

the usual meaning in this setup is that another backend process is already listening on port 5002.

It does **not** automatically mean the application is broken.

Check:

```bash
ss -ltnp | grep 5002
```

or:

```bash
lsof -i :5002
```

Then either reuse the running server or stop the old process before starting another.

This is an operational/process issue, not a research-model issue.

---

# 64. CI and Test Boundary

The final automated suite includes:

```text
tests/test_auth_rbac.py
tests/test_backend_api.py
tests/test_etl_invariants.py
```

Final verified result:

```text
39 / 39 PASSED
```

The tests cover:

- authentication,
- role-based authorization,
- REST API behavior,
- frozen dataset invariants.

The application also underwent browser E2E verification.

---

# 65. Missing Model Artifacts in CI

The model binaries are intentionally not committed to the repository.

Therefore CI environments may not have:

```text
model.xgb
vectorizer.joblib
```

The inference service handles absent model artifacts by treating the models as unavailable.

Explanation endpoints were additionally corrected to return the application's standard model-unavailable response rather than producing an unhandled:

```text
NoneType.transform()
```

error.

The relevant distinction is:

```text
RBAC works
+
model unavailable
```

rather than:

```text
RBAC failed
```

---

# 66. What the Project Actually Demonstrates

## A1

There is measurable signal for estimating CVSS v3.1 base scores from pre-scoring vulnerability information.

XGBoost outperformed the Ridge baseline on the held-out temporal test set.

## B2

There is measurable signal for predicting future KEV inclusion using publication-time information.

However, absolute performance is limited.

## B1

Using a later EPSS snapshot dramatically inflates historical performance.

This empirically demonstrates the importance of temporal feature boundaries.

## C1

A nonlinear context-aware prioritization surface behaves differently from an equal-weight additive baseline, especially near the top of the remediation queue.

---

# 67. What the Project Does NOT Demonstrate

It does not prove that:

- the model predicts all real exploitation,
- KEV membership equals exploitation probability,
- predicted CVSS should replace authoritative CVSS,
- the nonlinear prioritization surface is superior in real enterprises,
- synthetic asset tiers represent real organizational risk,
- SHAP establishes causality,
- the model guarantees better remediation outcomes,
- the system is an enterprise-grade cybersecurity platform.

These boundaries are part of the scientific result.

---

# 68. Main Limitations

### 1. KEV is imperfect ground truth

KEV membership does not capture every real-world exploitation event.

### 2. Synthetic asset context

C1 does not use real enterprise asset/remediation outcomes.

### 3. Limited B2 performance

The model has useful signal but is not a highly accurate exploitation predictor.

### 4. Historical snapshot

The research is tied to the frozen dataset snapshot.

### 5. No remediation outcome validation

The project does not observe whether organizations actually remediate better because of the prioritization model.

### 6. Distribution shift

Future vulnerability distributions can differ from the historical data.

### 7. Explainability limitations

SHAP explains model behavior, not reality.

---

# 69. Things That Are NOT Remaining Implementation Work

The following are completed and should not be treated as unfinished merely because they could be improved later:

- research dataset construction,
- deterministic ETL,
- dataset freezing,
- reproducibility verification,
- Phase 3 experiments,
- SHAP integration,
- FastAPI backend,
- API research-boundary enforcement,
- authentication,
- RBAC,
- frontend,
- responsive/mobile layout,
- loading/error/empty states,
- export functionality,
- printable reports,
- FAQ,
- contact prototype,
- documentation center,
- GitHub Pages deployment configuration,
- Cloudflare Tunnel configuration,
- production-domain frontend/API integration,
- GitHub Actions deployment,
- automated test suite,
- live tunneled E2E verification.

The fact that the system could be made prettier, deployed on cloud infrastructure, connected to a real identity provider, or backed by a production database does not make those things missing requirements of the current research prototype.

They are **future scope**, not incomplete current implementation.

---

# 70. If You Had to Rebuild the Project Yourself

The correct conceptual sequence is:

```text
1. Acquire and verify raw NVD/CISA/EPSS data

2. Build deterministic ETL

3. Validate schemas and joins

4. Generate canonical Parquet

5. Freeze dataset

6. Verify reproducibility

7. Define temporal train/validation/test split

8. Define feature availability at prediction time

9. Build A1 Ridge baseline

10. Build A1 XGBoost

11. Evaluate A1

12. Build B2 Logistic baseline

13. Build B2 XGBoost

14. Evaluate B2 with imbalance-aware metrics

15. Build B1 only as retrospective sensitivity analysis

16. Build controlled C1 prioritization experiment

17. Perform post-hoc SHAP

18. Freeze experimental outputs

19. Serialize final models

20. Build read-only backend

21. Expose prediction/scoring APIs

22. Enforce research boundaries at API level

23. Build authentication/RBAC application layer

24. Build frontend

25. Integrate frontend with backend

26. Verify authentication and authorization

27. Verify mobile/responsive behavior

28. Deploy static frontend

29. Tunnel/deploy backend

30. Perform end-to-end verification
```

This is the architecture, not merely a chronological list of coding tasks.

---

# 71. Complete Data Flow

You should eventually be able to draw this from memory:

```text
                 NVD
                  │
        ┌─────────┼─────────┐
        │         │         │
       CPE       CWE       CVSS
        │         │         │
        └─────────┼─────────┘
                  │
             Deterministic
                 ETL
                  │
       ┌──────────┴──────────┐
       │ Frozen Parquet Data │
       └──────────┬──────────┘
                  │
       ┌──────────┼──────────┐
       │          │          │
      A1         B2         C1
       │          │          │
    CVSS ML    KEV ML    Risk Surface
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
          Authentication
              + RBAC
                  │
                  ▼
              Frontend
                  │
                  ▼
                User
```

---

# 72. Complete Application Authentication Flow

You should also be able to explain:

```text
Register
   ↓
Backend validates request
   ↓
User created
   ↓
Login
   ↓
Backend authenticates
   ↓
Access token + user
   ↓
Frontend stores session
   ↓
State hydrates synchronously
   ↓
/auth/me verifies token
   ↓
Role-aware application
   ↓
API requests include Bearer token
   ↓
Backend checks authorization
   ↓
Response
   ↓
Logout
   ↓
Credentials removed
```

---

# 73. Complete Research Logic

The project can be reduced to four questions.

## Question A

> Can vulnerability severity be estimated before formal CVSS scoring?

Experiment:

```text
A1
```

Answer:

> Partially supported. Measurable predictive signal exists and XGBoost outperformed Ridge, but predictions are imperfect.

## Question B

> Can publication-time information predict future KEV inclusion?

Experiment:

```text
B2
```

Answer:

> Partially supported. Measurable signal exists, but absolute predictive performance remains limited.

## Question B2

> What happens when future EPSS information is allowed?

Experiment:

```text
B1
```

Answer:

> Apparent performance increases dramatically, demonstrating temporal leakage.

## Question C

> Does a nonlinear context-aware prioritization surface behave differently from a linear additive baseline?

Experiment:

```text
C1
```

Answer:

> Yes, particularly at the top of the remediation queue, but this does not prove superiority in real enterprise environments.

---

# 74. What You Should Be Able to Defend

### Why XGBoost?

Because the research hypothesis concerns nonlinear relationships and feature interactions, while Ridge and Logistic Regression provide linear baselines.

### Why temporal splitting?

Because vulnerability information evolves over time and random splitting can produce unrealistic historical evaluation.

### Why no EPSS in B2?

Because the available EPSS snapshot is later than many prediction points and would introduce temporal leakage.

### Why B1?

To empirically demonstrate the magnitude of retrospective leakage.

### Why PR-AUC?

Because KEV positives are extremely rare and accuracy can be misleading.

### Why C1?

Because prediction and prioritization are different problems; C1 studies interaction between vulnerability/threat signals and asset context.

### Why synthetic asset tiers?

Because real enterprise asset/remediation data are unavailable.

### Why SHAP?

To explain frozen nonlinear model predictions through post-hoc feature attribution.

### Why isn't SHAP causal?

Because model contribution does not establish real-world causation.

### Why freeze the dataset?

For reproducibility and to prevent later application changes from altering historical research results.

### Why DuckDB?

For efficient analytical querying of immutable Parquet.

### Why backend boundary enforcement?

Because a frontend restriction is not a reliable methodological control.

### Why frontend last?

Because validated research should determine the application, not the reverse.

---

# 75. Most Important Definitions

These should be explainable precisely.

### CVE

> Standardized vulnerability identifier.

### CVSS

> Standardized vulnerability severity scoring system.

### EPSS

> Exploit prediction signal that must be time-aligned when used for historical prediction.

### KEV

> CISA catalog of known exploited vulnerabilities; used here as a prediction target/proxy.

### Regression

> Prediction of a continuous numerical value.

### Classification

> Prediction of a class or probability.

### Temporal split

> Chronological partitioning of observations to preserve realistic prediction direction.

### Data leakage

> Information entering model development or evaluation that would not legitimately have been available at the prediction point.

### SHAP

> Post-hoc feature attribution method for explaining model predictions.

### Precision

> Fraction of predicted positives that are actually positive.

### Recall

> Fraction of actual positives that are successfully identified.

### PR-AUC

> Area under the precision-recall curve, particularly informative under class imbalance.

### Jaccard similarity

> Intersection divided by union of two sets.

---

# 76. Final Understanding Checklist

Before considering yourself fully prepared, you should eventually be able to answer these without relying on the project UI:

```text
□ What is a CVE?
□ What is CVSS?
□ What is EPSS?
□ What is KEV?
□ Why is KEV not identical to exploitation probability?
□ Regression vs classification?
□ What is Ridge regression?
□ What is Logistic regression?
□ What is a decision tree?
□ What is gradient boosting?
□ What is XGBoost?
□ What is TF-IDF?
□ What is an n-gram?
□ Why do bigrams matter?
□ What is temporal leakage?
□ Why is random splitting problematic?
□ Why is the test set untouched?
□ Why is PR-AUC preferred over accuracy?
□ Precision vs recall?
□ What is Precision@500?
□ What is MAE?
□ What is RMSE?
□ What is R²?
□ What is Spearman correlation?
□ What is Jaccard similarity?
□ What is nonlinear interaction?
□ What is the C1 equation?
□ Why synthetic asset tiers?
□ What is SHAP?
□ Why isn't SHAP causal?
□ Why freeze Parquet?
□ Why canonicalize fingerprints?
□ Why DuckDB?
□ What does FastAPI do?
□ What does the inference service do?
□ What does the scoring service do?
□ What does the explanation service do?
□ What does the provenance service do?
□ Why must B2 reject EPSS?
□ Why is B1 retrospective?
□ What is RBAC?
□ Why is frontend state persisted?
□ Why is /auth/me required?
□ What caused the duplicate state singleton bug?
□ How does Bearer-token propagation work?
□ Why did the UI come last?
□ What does the project actually demonstrate?
□ What does it explicitly NOT demonstrate?
□ What are the major limitations?
□ What would you change in a production system?
```

This checklist is the boundary between:

```text
having used the system
```

and:

```text
actually understanding the system
```

---

# 77. The Final Mental Model

Do not think:

> "I made a website with some ML."

Think:

```text
                    RESEARCH
                       │
             ┌─────────┴─────────┐
             │                   │
       What are we asking?   What is available?
             │                   │
             └─────────┬─────────┘
                       ↓
              METHODOLOGY
                       ↓
             TEMPORAL BOUNDARY
                       ↓
                 DATASET
                       ↓
                EXPERIMENTS
             ┌─────────┼─────────┐
             │         │         │
            A1        B2        C1
             │         │         │
             └─────────┼─────────┘
                       ↓
                  EVALUATION
                       ↓
                INTERPRETATION
                       ↓
                    SHAP
                       ↓
              FROZEN ARTIFACTS
                       ↓
                   FASTAPI
                       ↓
              AUTH + RBAC LAYER
                       ↓
                  FRONTEND
                       ↓
                PUBLIC DEMO
```

The application is the final representation of the research.

The research is not merely an excuse for the application.

---

# 78. The One Idea to Carry Into the Presentation

If everything else disappears, remember:

> **The project's central contribution is not simply applying XGBoost to vulnerabilities. It is demonstrating how vulnerability prioritization must respect information availability over time, while investigating nonlinear relationships between vulnerability characteristics, exploitation signals, and asset context.**

The B1/B2 comparison is particularly important because it demonstrates **why methodological discipline matters**, rather than merely reporting another model score.

And the final application demonstrates how those research artifacts can be turned into an inspectable, role-aware, explainable research prototype without changing the underlying frozen experiment.
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

### Live Demonstration Topology

The final demonstration environment is:

```text
Browser
   │
   ├── https://vuln-triage.seucra.tech
   │          │
   │          └── GitHub Pages
   │                └── Static frontend
   │
   └── HTTPS API requests
              │
              ▼
       vuln-triage-api.seucra.tech
              │
              ▼
        Cloudflare Tunnel
              │
              ▼
        localhost:5002
              │
              ▼
           FastAPI
              │
       ┌──────┴──────┐
       ▼             ▼
 Frozen Dataset   ML Artifacts
 ```

The frontend is therefore independently deployable, while the computational research backend remains local for the demonstration.

This is a:

> Research Prototype / Public Demonstration Deployment

---

# 40. Why This Deployment Is Acceptable for the Project

The goal is an academic demonstration, not a production SaaS platform.

The architecture allows:

- public static frontend access through GitHub Pages,
- public HTTPS API access through Cloudflare Tunnel,
- local model execution,
- local frozen-dataset access,
- no publication of research datasets or model binaries through GitHub Pages.

The backend remains physically local to the demonstration machine; Cloudflare Tunnel provides the public HTTPS route to it.

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
✓ GitHub Actions frontend deployment
✓ public custom-domain frontend deployment
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

### Important Deployment Observation

When the backend/API is unavailable, the GitHub Pages frontend itself can still load.

The application intentionally falls back to its public static navigation:

```text
Home
About
Docs
FAQ
Contact
```

This is not remaining implementation work.

It is an expected consequence of the decoupled architecture:

```text
GitHub Pages
    ↓
Static frontend
    ↓
Backend available?
    ├── YES → complete authenticated application
    └── NO  → public static shell/navigation
```

Backend-dependent functionality requires the FastAPI backend and Cloudflare Tunnel to be running.

During the live demonstration, therefore, the backend must be running on the local machine and exposed through:

```text
https://vuln-triage-api.seucra.tech
```

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
# Deliverable 2/4 — Future Scope

I found the previous `vuln2.md` and reviewed it against the completed project state. The core research directions are still valid, but several sections are now outdated because they describe things that have since been implemented—most notably authentication, application hardening, documentation, responsive UI, deployment preparation, and public demonstration.

So this should be treated as an **updated replacement for the old Future Scope**, not an append-only document. The old document correctly emphasized future research, but it mixed genuine future work with implementation work that is now complete. 

---

# Future Scope — Vulnerability Prioritization & Triage System

## 1. Purpose and Current Boundary

The current project establishes a completed research prototype combining:

* deterministic vulnerability-data preparation
* a frozen canonical dataset
* temporally separated ML experiments
* publication-time KEV prediction
* retrospective EPSS leakage analysis
* nonlinear contextual prioritization
* SHAP-based explainability
* FastAPI backend services
* authentication and role-based access control
* analyst, researcher, and administrator workflows
* research provenance
* responsive web UI
* automated verification
* public-demonstration deployment
* live tunneled public demonstration verified
* GitHub Pages frontend deployment

The current system should therefore be treated as the **baseline research platform** from which subsequent research can begin.

Future work should not simply add features to the existing application. Each major extension should first define:

1. the research question,
2. the information available at prediction time,
3. the ground truth,
4. the experimental protocol,
5. the evaluation methodology,
6. the reproducibility requirements.

This preserves the central methodological principle established by the project:

> **A new capability should become an implementation feature only after its research validity has been established.**

---

# 2. Research-Level Future Scope

## 2.1 Larger and More Recent Temporal Evaluation

The current experiments use:

```text
2002–2022 → Training
2023–2024 → Validation
2025–2026 → Test
```

A future study could extend the evaluation using genuinely later vulnerability data:

```text
Existing:
2002–2022 → Train
2023–2024 → Validation
2025–2026 → Test

Future:
2002–2024 → Train / Validation
2027+      → Future Holdout
```

This would test whether the observed results continue to hold for vulnerabilities that did not exist when the current models were developed.

A stronger approach would be **rolling temporal evaluation**, where multiple historical train/test windows are evaluated rather than relying on one fixed split.

This would make it possible to distinguish:

```text
one successful temporal split
```

from:

```text
consistent performance across time
```

The existing project already establishes temporal evaluation as a core methodological requirement. 

---

# 3. Time-Aligned EPSS Research

The B1 experiment demonstrated that using a later EPSS snapshot can dramatically inflate apparent historical performance.

The next logical experiment is therefore not simply:

> "Add EPSS."

It is:

> **Add only the EPSS information that would actually have existed at the prediction time.**

The future pipeline should look like:

```text
CVE published
      ↓
EPSS available at t₀
      ↓
Prediction
      ↓
Later KEV outcome
```

This would permit EPSS to become a legitimate predictive feature while preserving the temporal boundary.

The central research question becomes:

> How much predictive value does EPSS provide when the model receives only the EPSS information actually available at prediction time?

This would provide a much stronger result than the current retrospective B1 sensitivity experiment. 

---

# 4. Multi-Snapshot EPSS / Time-Series Modeling

A further extension would treat EPSS as a temporal signal rather than a single scalar.

Potential features include:

* initial EPSS
* maximum EPSS before KEV inclusion
* EPSS rate of change
* recent EPSS trend
* time since crossing a threshold
* EPSS volatility

Conceptually:

```text
EPSS(t₀)
   ↓
EPSS(t₁)
   ↓
EPSS(t₂)
   ↓
Temporal exploitation signal
```

The research question becomes whether **changes in exploitation likelihood** contain more useful information than a single EPSS observation.

This must remain strictly time-aligned; otherwise the same leakage problem demonstrated by B1 can reappear. 

---

# 5. Improved Exploitation Ground Truth

The current B2 target is:

```text
is_kev
```

KEV membership is useful, but it is not equivalent to every possible definition of exploitation.

Future research could distinguish:

```text
Observed exploitation
        ↓
CISA KEV inclusion
        ↓
Ransomware-associated exploitation
        ↓
Other exploitation characteristics
```

This could produce separate prediction tasks for:

* KEV inclusion
* confirmed exploitation
* ransomware-associated exploitation
* exploitation timing
* exploitation characteristics

The current terminology should remain unchanged unless stronger ground truth becomes available.

The important methodological improvement is to stop treating one catalog membership label as a universal proxy for exploitation. 

---

# 6. Real Enterprise Asset Context

C1 currently uses controlled asset criticality:

```text
Tier 1 → 0.25
Tier 2 → 0.50
Tier 3 → 0.75
Tier 4 → 1.00
```

These are deliberately synthetic decision-support inputs.

A major future research direction is to evaluate the prioritization methodology using anonymized real-world asset information such as:

* business criticality
* internet exposure
* asset ownership
* application importance
* network segmentation
* compensating controls
* vulnerability exposure
* patching constraints
* business impact

This would allow the nonlinear prioritization mechanism to be evaluated under actual operational conditions rather than controlled simulation.



---

# 7. Real Remediation Outcomes

The current project does not possess enterprise remediation ground truth.

A substantially stronger future study would collect outcomes such as:

* remediation completion time
* vulnerability acceptance
* patch priority
* incident association
* observed exploitation
* analyst priority decisions

The research question would then shift from:

```text
Can the model predict CVSS / KEV?
```

toward:

```text
Does the prioritization methodology improve actual remediation decisions?
```

This is an important distinction.

A model can perform well against CVSS or KEV while still failing to improve operational vulnerability management.

Real remediation outcomes would therefore provide a much stronger basis for evaluating the actual purpose of a triage system. 

---

# 8. Nonlinear Prioritization Research

The current C1 nonlinear surface is deliberately controlled:

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

[
\alpha=1.0,\qquad\beta=1.5
]

Future research could investigate:

* parameter sensitivity
* alternative interaction functions
* learned interaction parameters
* generalized additive models
* gradient-boosted ranking models
* pairwise ranking objectives
* learning-to-rank approaches

However, a critical methodological constraint remains:

> A future learned prioritization model needs an appropriate real-world target.

It should **not** simply learn to reproduce the existing project-controlled linear or nonlinear score.



---

# 9. Direct Learning-to-Rank Formulation

The current ML experiments predict:

```text
CVSS score
KEV membership
```

The actual operational question, however, is closer to:

> Which vulnerabilities should an analyst investigate first?

Future research could therefore formulate vulnerability triage directly as a ranking problem.

Possible approaches:

* pairwise ranking
* listwise ranking
* gradient-boosted ranking
* ranking-aware neural models

Potential evaluation metrics:

* Precision@K
* Recall@K
* NDCG@K
* MAP
* agreement with expert analysts

This would move the machine-learning objective closer to the actual triage problem rather than using CVSS or KEV as indirect targets. 

---

# 10. Cost-Aware Prioritization

The current prioritization framework does not model remediation cost.

Future work could incorporate:

```text
Risk
 +
Asset criticality
 +
Exposure
 +
Exploit likelihood
 +
Remediation cost
```

The objective could become:

> Which remediation queue produces the greatest expected risk reduction under a fixed engineering budget?

This changes the system from:

```text
Vulnerability ranking
```

to:

```text
Resource-aware security decision support
```

This would be particularly relevant for environments where remediation capacity is limited.



---

# 11. Uncertainty-Aware Predictions

The current A1 and B2 workflows expose predictions, but the research does not yet make uncertainty a first-class output.

Future work could investigate:

* prediction intervals
* conformal prediction
* calibrated probabilities
* ensemble variance
* uncertainty-aware ranking

This could distinguish:

```text
High predicted risk
+
High confidence
```

from:

```text
High predicted risk
+
High uncertainty
```

That distinction could be valuable in triage because analysts may reasonably treat an uncertain high-risk prediction differently from a high-confidence prediction.



---

# 12. Probability Calibration

B2 produces probabilities associated with future KEV membership.

A future study should determine whether those probabilities are actually calibrated.

Possible evaluation:

* Brier score
* calibration curves
* expected calibration error
* reliability diagrams

This matters because:

```text
Good ranking
≠
Well-calibrated probability
```

A model may correctly rank vulnerabilities while producing probabilities that should not be interpreted literally.

Calibration becomes especially important if predictions eventually influence resource allocation. 

---

# 13. Explainability Research

The current system already uses SHAP.

Therefore, future work should **not** simply say "add explainability."

The next research question is whether the explanations are useful and stable.

Potential studies include:

* SHAP stability across model versions
* SHAP interaction explanations
* explanation consistency across time
* counterfactual explanations
* comparison with alternative explanation methods
* analyst-centered explanation evaluation

The strongest extension would test:

> Do model explanations actually help security analysts make better decisions?

This turns explainability from a visualization feature into an empirical research question. 

---

# 14. Human-in-the-Loop Triage

A future system could introduce a controlled analyst-feedback loop:

```text
Model ranking
      ↓
Analyst review
      ↓
Accept / Reject / Modify
      ↓
Feedback dataset
      ↓
Future model evaluation
```

This could eventually support:

* active learning
* analyst-guided ranking
* human-in-the-loop prioritization

However, analyst feedback must not automatically become training data.

The research would first need to determine whether the feedback represents useful signal or simply reproduces existing analyst or organizational biases. 

---

# 15. Continuous Model Lifecycle

The current application uses frozen Phase 3 model artifacts.

A future operational system would require a controlled model lifecycle:

```text
New vulnerability data
        ↓
Validation
        ↓
Feature generation
        ↓
Model retraining
        ↓
Temporal evaluation
        ↓
Model approval
        ↓
Versioned deployment
```

Each model version should preserve:

* training period
* dataset version
* feature configuration
* hyperparameters
* evaluation results
* model hash
* provenance

The existing provenance architecture provides a foundation for this future lifecycle. 

---

# 16. Continuous Data Ingestion

The current frozen dataset is intentional and remains important for reproducible research.

A future operational platform could introduce scheduled ingestion of:

* NVD updates
* CISA KEV updates
* EPSS updates
* CPE changes
* vendor statements

The important principle must remain:

> New data must be versioned and validated before becoming part of the research or application dataset.

Historical snapshots should also be preserved so that future experiments remain reproducible.



---

# 17. Stronger Experiment Tracking

Future research iterations could formally record:

```text
Dataset version
Model version
Feature version
Code commit
Hyperparameters
Random seed
Training period
Evaluation period
Metrics
Model artifact hash
```

This would make it possible to answer, years later:

> Exactly which data, code, features, parameters, and model produced this result?

This would extend the reproducibility work already established by the current project. 

---

# 18. Scaling the Data Layer

The current:

```text
DuckDB
+
Immutable Parquet
```

architecture is appropriate for the research prototype.

It should **not** be replaced merely because PostgreSQL or Elasticsearch/OpenSearch might appear more production-oriented.

At substantially larger workloads, future infrastructure could introduce:

* PostgreSQL
* dedicated analytical storage
* Elasticsearch/OpenSearch
* caching
* materialized views

The correct trigger should be actual workload requirements rather than architectural fashion.

The current read-only Parquet architecture is therefore a deliberate research choice, not a deficiency. 

---

# 19. Production Security Hardening

The application now has authentication and RBAC, so the old Future Scope statement that authentication was excluded is obsolete.

The next security layer for an actual production deployment would include:

* stronger secret management
* comprehensive audit logging
* rate limiting
* security headers
* dependency monitoring
* API abuse protection
* container hardening
* secure session management
* deployment-level HTTPS/TLS controls
* operational monitoring

These are **deployment hardening concerns**, not missing research functionality.

The current prototype is therefore not incomplete because these controls are absent; they belong to a future production-hardening phase with different operational requirements.

The current public deployment should therefore continue to be described as a research/public-demonstration system rather than an enterprise production security platform.

---

# 20. Production Infrastructure

The current system is already capable of public demonstration through the configured frontend/backend deployment architecture.

Future production-scale infrastructure could evolve toward:

```text
Frontend
   ↓
Reverse Proxy / Edge
   ↓
FastAPI
   ↓
ML / Data Services
   ↓
Versioned Data Storage
```

Possible targets include:

* institutional infrastructure
* private cloud
* controlled enterprise environments

The immutable research-data boundary should remain even after the application infrastructure becomes more complex.

---

# 21. Analyst Workflow Expansion

The current UI is sufficient for the completed research prototype.

Future operational workflows could introduce:

* saved searches
* persistent analyst work queues
* vulnerability comparison
* bulk prioritization
* custom asset inventories
* remediation status
* analyst notes
* filtering presets
* historical priority changes
* notifications

These features become substantially more meaningful once real asset and remediation data exist.

This is therefore a **secondary future direction**, not a prerequisite for the current research system. 

---

# 22. Multi-Organization Evaluation

The current project does not contain real organizational datasets.

A future study could evaluate the methodology across multiple organizations with different:

* asset distributions
* technology stacks
* security practices
* remediation capabilities
* business priorities

The research question becomes:

> Does the prioritization methodology generalize across organizations with different operational environments?

This would be essential before making broad enterprise claims. 

---

# 23. Fairness and Bias Analysis

Historical vulnerability data are not necessarily a neutral representation of future security risk.

Future analysis could examine whether model behavior varies systematically across:

* vendors
* products
* vulnerability classes
* publication periods
* CWE categories
* technology ecosystems

This would help determine whether apparently good aggregate performance hides systematic weaknesses in particular parts of the vulnerability ecosystem. 

---

# 24. Adversarial Robustness

Because several model inputs originate from vulnerability descriptions and metadata, future research could evaluate robustness against:

* wording changes
* incomplete descriptions
* unusual terminology
* adversarial text perturbations
* malformed metadata
* distribution shifts

The objective would be to determine whether predictions remain stable when vulnerability descriptions differ from the patterns represented in historical training data.



---

# 25. Distribution-Shift Analysis

The current temporal split provides a basic form of temporal generalization.

Future research could explicitly measure:

```text
Training distribution
        ↓
Validation distribution
        ↓
Test distribution
```

and identify which feature distributions change.

Potential causes include:

* new technologies
* changing vulnerability language
* changes in CVSS practices
* changing exploitation behavior
* changes in vendor reporting
* changes in KEV selection behavior

This would help explain **why** model performance changes over time rather than merely reporting that it changed. 

---

# 26. Reproducibility as a Research Artifact

The project's reproducibility work could itself become a research contribution.

A future reproduction package could provide:

* exact dataset manifests
* deterministic rebuild scripts
* experiment configuration files
* model hashes
* environment lockfiles
* automated end-to-end reproduction
* independent reproduction instructions

This would allow the project to function not only as a vulnerability-prioritization system but also as a **reproducible cybersecurity research artifact**. 

---

# 27. Long-Term Research Direction

The most significant long-term evolution is from:

```text
Vulnerability
      ↓
Risk Score
      ↓
Priority Ranking
```

toward:

```text
Vulnerability
      +
Threat Intelligence
      +
Asset Exposure
      +
Business Impact
      +
Exploit Likelihood
      +
Remediation Cost
      +
Model Uncertainty
      ↓
Expected Risk Reduction
      ↓
Resource-Aware Remediation Decision
```

This would transform the system from a vulnerability prioritization application into a broader **security decision-support platform**.

However, this should be treated as a new research phase rather than an automatic continuation of the current experiment.

---

# 28. Recommended Future Research Roadmap

The most defensible order of progression is:

```text
1. Time-aligned EPSS
        ↓
2. Rolling temporal evaluation
        ↓
3. Probability calibration
        ↓
4. Improved exploitation ground truth
        ↓
5. Real asset/context data
        ↓
6. Real remediation outcomes
        ↓
7. Learning-to-rank formulation
        ↓
8. Uncertainty-aware prioritization
        ↓
9. Human analyst evaluation
        ↓
10. Production-scale deployment
```

This ordering matters.

For example, there is little value in building a sophisticated learning-to-rank model before obtaining a defensible ranking ground truth.

Likewise, deploying continuous retraining before establishing time-aligned evaluation could automate an invalid methodology.

The research boundary therefore remains:

> **Research validity first → implementation second → operational deployment third.**

The previous Future Scope document already identified essentially this ordering; it remains valid after removing the now-completed implementation work. 

---

# 29. Things That Are *Not* Remaining Future Scope

The following should **not** be presented as future implementation work anymore:

* basic frontend implementation
* responsive/mobile UI
* authentication
* RBAC
* analyst/researcher/admin role separation
* API authentication enforcement
* loading/error/empty states
* CSV/JSON export
* printable CVE reports
* FAQ
* documentation center
* feedback UI
* accessibility improvements
* frontend/backend integration
* basic API implementation
* automated test suite
* research-data immutability
* model artifact reconstruction
* SHAP integration
* public demonstration deployment preparation

These are already part of the completed implementation.

Future work begins **after this boundary**.

---

# 29A. Things That Are *Not* Remaining Implementation Work

The public frontend and research backend are intentionally decoupled.

When the FastAPI backend is unavailable, the GitHub Pages frontend can still load its static public shell and navigation:

```text
Home
About
Docs
FAQ
Contact
```

This is expected behavior, not an incomplete implementation.

The backend-dependent application features require the FastAPI service to be available through the configured public API endpoint:

```text
https://vuln-triage-api.seucra.tech
```

The live demonstration therefore requires:

```text
GitHub Pages
    ↓
Static Frontend
    ↓
Cloudflare Tunnel
    ↓
Local FastAPI Backend
    ↓
Frozen Dataset + Model Artifacts
```

The backend machine must remain running for authenticated workflows, vulnerability retrieval, predictions, prioritization, SHAP explanations, and other backend-dependent functionality.

---

# 30. Final Future-Scope Position

The current project has established the foundation.

The next generation should focus less on adding UI features and more on obtaining the evidence necessary to make stronger security claims.

The progression is therefore:

```text
CURRENT PROJECT

Historical vulnerability data
        ↓
Deterministic ETL
        ↓
Frozen dataset
        ↓
Temporal ML
        ↓
Leakage analysis
        ↓
Controlled prioritization
        ↓
SHAP
        ↓
Validated application


FUTURE RESEARCH

Time-aligned data
        ↓
Better exploitation ground truth
        ↓
Real asset context
        ↓
Real remediation outcomes
        ↓
Direct ranking objectives
        ↓
Uncertainty + calibration
        ↓
Human analyst evaluation
        ↓
Operational validation
        ↓
Production-scale platform
```

The most important principle remains unchanged:

> **Every new capability should first have a defensible research definition, feature-availability boundary, evaluation methodology, and source of ground truth before it becomes an implementation feature.** 

### Future Scope in One Paragraph

The completed system establishes a reproducible foundation for vulnerability prioritization using temporally disciplined machine learning, threat intelligence, controlled asset context, nonlinear decision support, explainability, and an authenticated analyst-facing application. Future research should primarily focus on time-aligned EPSS and other temporal threat-intelligence signals, stronger exploitation ground truth, rolling temporal evaluation, probability calibration, uncertainty estimation, real enterprise asset and remediation data, direct learning-to-rank formulations, analyst-centered evaluation, and multi-organization validation. At the engineering level, continuous data ingestion, versioned model lifecycle management, stronger production security, and larger-scale infrastructure can eventually transform the research prototype into an operational security decision-support platform. These extensions should remain separate research phases and must preserve the reproducibility, provenance, and temporal-validity principles established by the current system. 

