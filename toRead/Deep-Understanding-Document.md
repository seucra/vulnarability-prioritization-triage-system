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
