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

