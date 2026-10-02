# Future Scope and Research Extensions for the Vulnerability Prioritization & Triage System

**Academic Project Context**: B.Tech Computer Engineering Web Design Lab Research Prototype & Public Demonstration Deployment  
**Repository Identifier**: `seucra/vulnarability-prioritization-triage-system`  
**Document Classification**: Strategic Research Roadmap & Technical Extension Guide  
**Current Baseline State**: Phase 4 Complete (Frozen Processed Data, Phase 3 ML Models Serialized, FastAPI Backend, Vanilla SPA Frontend, Full RBAC, Automated Test Suite 46/46 Passed, Demonstration Deployment Verified)  

---

## 1. Scope and Current Baseline

The Vulnerability Prioritization & Triage System (VTS) is an academic research prototype developed to study the intersection of vulnerability severity estimation, threat forecasting under temporal constraints, retrospective data leakage, and multi-criteria decision surfaces. 

### 1.1 The Operational Baseline
The current repository establishes a concrete, verified baseline comprising:
- **Canonical Processed Data**: Six Snappy-compressed Parquet tables under `data/processed/` covering **366,547 unique CVEs** (1988–2026), 430,273 CWE mappings, 3,133,450 CPE applicability nodes, 348,900 EPSS scores (frozen snapshot of 2026-07-16), 1,647 CISA KEV entries, and 1,486 vendor statements.
- **Empirical Machine Learning Models**:
  - `EXP-A1`: Pre-scoring CVSS v3.1 base score XGBoost regressor achieving an MAE of **0.9750** on 81,604 held-out test CVEs (2025–2026).
  - `EXP-B2`: Strict publication-time KEV exploitation XGBoost classifier achieving a PR-AUC of **0.02884** (8.96× uplift over random guessing) and Precision@500 of 6.40% on 91,242 test CVEs (294 KEV positives).
  - `EXP-B1`: Retrospective sensitivity audit proving that access to a future EPSS snapshot causes an **11.49× artificial PR-AUC inflation** (jumping to 0.33153).
- **Decision-Support Simulation (`EXP-C1`)**: Dual-mode prioritization comparing an additive linear model ($S_{\text{linear}}$) against a multiplicative non-linear surface ($S_{\text{nonlinear}}$), showing a Top-100 Jaccard overlap of only **0.005 (0.5%)**.
- **Local Interpretability**: Tree-based SHAP (`TreeExplainer`) feature attributions integrated into backend inference and visualized in the frontend UI.
- **Application & Demonstration Layer**: A FastAPI REST API service (Port 5002) with 15 endpoints, SQLite user registry with PBKDF2-HMAC-SHA256 password hashing and JWT RBAC (`analyst`, `researcher`, `admin`), and a responsive vanilla JavaScript Single Page Application (SPA).

Future work must **not** re-invent or re-propose capabilities that are already implemented and verified in the codebase. Instead, subsequent research must treat this platform as an established baseline and address verified methodological, empirical, and architectural limitations.

---

## 2. Implemented Capabilities (Not Future Work)

To maintain absolute academic integrity, the following features are cataloged as **already implemented and verified** in the repository and must not be described as future scope:

| System Dimension | Fully Implemented & Verified Capabilities | Authoritative Code / Artifact Reference |
|---|---|---|
| **Data Engineering** | Deterministic ETL pipeline from raw JSON/XML to Parquet; canonicalization hashing routines; automated invariant test suite (15 tests). | `scripts/build_processed_data.py`, `scripts/fingerprint_processed_data.py`, `tests/test_etl_invariants.py` |
| **Severity Estimation** | Pre-scoring CVSS v3.1 estimation using TF-IDF text features, CWE taxonomy, and CPE platform counts; comparison against Ridge baseline. | `scripts/experiments/run_exp_a1.py`, `data/experiments/phase3/exp_a1/` |
| **Publication-Time Prediction** | Strict information boundary enforcement rejecting post-publication telemetry (EPSS, CVSS vectors); baseline comparison against Logistic Regression. | `scripts/experiments/run_exp_b2.py`, `backend/app/schemas/prediction.py` |
| **Leakage Quantification** | Quantitative evaluation of retrospective EPSS snapshot leakage demonstrating 11.49× performance inflation. | `scripts/experiments/run_exp_b1.py`, `data/experiments/phase3/exp_b1/` |
| **Multi-Criteria Scoring** | Dual-mode prioritization engine implementing Mode 1 (Linear Equal Weights) and Mode 2 (Nonlinear Interactive Surface with $\alpha=1.0, \beta=1.5$). | `backend/app/services/scoring_service.py`, `data/experiments/phase3/exp_c1/` |
| **Local Explainability** | Exact TreeExplainer SHAP attribution generation for both regression and classification models with causal disclaimer guards. | `backend/app/services/explanation_service.py`, `scripts/experiments/run_shap_analysis.py` |
| **Access Control & Auth** | SQLite-backed user management, PBKDF2-HMAC-SHA256 password hashing, HS256 JWT issuance, and role enforcement (`analyst`, `researcher`, `admin`). | `backend/app/core/security.py`, `backend/app/core/auth_db.py`, `tests/test_auth_rbac.py` |
| **Analyst Batch Triage** | Multi-CVE batch queue scoring (up to 100 items), automated metadata joining, queue rank sorting, score shift tracking, and CSV/JSON export. | `backend/app/api/v1/prioritize.py`, `frontend/js/components/batch_triage_view.js` |
| **Demonstration Deployment** | Public demonstration topology with GitHub Pages frontend and Cloudflare Tunnel reverse proxy to a self-hosted FastAPI VPS daemon. | `docs/DEPLOYMENT.md`, `docs/final-deployment-audit.md` |

---

## 3. Current Limitations Verified from the Repository

The future research roadmap is directly derived from eight verified repository limitations:

1. **Static Data Snapshots**: The repository is bound to immutable snapshots (frozen 2026-07-26; EPSS snapshot 2026-07-16). There is no automated cron worker to poll live NVD JSON 2.0 feeds or FIRST daily EPSS CSV releases.
2. **Single-Snapshot EPSS Limitation**: EXP-B1 utilized a single retrospective EPSS file (`epss_scores-2026-07-16.csv.gz`). The repository does not store historical daily EPSS time-series data, precluding the study of longitudinal score trajectories.
3. **Imperfect Ground Truth (KEV Delay & Incompleteness)**: CISA KEV reflects confirmed enterprise exploitation in federal networks, with a median addition delay of 285.2 days post-publication. It misses unobserved, private, or nation-state zero-day exploitation, creating false negatives in the training label.
4. **CVSS Missingness**: 37.88% of canonical CVEs lack CVSS v3.1 scores (pre-2016 legacy CVEs having only CVSS v2, or recent disclosures under active analysis).
5. **Synthetic Controlled Asset Tiers**: In EXP-C1, asset criticality is modeled using four discrete synthetic scalar values ($A \in \{0.25, 0.50, 0.75, 1.00\}$) rather than dynamic enterprise asset telemetry (e.g., CMDB, active reachability, network topology).
6. **Lack of Enterprise Triage Telemetry**: The repository does not contain enterprise ticket histories, patch turnaround times, or confirmed incident telemetry. Consequently, real-world "Work Reduction" and "Compromise Prevention" cannot be measured empirically.
7. **Extreme Class Imbalance Tail Behavior**: With only 294 KEV positive instances among 91,242 test CVEs (0.32% base rate), standard tree models exhibit poor probability calibration in the extreme tail $[p > 0.8]$.
8. **Single-Host Prototype Infrastructure**: The demonstration deployment lacks distributed clustering, enterprise secret management (e.g., HashiCorp Vault), or automated container orchestration.

---

## 4. Immediate Research-Completion Plan

These immediate actions address specific documentation discrepancies, missing analysis artifacts, and statistical validations that can be completed within the current dataset boundary:

### 4.1 Formal Deprecation of the Discrepant B2 PR-AUC Value (0.3845)
- **Status**: *Immediate Action Required*
- **Problem**: An unverified value of `PR-AUC = 0.3845` appeared in `docs/final-repo-state.md:160` mislabeled as "EXP-B2 (Text+Meta+EPSS)", while the serialized artifact `data/experiments/phase3/exp_b2/metrics.json` definitively records `PR-AUC = 0.02884`.
- **Action**: Update all legacy research notes to explicitly state that 0.3845 was an unverified draft entry conflated with an example API output string (`"predicted_kev_probability": 0.38451` in `docs/API.md:146`). Reaffirm that **0.02884** is the sole verified, authoritative test PR-AUC for publication-time KEV classification.

### 4.2 Cross-Experiment Population Alignment and Row-Level Join Matrix
- **Status**: *Proposed (Near-Term)*
- **Problem**: EXP-A1 evaluates on 81,604 test CVEs (restricted to CVEs with CVSS v3.1), while EXP-B2 evaluates on 91,242 test CVEs (all canonical CVEs published in 2025–2026).
- **Action**: Generate an intersected prospective evaluation subset ($n = 81,604$) containing simultaneous row-level predictions for:
  - Official CVSS v3.1 Base Score ($y_{\text{cvss}}$)
  - EXP-A1 Predicted CVSS Base Score ($\hat{y}_{\text{cvss}}$)
  - Ground-truth KEV listing status ($y_{\text{kev}}$)
  - EXP-B2 Predicted KEV probability ($\hat{p}_{\text{b2}}$)
  - EXP-B1 Leaked KEV probability ($\hat{p}_{\text{b1}}$)
  - Mode 1 Linear Priority Rank ($R_{\text{linear}}$)
  - Mode 2 Nonlinear Priority Rank ($R_{\text{nonlinear}}$)
  Serialize this consolidated table as `data/experiments/phase3/consolidated_triage_evaluation.parquet`.

### 4.3 Definition and Evaluation of KEV Observation Cutoff Windows
- **Status**: *Proposed (Near-Term)*
- **Problem**: In EXP-B2, the label $y=1$ denotes that a CVE was listed in CISA KEV at any time up to the dataset freeze date (2026-07-26). Vulnerabilities published in early 2025 had ~18 months of observation time, whereas vulnerabilities published in mid-2026 had only weeks.
- **Action**: Implement a fixed-window horizon label (e.g., $y_{\le 180\text{d}} = 1$ if added to KEV within 180 days of publication; 0 otherwise). Filter the test partition to CVEs with at least 180 days of exposure prior to freeze date, eliminating right-censoring bias.

### 4.4 Empirical Calibration Analysis (Brier Score & Reliability Diagrams)
- **Status**: *Proposed (Near-Term)*
- **Problem**: EXP-B2 uses `scale_pos_weight=20` to compensate for class imbalance. While this optimizes ranking (PR-AUC), it skews predicted probabilities away from true posterior probabilities.
- **Action**: Compute the Brier score and plot calibration curves for EXP-B2. Fit isotonic regression and Platt scaling (sigmoid) calibrators on the validation partition and evaluate whether calibrated probabilities preserve PR-AUC while improving probability interpretation.

---

## 5. Near-Term Extensions

### 5.1 Historical EPSS Daily Time-Series Ingestion
- **Classification**: *Proposed*
- **Research Question**: *How rapidly does EPSS predictive power improve as post-disclosure days accumulate ($t \in \{1, 7, 14, 30, 60, 90\}$ days), and at what temporal threshold does threat telemetry surpass initial disclosure text?*
- **Implementation**: Ingest the official historical EPSS daily archive (available from `github.com/empiricalsec/epss_scores`). For each test CVE, extract EPSS scores at discrete post-publication intervals and fit rolling classification models.

### 5.2 Rolling-Origin and Expanding-Window Temporal Cross-Validation
- **Classification**: *Proposed*
- **Research Question**: *How stable are pre-scoring regression (EXP-A1) and exploitation prediction (EXP-B2) models across shifting vulnerability disclosure eras?*
- **Implementation**: Replace the single 2002–2022 / 2023–2024 / 2025–2026 split with a rolling annual evaluation scheme (e.g., Train 2015–2021 $\rightarrow$ Test 2022; Train 2016–2022 $\rightarrow$ Test 2023; etc.) to measure concept drift in vulnerability descriptions and software platforms.

### 5.3 Fine-Grained Feature Ablation and Text Embedding Benchmarks
- **Classification**: *Proposed*
- **Research Question**: *Does replacing TF-IDF unigrams/bigrams with pre-trained cybersecurity transformer embeddings (e.g., SecureBERT, RoBERTa-Sec) improve CVSS estimation MAE and KEV PR-AUC without inducing severe latency overhead?*
- **Implementation**: Benchmark five distinct feature representation subsets:
  1. Metadata only (CWE indicators + CPE counts + publication month)
  2. TF-IDF unigrams/bigrams (Current VTS baseline, 500 features)
  3. Transformer dense embeddings (e.g., `sentence-transformers/all-MiniLM-L6-v2` or `SecureBERT`)
  4. Hybrid text embeddings + metadata
  5. Multi-task learning architecture jointly estimating CVSS sub-metrics (Attack Vector, Privileges Required, Scope).

### 5.4 Bootstrapped Confidence Intervals for Model Benchmarks
- **Classification**: *Proposed*
- **Implementation**: Execute 1,000-iteration stratified bootstrap sampling on the test partitions to compute 95% confidence intervals for EXP-A1 MAE ($[0.9750 \pm \delta]$) and EXP-B2 PR-AUC ($[0.02884 \pm \epsilon]$), providing rigorous error bounds for academic publication.

---

## 6. Medium-Term Research Directions

### 6.1 Real Enterprise Asset Inventory and CMDB Integration
- **Classification**: *Proposed (Requires External Data)*
- **Motivation**: VTS currently uses synthetic asset tiers ($A \in \{0.25, 0.50, 0.75, 1.00\}$). In real enterprise environments, asset criticality depends on business data sensitivity, regulatory scope (e.g., PCI-DSS, HIPAA), user access volume, and system redundancy.
- **Approach**: Formulate an open integration connector for Configuration Management Databases (CMDB) such as ServiceNow or open-source asset inventories (e.g., Snipe-IT). Map real asset attributes to a multi-dimensional criticality vector:
  $$\vec{A} = \langle \text{ConfidentialityRequirement}, \text{PublicFacing}, \text{DataClassification}, \text{RedundancyFactor} \rangle$$

### 6.2 Network Reachability, Exposure, and Compensating Controls
- **Classification**: *Proposed*
- **Motivation**: A vulnerability with CVSS 10.0 and KEV listing poses minimal immediate risk if hosted on an isolated internal network behind an air-gapped firewall with zero ingress routes.
- **Approach**: Integrate network reachability matrices and Web Application Firewall (WAF) rule coverage into the Mode 2 prioritization surface:
  $$S_{\text{contextual}} = S_{\text{nonlinear}} \cdot \mathbb{I}_{\text{reachable}} \cdot (1 - \text{MitigationFactor}_{\text{WAF}})$$

### 6.3 Cost-Sensitive Remediation Optimization
- **Classification**: *Proposed*
- **Motivation**: Triage decisions cannot be based solely on risk; they must balance risk reduction against patching costs (e.g., reboot downtime, regression testing overhead, patch conflict risks).
- **Approach**: Formulate vulnerability remediation as a constrained Knapsack optimization problem:
  $$\max \sum_{i \in \text{Patches}} \Delta \text{Risk}_i \cdot x_i \quad \text{subject to} \quad \sum_{i \in \text{Patches}} \text{Cost}_i \cdot x_i \le \text{MaintenanceWindowCapacity}$$

### 6.4 Concept Drift Detection and Model Lifecycle Monitoring
- **Classification**: *Proposed*
- **Approach**: Deploy automated Kolmogorov-Smirnov (KS) tests and Population Stability Index (PSI) monitors on incoming vulnerability descriptions and feature distributions to alert operators when vocabulary drift degrades model inference.

---

## 7. Ambitious Long-Term Research Directions

### 7.1 Attack Graph and Dependency Topology Modeling (Graph Neural Networks)
- **Classification**: *Speculative / Ambitious*
- **Conceptual Vision**: Moving beyond single-CVE assessment to multi-step lateral movement path analysis. Vulnerabilities that appear benign in isolation (e.g., local privilege escalation) become critical when chained with an unauthenticated external SSRF flaw.
- **Methodology**: Construct heterogeneous system attack graphs integrating Software Bill of Materials (SBOM), active network sockets, and identity permissions. Apply Graph Convolutional Networks (GCN) or Relational Graph Transformers (e.g., building upon the concepts of Jiang et al., 2025 VulRG) to score whole attack paths rather than isolated vulnerabilities.

### 7.2 Counterfactual and Causal Explainability
- **Classification**: *Speculative*
- **Limitation of Current SHAP**: SHAP provides statistical associative feature attributions, which can be conflated with causality. For example, the presence of the word "windows" has a high positive $\phi$ in EXP-B2 not because running Windows causes exploitation, but because attackers heavily target widespread enterprise operating systems.
- **Methodology**: Develop structural causal models (SCMs) for software vulnerabilities to generate actionable counterfactual explanations (e.g., *"If this network service had Privileges Required: High instead of None, the estimated exploitation likelihood would decrease by 78%"*).

### 7.3 Longitudinal Operational Field Evaluation
- **Classification**: *Speculative (Requires Industry Partnership)*
- **Methodology**: Deploy VTS in parallel with conventional CVSS-only triage in an operational security operations center (SOC) over a 12-month period. Track empirical mean time to remediate (MTTR), false alarm reduction, patching hours consumed, and actual breach penetration events to validate real-world Work Reduction.

---

## 8. Security, Governance, and Deployment Extensions

To evolve VTS from an academic demonstration deployment into a robust institutional tool, the following security and governance hardening steps are specified:

| Area | Current Baseline State | Target Governance / Production Extension | Priority |
|---|---|---|---|
| **Secret Management** | JWT secret key loaded from local `.env` file via Pydantic settings. | Migrate secret storage to HashiCorp Vault, AWS Secrets Manager, or Doppler with dynamic key rotation. | High |
| **Authentication** | Local SQLite user registry with PBKDF2 hashing and JWT bearer tokens. | Implement OpenID Connect (OIDC) / SAML 2.0 single sign-on (SSO) integration (e.g., Keycloak, Okta, Microsoft Entra ID). | High |
| **Audit Logging** | Uvicorn console logging with standard HTTP access records. | Implement immutable append-only JSON audit logging tracking all triage score overrides, batch queue exports, and user logins. | Medium |
| **Containerization** | Direct process execution via `run.sh` / Python virtual environment. | Provide multi-stage Dockerfiles (`Dockerfile.backend`, `Dockerfile.frontend`) and `docker-compose.yml` for isolated deployment. | High |
| **Model Integrity** | XGBoost binary models (`model.xgb`) loaded via native UBJSON deserialization. | Implement cryptographic signing of model binaries (Cosign / Sigstore) and verify checksums upon backend startup. | Medium |
| **Tenant Isolation** | Single-tenant database model; shared SQLite user table. | Implement multi-tenant schema partitioning enabling distinct organizations to maintain private asset inventories and custom triage weights. | Low |

---

## 9. Proposed Research Questions (Formal Specification)

Subsequent studies utilizing the VTS research platform should address the following testable scientific questions:

- **Scientific RQ-F1 (Temporal Telemetry Horizon)**: *At what disclosure horizon $t \in [1, 180]$ days does dynamic exploit prediction telemetry (EPSS) asymptotically surpass publication-time NLP features in maximizing Top-500 KEV recall?*
- **Scientific RQ-F2 (Calibrated Tail Inference)**: *Can non-parametric isotonic regression preserve XGBoost ranking discrimination (PR-AUC $\ge 0.028$) while reducing tail probability Brier calibration error by at least 25%?*
- **Scientific RQ-F3 (Transformer Representation Gain)**: *Does fine-tuning domain-specific language representations (SecureBERT) provide a statistically significant reduction in CVSS pre-scoring MAE ($p < 0.01$) compared to sublinear TF-IDF n-grams?*
- **Engineering Objective-F1 (Live Synchronization Worker)**: *Design and verify an asynchronous background worker that performs daily delta ingestion of NVD 2.0 feeds and EPSS CSVs without interrupting zero-copy DuckDB Parquet queries.*
- **Artifact Objective-F2 (Containerized Benchmark Image)**: *Package the complete frozen research corpus, serialized models, and verification suites into an OCI-compliant reproducible container image deposited with a permanent Zenodo DOI.*

---

## 10. Prioritized Roadmap Table

| Roadmap Item | Research / Engineering Motivation | Pre-requisites & Dependencies | Target Metric / Expected Evidence | Risk & Feasibility | Horizon | Changes Central Paper Claim? |
|---|---|---|---|---|---|---|
| **F-01: Historical EPSS Daily Ingestion** | Enable longitudinal telemetry research without data leakage. | Ingest FIRST daily historical CSV archive (~2021–2026). | Time-series dataframe linking CVEs to daily EPSS trajectories. | Low risk; publicly available data. | Near-Term (1–3 mo) | No (Reinforces leakage thesis). |
| **F-02: Fixed-Horizon KEV Evaluation** | Eliminate right-censoring bias in recent test disclosures. | Temporal join between NVD published date and KEV addition date. | PR-AUC and Recall@K evaluated on fixed 180-day window. | Low risk; straightforward SQL logic. | Near-Term (1–3 mo) | No (Refines baseline precision). |
| **F-03: Model Probability Calibration** | Provide meaningful absolute probabilities for risk calculations. | Serialized validation prediction arrays from EXP-B2. | Brier Score reduction; reliability diagrams. | Low risk; standard scikit-learn calibrators. | Near-Term (1–3 mo) | No (Improves interpretability). |
| **F-04: Transformer Embedding Benchmark** | Test whether deep language models improve over TF-IDF. | GPU compute environment; HuggingFace Transformers. | MAE comparison on EXP-A1; PR-AUC on EXP-B2. | Medium risk; high inference latency. | Medium-Term (3–6 mo) | Potentially (If deep NLP surpasses 0.9750 MAE). |
| **F-05: Live Data Sync Background Worker** | Transition prototype into a continuous monitoring tool. | NVD API Key; automated cron / Celery scheduler. | Automated delta Parquet updates; zero query lockups. | Medium risk; NVD API rate limits. | Medium-Term (3–6 mo) | No (Engineering enhancement). |
| **F-06: Containerized Packaging (Docker)** | Ensure push-button cross-platform reproduction. | Dockerfile optimization; rootless security configuration. | Passing test suite inside container; minimal image size. | Very low risk; standard DevOps practice. | Near-Term (1 mo) | No (Artifact enhancement). |
| **F-07: Real CMDB Asset Connector** | Replace synthetic tiers with empirical enterprise context. | Partner enterprise asset inventory / CMDB export. | Evaluation on real asset distributions. | High risk; requires external enterprise data. | Long-Term (6–12 mo) | Yes (Extends claims to operational triage). |
| **F-08: Attack Path Graph Neural Network** | Account for multi-vulnerability exploit chaining. | Graph modeling of SBOM, sockets, and identity paths. | Path-level vulnerability risk scores and ROC-AUC. | High risk; high theoretical complexity. | Long-Term (>12 mo) | Yes (Establishes topological risk paradigm). |

---

## 11. Future-Work Non-Claims

To ensure absolute scientific honesty in academic defense and documentation:
1. **No Operational Superiority Claim**: Proposed future extensions (such as CMDB integration or graph modeling) must not be cited as evidence that VTS currently outperforms commercial vulnerability management systems.
2. **No Guaranteed Predictive Uplift**: Hypothesized improvements from transformer embeddings (SecureBERT) are speculative until empirically evaluated against the current TF-IDF baseline.
3. **No Causal Guarantee**: Future counterfactual attribution extensions remain theoretical; statistical attribution does not prove physical exploit exploitability.
4. **No Zero-Day Capability**: VTS is designed for publicly disclosed CVEs; future work does not claim to detect or prevent undisclosed zero-day exploits prior to vulnerability enumeration.

---

## 12. References

1. **Jiang, L., et al.** (2025). A Survey on Vulnerability Prioritization: Taxonomy, Metrics, and Research Challenges. *arXiv preprint arXiv:2502.11070*. [https://arxiv.org/abs/2502.11070](https://arxiv.org/abs/2502.11070)
2. **Jacobs, J., et al.** (2023). Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights. *arXiv preprint arXiv:2302.14172*. [https://arxiv.org/abs/2302.14172](https://arxiv.org/abs/2302.14172)
3. **Ravalico, D., Farina, L., Trevisan, M., & Bartoli, A.** (2025). Analysing the Temporal Dynamics of the Exploit Prediction Scoring Systems. *SSRN Electronic Journal*, SSRN:5147459. [https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459](https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459)
4. **Agyei, K. G., et al.** (2026). Explainable Risk-Based Vulnerability Prioritization in Hybrid Cloud: Integrating CVSS, EPSS, and CISA KEV with Asset Criticality Signals. *World Journal of Advanced Research and Reviews*, 30(01), 2044–2052. [https://doi.org/10.30574/wjarr.2026.30.1.1006](https://doi.org/10.30574/wjarr.2026.30.1.1006)
5. **FIRST**: Exploit Prediction Scoring System (EPSS) Research & Data. [https://www.first.org/epss/research](https://www.first.org/epss/research)
6. **CISA**: Known Exploited Vulnerabilities Catalog. [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
7. **NIST**: Common Vulnerability Scoring System (CVSS) Specification. [https://nvd.nist.gov/vuln-metrics/cvss](https://nvd.nist.gov/vuln-metrics/cvss)

---

## 13. Audit and Concluding Declarations

- **Repository Facts Inspected**: All proposed extensions are directly mapped against the physical implementation files in `seucra/vulnarability-prioritization-triage-system` (`backend/`, `src/ingestion/`, `scripts/experiments/`, `data/experiments/phase3/`, `tests/`).
- **Unresolved Limitations**: Identified limitations (synthetic asset tiers, single retrospective EPSS snapshot, static freeze boundary) are explicitly scoped and isolated.
- **Recommended Next Three Actions**:
  1. Produce the consolidated evaluation matrix `data/experiments/phase3/consolidated_triage_evaluation.parquet` aligning EXP-A1 and EXP-B2 test subsets.
  2. Implement probability calibration (Platt scaling / Isotonic regression) on EXP-B2 validation probabilities.
  3. Package the application and experiments into an official `Dockerfile` and `docker-compose.yml` for automated one-step reproduction.
- **Authoritative Declaration**: *Future research plans and proposed extensions described in this document represent hypotheses to be tested and architectural targets to be built; they do not constitute evidence of current operational capability.*
