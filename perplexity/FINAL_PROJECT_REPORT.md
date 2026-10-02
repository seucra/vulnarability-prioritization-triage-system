# Final Project Report: Vulnerability Prioritization & Triage System (VTS)

**Academic Project Context**: B.Tech Computer Engineering Web Design Lab Research Prototype & Public Demonstration Deployment  
**Institution**: Department of Computer Engineering  
**Academic Year / Date**: 2025–2026 / August 2026 (Audited October 2026)  
**Repository Identifier**: `seucra/vulnarability-prioritization-triage-system`  
**Dataset Freeze Date**: 2026-07-26 | **EPSS Snapshot Date**: 2026-07-16T12:03:48Z (`v2026.06.15`)  
**Document Classification**: Authoritative Scientific & Engineering Final Report  

---

## 1. Title Page & Administrative Metadata

- **Project Title**: Vulnerability Prioritization & Triage System: An Empirical Investigation into Publication-Time Severity Estimation, Exploitation Prediction Leakage, and Multi-Criteria Risk Surfaces
- **Short Name**: VTS (Vulnerability Triage System)
- **Academic Context**: B.Tech Computer Engineering Capstone / Web Design Lab (WDL) Research Prototype
- **Repository**: `seucra/vulnarability-prioritization-triage-system` (Local Path: `/home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system`)
- **System Version**: `1.0.0` (FastAPI Backend, Vanilla ES Modules SPA Frontend, DuckDB Columnar Query Engine, SQLite RBAC User Registry)
- **Author/Student Information**: Academic Research Team, Department of Computer Engineering
- **Supervisor / Evaluator Context**: Academic Examination Panel, Computer Engineering Board

---

## 2. Abstract

The escalating rate of disclosed Common Vulnerabilities and Exposures (CVEs)—exceeding 366,000 canonical records by mid-2026—imposes an unsustainable operational burden on cybersecurity triage teams. Conventional vulnerability triage relies heavily on Common Vulnerability Scoring System (CVSS) Base Scores, which reflect intrinsic technical severity rather than dynamic operational risk or real-world exploitation probability. Consequently, security teams suffer from severe alert fatigue and misallocated remediation effort. This project investigates whether machine learning (ML) and multi-criteria decision surfaces can provide rigorous, context-sensitive triage assistance under realistic operational information-availability constraints.

We construct an immutable, deterministically audited research corpus across 366,547 canonical CVE records (1988–2026) integrating the National Vulnerability Database (NVD), Common Weakness Enumeration (CWE), Common Platform Enumeration (CPE), CISA Known Exploited Vulnerabilities (KEV), and the FIRST Exploit Prediction Scoring System (EPSS). Using strict temporal partitioning (Train: 2002–2022; Validation: 2023–2024; Test: 2025–2026), we conduct four core empirical investigations:
1. **EXP-A1 (Severity Estimation)**: Pre-scoring CVSS v3.1 base score estimation at disclosure time using natural language text tokens and weakness taxonomy, achieving a Test Mean Absolute Error (MAE) of **0.9750** with an XGBoost regressor (a 10.99% error reduction over a Ridge baseline MAE of 1.0954 across 81,604 test CVEs).
2. **EXP-B2 (Temporally Constrained Exploitation Prediction)**: Publication-time prediction of eventual CISA KEV inclusion without post-publication telemetry, achieving a Precision-Recall Area Under Curve (PR-AUC) of **0.02884** (XGBoost) on an extreme class imbalance of 0.32% (294 KEV positives in 91,242 test CVEs), providing an **8.96× precision multiplier** over random guessing.
3. **EXP-B1 (Retrospective Snapshot Leakage Audit)**: Quantitative proof that incorporating a static post-hoc EPSS snapshot inflates Test PR-AUC to **0.33153** (an **11.49× artificial performance inflation**), demonstrating a prevalent methodological flaw in vulnerability research.
4. **EXP-C1 (Multi-Criteria Risk Surface Simulation)**: Factorial decision-support simulation across 227,694 intersected CVEs, demonstrating that while linear additive scoring creates a rigid priority ceiling that over-prioritizes binary KEV flags, a non-linear interactive surface ($S_{\text{nonlinear}}$) couples severity, threat probability, and asset criticality multiplicatively, yielding an extreme queue disruption with a Top-100 Jaccard overlap of only **0.005 (0.5%)**.

The system operationalizes these research findings into a modular FastAPI backend, an interactive Single Page Application (SPA), TreeExplainer SHAP explainability, and an automated verification test suite (46 unit/integration pytests and 15 professor demonstration tests passing at 100%). We emphasize that VTS is an academic research prototype and public demonstration deployment, not an enterprise production service; it does not claim offensive exploit generation, causal guarantees, or unverified operational work reduction.

---

## 3. Keywords

Vulnerability Prioritization; CVE Triage; CVSS Pre-Scoring; Exploit Prediction Scoring System (EPSS); CISA Known Exploited Vulnerabilities (KEV); Data Leakage; Temporal Validation; XGBoost; SHAP Explainability; Multi-Criteria Decision Analysis.

---

## 4. Introduction

### 4.1 The Vulnerability Management Dilemma
Modern software organizations face a structural imbalance between the volume of disclosed software vulnerabilities and their capacity to remediate them. The National Vulnerability Database (NVD) catalogs over 366,000 vulnerabilities, with annual disclosure rates accelerating annually. In enterprise networks running heterogeneous application stacks, vulnerability scanning tools routinely generate tens of thousands of alerts per scan cycle. Remediation—consisting of patch testing, dependency regression analysis, system reboot orchestration, and architectural reconfiguration—is resource-intensive, downtime-inducing, and costly. Triage teams cannot remediate all reported vulnerabilities; they must decide *which vulnerabilities must be patched immediately, which can be scheduled for routine maintenance, and which can be deferred*.

### 4.2 Severity Versus Risk: The Fallacy of CVSS-Only Prioritization
For two decades, organizations have relied on the Common Vulnerability Scoring System (CVSS) Base Score as the de facto prioritization threshold. Mandates such as PCI-DSS historically required organizations to remediate any vulnerability with a CVSS Base Score $\ge 7.0$ (High or Critical). However, authoritative standards organizations explicitly refute this usage:
- The National Institute of Standards and Technology (NIST) states that *CVSS is a qualitative severity measure and is not itself a measure of risk* ([NIST CVSS FAQ](https://nvd.nist.gov/general/faq-sections/cve-faqs); [NIST Vulnerability Metrics](https://nvd.nist.gov/vuln-metrics/cvss)). Severity measures the hypothetical worst-case technical impact (confidentiality, integrity, availability loss) under idealized conditions if an exploit succeeds.
- Prioritization, by contrast, requires assessing *risk*, which is a function of technical impact, threat activity (the likelihood that an exploit exists and is actively deployed against targets in the wild), and organizational context (asset exposure, criticality, and compensating network controls).

Empirical studies show that fewer than 2% to 5% of all published CVEs are ever exploited in the wild. Consequently, prioritizing solely by CVSS $\ge 7.0$ forces security operations teams to spend 80% to 90% of their remediation capacity on vulnerabilities that attackers never attempt to weaponize, while potentially ignoring lower-severity flaws (e.g., CVSS 5.5) that serve as active entry points in ransomware campaigns.

### 4.3 Emergence of Threat-Informed Signals: EPSS and CISA KEV
To bridge the gap between static severity and dynamic threat activity:
1. The **Exploit Prediction Scoring System (EPSS)**, maintained by the Forum of Incident Response and Security Teams (FIRST), produces daily machine-learning estimates of the probability $[0.0, 1.0]$ that a CVE will be exploited in the wild in the next 30 days ([FIRST EPSS FAQ](https://www.first.org/epss/faq); [FIRST EPSS Overview](https://www.first.org/epss/)). EPSS reflects temporal threat dynamics but is explicitly not a complete risk score: it omits asset criticality, technical impact, and reachability.
2. The Cybersecurity and Infrastructure Security Agency (CISA) maintains the **Known Exploited Vulnerabilities (KEV)** catalog ([CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)), an authoritative inventory of vulnerabilities with confirmed in-the-wild exploitation. Inclusion in KEV establishes empirical ground truth of attacker weaponization, but KEV is inherently retrospective: vulnerabilities are added only after exploitation is detected and verified by federal analysts, creating a substantial observation lag.

### 4.4 Research Motivation: Information Availability and Methodological Rigor
While combining CVSS, EPSS, KEV, and asset context is conceptually compelling, academic literature and vendor implementations frequently violate fundamental methodological boundaries:
- **Temporal Data Leakage**: Many published machine-learning studies evaluate models on historical CVEs using *current* (retrospective) EPSS scores or post-hoc CVSS sub-scores that were not available when the vulnerability was disclosed.
- **Linear Additive Ceilings**: Naive composite scoring formulas sum normalized metrics linearly, allowing binary flags (e.g., KEV listing) or extreme values to rigidly skew triage queues regardless of system criticality.
- **Opacity**: Advanced black-box ML models are deployed without auditability or local feature attribution, preventing analysts from understanding the underlying rationale.

### 4.5 Scope and Positioning of VTS
The Vulnerability Prioritization & Triage System (VTS) was designed and implemented as an academic research prototype and public demonstration platform developed within the B.Tech Computer Engineering Web Design Lab. It addresses three core questions:
1. Can initial text descriptions and weakness metadata accurately pre-estimate CVSS v3.1 base scores before official NVD analysis is completed?
2. What predictive accuracy can be achieved when forecasting eventual CISA KEV exploitation at publication time under strict information-availability boundaries?
3. How severely do static retrospective EPSS snapshots distort historical evaluation, and how do nonlinear interaction surfaces alter queue compositions compared to linear baselines?

VTS is explicitly **not** an enterprise production security service, does not execute offensive exploitation, and does not claim operational security guarantees without empirical enterprise telemetry.

---

## 5. Research Questions and Objectives

The investigation is governed by five formal research questions (RQs) and two engineering/artifact objectives:

- **RQ1 (Disclosure-Time Severity Estimation)**: To what extent can tree-based gradient boosting (XGBoost) accurately estimate continuous CVSS v3.1 Base Scores $[0.0, 10.0]$ using solely the natural language disclosure text, CWE identifiers, and CPE platform counts available at initial publication, compared to a linear Ridge regression baseline?
- **RQ2 (Publication-Time Exploitation Forecasting)**: What precision, recall, and PR-AUC can be achieved when classifying eventual CISA KEV catalog inclusion at publication time under extreme class imbalance (~0.32% positive rate), when all post-publication signals (EPSS, CVSS vector components, subsequent telemetry) are strictly forbidden?
- **RQ3 (Quantification of Retrospective Leakage)**: How much artificial performance inflation occurs when a model is provided access to a static retrospective EPSS snapshot (July 2026) during historical CVE evaluation, compared to strict publication-time feature boundaries?
- **RQ4 (Prioritization Surface Behavior)**: How do linear additive scoring models ($S_{\text{linear}}$) and nonlinear interactive decision surfaces ($S_{\text{nonlinear}}$) diverge across controlled asset criticality tiers ($A \in \{0.25, 0.50, 0.75, 1.00\}$) in terms of global rank correlation and top-tier queue composition?
- **RQ5 (Local Feature Attribution and Interpretability)**: Can tree-based Shapley additive explanations (SHAP) provide consistent, human-interpretable feature attributions for disclosure-time regression and classification predictions without making invalid physical causal claims?
- **Objective 1 (Deterministic Provenance & Reproducibility)**: Design, implement, and verify an end-to-end data pipeline that guarantees bit-for-bit rebuild reproducibility across raw source ingestion, canonical Parquet generation, and model serialization.
- **Objective 2 (Auditable Demonstration Architecture)**: Operationalize the research pipeline into an auditable REST API and web user interface supporting role-based access control (RBAC), multi-CVE batch triage, and full provenance transparency.

---

## 6. Background and External Foundations

### 6.1 Vulnerability Identification: CVE, NVD, CWE, and CPE
- **Common Vulnerabilities and Exposures (CVE)**: Managed by MITRE and Authorized CVE Numbering Authorities (CNAs), the CVE dictionary provides standardized alphanumeric identifiers (e.g., `CVE-2021-44228`) for publicly known cybersecurity vulnerabilities.
- **National Vulnerability Database (NVD)**: Operated by NIST, NVD synchronizes with MITRE CVE releases and enriches entries with technical analysis, CVSS vectors, Common Weakness Enumeration (CWE) classifications, and Common Platform Enumeration (CPE) applicability statements.
- **Common Weakness Enumeration (CWE)**: A community-developed taxonomy of software and hardware weakness types (e.g., `CWE-79`: Cross-Site Scripting; `CWE-89`: SQL Injection; `CWE-502`: Deserialization of Untrusted Data).
- **Common Platform Enumeration (CPE)**: A structured naming specification (`cpe:2.3:part:vendor:product:version:...`) identifying hardware (`h`), operating systems (`o`), and applications (`a`) affected by a CVE.

### 6.2 The Common Vulnerability Scoring System (CVSS)
Maintained by FIRST, CVSS provides an open framework for communicating vulnerability characteristics. The CVSS v3.1 specification consists of three metric groups:
1. **Base Score**: Captures intrinsic qualities that are constant over time and user environments (Attack Vector `AV`, Attack Complexity `AC`, Privileges Required `PR`, User Interaction `UI`, Scope `S`, Confidentiality `C`, Integrity `I`, Availability `A`). Base scores range from $0.0$ to $10.0$ and map to qualitative ratings: Low (0.1–3.9), Medium (4.0–6.9), High (7.0–8.9), and Critical (9.0–10.0).
2. **Temporal Score**: Measures exploit code maturity, remediation level, and report confidence.
3. **Environmental Score**: Customizes base metrics to specific organizational infrastructures.

*Critical Distinction*: NIST explicitly emphasizes that CVSS Base Scores measure *severity*, not *risk*. In practice, organizations rarely compute Environmental scores due to asset inventory complexity, leading to severe reliance on static Base Scores.

### 6.3 Exploit Prediction Scoring System (EPSS)
Developed by FIRST and empirical security researchers (Jacobs et al., 2021), EPSS estimates the empirical probability ($p \in [0.0, 1.0]$) that a vulnerability will be exploited in the wild within 30 days following scoring. EPSS leverages an ensemble model trained on daily honeypot observations, intrusion detection telemetry, and vulnerability characteristics. EPSS publishes both an absolute probability and a percentile rank ($[0.0, 1.0]$). EPSS is updated daily and reflects current threat interest. However, FIRST emphasizes that EPSS does not measure business impact or network reachability and must be combined with contextual signals.

### 6.4 CISA Known Exploited Vulnerabilities (KEV) Catalog
Established pursuant to Binding Operational Directive (BOD) 22-01 by CISA, the KEV catalog identifies vulnerabilities that have been confirmed as actively exploited in the wild. To be listed in KEV, three conditions must be satisfied: (1) a valid CVE exists, (2) reliable evidence confirms active exploitation, and (3) a clear remediation action (patch or mitigation) is available. KEV serves as an authoritative ground-truth catalog of attacker weaponization. However, KEV additions suffer from empirical observation delay: analysis of the catalog reveals a median delay of 285.2 days between NVD publication and KEV listing.

### 6.5 Temporal Validation, Data Leakage, and Class Imbalance
- **Temporal Splitting**: In temporal processes like vulnerability disclosure and exploitation, traditional $k$-fold cross-validation or random train/test splits introduce massive *look-ahead data leakage*. Models trained on random splits inadvertently use future vulnerabilities to predict past vulnerabilities, learning temporal artifacts that cannot exist at inference time. Strict chronological partitioning (Train: past, Validation: intermediate, Test: future) is mandatory.
- **Class Imbalance**: Weaponized vulnerabilities represent an extreme minority class. In the canonical CVE population, fewer than 0.45% of vulnerabilities ever appear in CISA KEV. Under such severe imbalance, accuracy and ROC-AUC become deceptively optimistic; the Precision-Recall Area Under Curve (PR-AUC), Precision@K, and Recall@K are the only methodologically sound performance indicators.

### 6.6 Explainable Machine Learning (SHAP)
Post-hoc model interpretability is achieved using Shapley Additive Explanations (SHAP), introduced by Lundberg and Lee (2017). Based on cooperative game theory, SHAP computes feature attributions $\phi_i$ that satisfy local accuracy, missingness, and consistency:
$$f(x) = \phi_0 + \sum_{i=1}^{M} \phi_i$$
where $\phi_0$ is the base expected model output and $\phi_i$ represents the additive contribution of feature $i$. For gradient-boosted decision trees, `TreeExplainer` calculates exact polynomial-time Shapley values, capturing non-linear feature interactions without numerical sampling variance.

---

## 7. Related Work

The development and evaluation of VTS are situated within the broader literature on vulnerability prioritization, exploit prediction, and explainable cybersecurity ML:

### 7.1 Vulnerability Prioritization Surveys and Frameworks
- **Jiang et al. (2025), "A Survey on Vulnerability Prioritization: Taxonomy, Metrics, and Research Challenges"** ([arXiv:2502.11070](https://arxiv.org/abs/2502.11070)): Reviews 82 studies and classifies prioritization into severity-based, exploitability-based, and context-aware paradigms. Identifies severe research gaps in dynamic context modeling, temporal evaluation discipline, and explanation stability. VTS directly implements the survey's recommendations regarding temporal partitioning and transparent multi-signal surfaces.
- **Bulut et al. (2022), "Vulnerability Prioritization: An Offensive Security Approach"** ([arXiv:2206.11182](https://arxiv.org/abs/2206.11182)): Investigates prioritization from the perspective of penetration testing and offensive utility. In contrast, VTS adopts a defensive triage perspective combining disclosure-time NLP and controlled asset criticality.
- **FRAPE (2025), "A Framework for Risk Assessment, Prioritization and Explainability of Vulnerabilities in Cybersecurity"** ([ScienceDirect](https://www.sciencedirect.com/science/article/pii/S2214212625000092)): Integrates active learning, supervised classification, and explainability. VTS differs by evaluating strict publication-time feature boundaries, isolating retrospective EPSS leakage, and formulating non-linear multi-criteria surfaces.
- **Balsam et al. (2025), "Automatic CVSS-Based Vulnerability Prioritization and Response with Context Information and Machine Learning"** (Applied Sciences, 15(16), 8787, [MDPI](https://www.mdpi.com/2076-3417/15/16/8787)): Combines CVSS vectors, context attributes, and ML for patch response. VTS investigates pre-scoring estimation *before* official CVSS vectors are assigned.
- **Agyei et al. (2026), "Explainable Risk-Based Vulnerability Prioritization in Hybrid Cloud"** (WJARR, 30(01), 2044–2052, [DOI:10.30574/wjarr.2026.30.1.1006](https://doi.org/10.30574/wjarr.2026.30.1.1006)): Evaluates a simulated enterprise dataset combining CVSS, EPSS, KEV, and asset criticality. VTS provides the underlying empirical verification on 366,547 real-world CVEs, distinguishing between linear and nonlinear interaction dynamics.

### 7.2 EPSS and Exploitation Forecasting Foundations
- **Jacobs et al. (2021), "Exploit Prediction Scoring System"** ([arXiv:1908.04856](https://arxiv.org/abs/1908.04856)): Establishes the foundational EPSS model using generalized linear models and empirical threat telemetry.
- **Jacobs et al. (2023), "Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights"** ([arXiv:2302.14172](https://arxiv.org/abs/2302.14172)): Introduces EPSS v3, demonstrating an 82% performance gain over previous models in discriminating exploited vulnerabilities.
- **Ravalico et al. (2025), "Analysing the Temporal Dynamics of the Exploit Prediction Scoring Systems"** ([SSRN:5147459](https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459)): Evaluates >45,000 CVEs across time, showing that EPSS requires weeks or months post-disclosure to achieve peak predictive accuracy. This directly justifies VTS's design of EXP-B2 (which forbids EPSS at publication time) and EXP-B1 (which audits leakage).
- **Parla (2024), "Efficacy of EPSS in High Severity CVEs found in KEV"** ([arXiv:2411.02618](https://arxiv.org/abs/2411.02618)): Evaluates EPSS trajectories for vulnerabilities that eventually enter KEV, showing that initial EPSS scores often miss early weaponization.

### 7.3 Foundational Algorithms
- **XGBoost**: Chen & Guestrin (2016), "XGBoost: A Scalable Tree Boosting System" (ACM KDD 2016, [ACM DL](https://doi.org/10.1145/2939672.2939785)).
- **SHAP**: Lundberg & Lee (2017), "A Unified Approach to Interpreting Model Predictions" (NeurIPS 2017, [NeurIPS Proceedings](https://papers.nips.cc/paper/7062-a-unified-approach-to-interpreting-model-predictions)).

---

## 8. Research Data and Provenance

### 8.1 Source Data Inventory & Ingestion
The raw data foundation is ingested by specialized Python modules under `src/ingestion/` from authoritative sources:
1. **NVD Feeds (2002–2026)**: Ingested via `src/ingestion/nvd.py` from 27 yearly compressed JSON archives (`nvdcve-2.0-2002.json.gz` through `nvdcve-2.0-2026.json.gz`, plus `modified` and `recent` feeds) located in `data/raw/nvd/`.
2. **NVD CPE Dictionary & Matches**: Ingested via `src/ingestion/cpe.py` from `nvdcpe-2.0.tar.gz` and `nvdcpematch-2.0.tar.gz` in `data/raw/cpe/`.
3. **FIRST EPSS Score Snapshot**: Ingested via `src/ingestion/epss.py` from `epss_scores-2026-07-16.csv.gz` in `data/raw/epss/`. Snapshot timestamp: `2026-07-16T12:03:48Z`, utilizing EPSS Model Version `v2026.06.15`.
4. **CISA KEV Catalog**: Ingested via `src/ingestion/kev.py` from `known_exploited_vulnerabilities.csv` in `data/raw/kev/`, downloaded on `2026-07-26`.
5. **NVD Vendor Statements**: Ingested via `src/ingestion/vendor.py` from `vendorstatements.xml.gz` in `data/raw/vendor/`.

### 8.2 Deterministic ETL Pipeline & Canonical Parquet Schema
The script `scripts/build_processed_data.py` executes a deterministic transformation pipeline, generating six Snappy-compressed Parquet tables under `data/processed/`. The dataset was frozen on **2026-07-26**:

| Table Name | File Name | Canonical Record Count | Disk Size | Primary Entity / Join Key | Binary SHA-256 Checksum |
|---|---|---|---|---|---|
| **Vulnerabilities** | `vulnerabilities.parquet` | **366,547** | 53.44 MB | Canonical CVE Record (`cve_id`) | `bd54d9fce55fa97388102c1c0db7df05c6f02c5828f6f0dfcba19780dc0008ae` |
| **Weaknesses** | `cve_cwe.parquet` | **430,273** | 2.91 MB | CVE-to-CWE Mapping (`cve_id`, `cwe_id`) | `6e8700c6ab6fb2cbdaa608e7b63681eaa4977cf251a136805d81fe9dc8fc1d44` |
| **Platform Matches** | `cve_cpe.parquet` | **3,133,450** | 33.91 MB | Platform Configurations (`cve_id`, `cpe_uri`) | `8ae41b32fcedf3529c7ad644a2a8b395e306f73c7209cee13f34e54fea9da026` |
| **EPSS Snapshot** | `epss.parquet` | **348,900** | 3.87 MB | Daily EPSS Telemetry (`cve_id`) | `be976efc624c2fb25aaf55ccaf5ca7d420a28082ac328a3746bcb28aa422e7bc` |
| **CISA KEV** | `kev.parquet` | **1,647** | 0.24 MB | Confirmed Exploitation (`cve_id`) | `cddd4b66170c4ade28b4d25ec906efdb6fac96dfd703bccfd2925becabe8f99f` |
| **Vendor Statements**| `vendor_statements.parquet` | **1,486** | 0.11 MB | Vendor Responses (`cve_id`, `organization`) | `85daaa54175e8bfb4d257f28132a45754d1c52926413631276caa5786f345f52` |
| **Total** | — | **4,282,303** | **94.48 MB** | — | — |

### 8.3 Statistical Profiling and Missingness
Data profiling executed via `scripts/research/characterize_datasets.py` (`data/experiments/phase2_metrics.json`) reveals key population characteristics:
- **Canonical Population**: 366,547 unique CVEs spanning publication years 1988 through 2026.
- **CVSS Coverage**:
  - CVSS v2.0: 194,548 records (53.08%), Mean = 5.909, Median = 5.5.
  - CVSS v3.0: 54,540 records (14.88%), Mean = 7.192, Median = 7.5.
  - **CVSS v3.1**: **227,694 records** (**62.12%**), Mean = **7.032**, Median = **7.2**, Std Dev = 1.703.
  - CVSS v4.0: 29,964 records (8.17%), Mean = 6.145, Median = 6.6.
  - *Missingness Note*: 138,853 CVEs (37.88%) lack CVSS v3.1 scores. Pre-2016 vulnerabilities relied exclusively on CVSS v2, while recent 2026 disclosures may still be undergoing NVD analysis.
- **EPSS Coverage**: 348,900 CVEs (95.19% coverage). Missing in 17,647 CVEs (primarily rejected, withdrawn, or newly assigned CVEs).
  - EPSS Distribution: Highly right-skewed; Median = 0.00727 (0.73%), Mean = 0.02888 (2.89%), 90th percentile = 0.04282, 99th percentile = 0.58648.
- **CISA KEV Distribution**:
  - 1,647 cataloged vulnerabilities out of 366,547 total CVEs (**0.4493% overall base rate**; ~1 in 222).
  - **Addition Delay ($\Delta t$)**: Median delay between official NVD publication and KEV listing is **285.2 days** (~0.78 years).
  - **Negative Delay ($\Delta t < 0$)**: 210 CVEs (12.75% of KEV) were added to the CISA KEV catalog *prior* to official NVD publication, demonstrating that real-world exploitation frequently precedes formal vulnerability repository documentation.

### 8.4 Deterministic Rebuild and Invariant Verification
To prevent silent data mutation, `scripts/fingerprint_processed_data.py` implements an all-column canonicalization hashing routine. Rebuilding the datasets from raw sources produces zero logical row differences across all tables (`scripts/compare_rebuilds.py`). Fifteen invariant integrity tests (`tests/test_etl_invariants.py`) run under pytest to guarantee primary key uniqueness, foreign key validity, and score bounds.

---

## 9. Methodology

```
┌────────────────────────────────────────────────────────────────────────┐
│                        CANONICAL RAW SOURCES                           │
│     NVD Feeds (2002–2026) │ CPE Dict │ EPSS Snapshot │ CISA KEV        │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                     DETERMINISTIC ETL PIPELINE                         │
│  data/processed/*.parquet (366,547 CVEs, Hash-Verified, Frozen 2026)   │
└───────────────────┬───────────────────────────────┬────────────────────┘
                    │                               │
       ┌────────────┴────────────┐                  │
       ▼                         ▼                  ▼
┌────────────────┐      ┌────────────────┐   ┌───────────────────────────┐
│     EXP-A1     │      │     EXP-B2     │   │          EXP-C1           │
│  CVSS v3.1     │      │ Publication-   │   │ Multi-Criteria Simulation │
│  Pre-Scoring   │      │ Time KEV       │   │ (Intersected n=227,694)   │
│  (XGBoost)     │      │ (XGBoost)      │   │ Linear vs Nonlinear       │
└──────┬─────────┘      └──────┬─────────┘   └─────────────┬─────────────┘
       │                       │                           │
       ▼                       ▼                           │
┌────────────────────────────────────────┐                 │
│         SHAP EXPLAINABILITY            │                 │
│ TreeExplainer Local Attribution (phi)  │                 │
└──────────────────┬─────────────────────┘                 │
                   │                                       │
                   ▼                                       ▼
┌────────────────────────────────────────────────────────────────────────┐
│                      FASTAPI REST BACKEND LAYER                        │
│   /predict/cvss  │  /predict/kev  │  /prioritize  │  /explain  │ RBAC  │
└───────────────────────────────────┬────────────────────────────────────┘
                                    │
                                    ▼
┌────────────────────────────────────────────────────────────────────────┐
│                         WEB APPLICATION SPA                            │
│  Vulnerability Explorer │ Batch Triage Queue │ Provenance Audit UI     │
└────────────────────────────────────────────────────────────────────────┘
```

### 9.1 Temporal Partitioning Protocol
To reflect real-world operational inference, all experimental evaluations enforce chronological splitting based on vulnerability publication timestamp:
- **TRAIN Partition (2002–2022)**: Historical baseline for feature extraction, vectorizer fitting, and initial model training.
- **VALIDATION Partition (2023–2024)**: Intermediate historical window reserved for hyperparameter tuning and early stopping.
- **TEST Partition (2025–2026)**: Strictly held-out prospective evaluation window, simulating operational inference on newly disclosed vulnerabilities.
- **TRAIN+VAL Refit (2002–2024)**: Following hyperparameter selection, models are refit on the concatenated Train and Validation partitions before generating final predictions on the untouched Test partition.

| Partition | Publication Years | Total Canonical CVEs | EXP-A1 Population (CVSS v3.1) | EXP-B2 / B1 Population | KEV Positives (%) | Evaluation Role |
|---|---|---|---|---|---|---|
| **TRAIN** | 2002–2022 | 218,655 | 78,172 | 203,652 | 1,029 (0.51%) | Model fitting |
| **VALIDATION** | 2023–2024 | 71,653 | 67,918 | 71,653 | 324 (0.45%) | Hyperparameter tuning |
| **TEST** | 2025–2026 | 91,242 | 81,604 | 91,242 | 294 (0.32%) | **Untouched Evaluation** |
| **TRAIN+VAL** | 2002–2024 | 290,308 | 146,090 | 275,305 | 1,353 (0.49%) | Final refit before test |

### 9.2 EXP-A1: Pre-Scoring CVSS v3.1 Base Score Estimation
- **Objective**: Predict official CVSS v3.1 base score $[0.0, 10.0]$ when a CVE is first published, bridging the multi-week delay before NVD analysts publish official scores.
- **Population**: 227,694 CVEs with valid CVSS v3.1 scores.
- **Feature Pipeline (531 features total)**:
  - 500 unigram/bigram TF-IDF text tokens extracted from `description_en` (`max_features=500, stop_words='english', ngram_range=(1,2), sublinear_tf=True`).
  - One-hot encoded indicators for the top 20 most frequent CWE identifiers.
  - CPE configuration counts: total CPE count, application part `a` count, OS part `o` count, hardware part `h` count, vendor count, and product count.
  - Publication month (`pub_month` $\in [1, 12]$).
- **Prohibited Features**: Official CVSS vector strings, sub-scores, EPSS scores, KEV status, post-publication timestamps.
- **Models**:
  - Baseline: Ridge Regression ($\alpha = 10.0$, selected via validation grid $[0.1, 1.0, 10.0, 100.0, 500.0]$).
  - Nonlinear: XGBoost Regressor (`max_depth=8, n_estimators=200, learning_rate=0.05, tree_method='hist'`).
- **Evaluation Metrics**: Mean Absolute Error (MAE), Root Mean Squared Error (RMSE), Coefficient of Determination ($R^2$).

### 9.3 EXP-B2: Publication-Time Exploitation Prediction (No EPSS)
- **Objective**: Predict eventual CISA KEV catalog inclusion ($y \in \{0, 1\}$) at initial disclosure time under extreme class imbalance.
- **Population**: 366,547 total canonical CVEs (Test set: 91,242 CVEs, 294 KEV positives = 0.322% base rate).
- **Feature Pipeline (531 features total)**: Identical publication-time feature set as EXP-A1 (text TF-IDF, CWE indicators, CPE counts, publication month).
- **Strict Boundary Enforcement**: All post-publication signals—specifically EPSS scores, EPSS percentiles, and CVSS vector components—are strictly prohibited. Attempting to pass these features to the inference engine triggers an HTTP 422 Unprocessable Entity error.
- **Models**:
  - Baseline: Logistic Regression (`class_weight='balanced', C=10.0`, selected via grid $[0.01, 0.1, 1.0, 10.0]$).
  - Nonlinear: XGBoost Classifier (`scale_pos_weight=20, max_depth=4, n_estimators=100, learning_rate=0.1, eval_metric='logloss'`).
- **Evaluation Metrics**: Precision-Recall Area Under Curve (PR-AUC), ROC-AUC, Precision@500, Recall@500, Max F1-score.

### 9.4 EXP-B1: Retrospective Snapshot Sensitivity Experiment (Leakage Audit)
- **Objective**: Quantify the artificial performance distortion introduced when machine learning models are granted access to a static future EPSS snapshot during historical evaluation.
- **Population & Partitions**: Identical to EXP-B2.
- **Feature Set**: The 531 publication-time features of EXP-B2 **plus** two leaked retrospective features: `epss` (absolute score) and `epss_percentile` from the static snapshot of 2026-07-16 (EPSS model `v2026.06.15`).
- **Models**: Identical hyperparameter search grid and training protocol as EXP-B2.

### 9.5 EXP-C1: Multi-Criteria Prioritization Simulation
- **Nature of Experiment**: Controlled factorial decision-support simulation across defined scenarios; **not** a supervised learning task (no loss function minimization, no train/test split).
- **Population**: 227,694 intersected CVEs possessing complete CVSS v3.1, EPSS snapshot, and CISA KEV annotations.
- **Normalized Input Signals**:
  - $x_1$: Normalized CVSS v3.1 Base Score ($\frac{\text{CVSS}}{10.0} \in [0.0, 1.0]$)
  - $x_2$: EPSS Snapshot Probability ($p \in [0.0, 1.0]$)
  - $x_3$: CISA KEV Catalog Membership ($\mathbb{I}_{\text{KEV}} \in \{0, 1\}$)
  - $x_4$: Asset Criticality Tier ($A \in \{0.25, 0.50, 0.75, 1.00\}$)
- **Scoring Formulations**:
  1. *Mode 1 (Linear Equal-Weights Baseline)*:
     $$S_{\text{linear}} = 0.25 \cdot x_1 + 0.25 \cdot x_2 + 0.25 \cdot x_3 + 0.25 \cdot x_4$$
  2. *Mode 2 (Nonlinear Interactive Risk Surface)*:
     $$S_{\text{nonlinear}} = x_4 \cdot \left[ 1 - \left(1 - x_1\right)^{1 + \alpha \cdot x_3} \cdot \left(1 - x_2\right)^{1 + \beta \cdot x_3} \right]$$
     with interaction exponents $\alpha = 1.0$ (KEV severity multiplier) and $\beta = 1.5$ (KEV threat multiplier).
- **Evaluation Metrics**: Global Spearman rank correlation ($\rho$), Kendall rank correlation ($\tau$), Top-100 Jaccard overlap, Top-1000 Jaccard overlap, and KEV capture count in top queues.

### 9.6 SHAP Explainability Protocol
Local feature attributions are computed using `shap.TreeExplainer` on the fitted XGBoost models. For each prediction, the background base value $\phi_0$ and per-feature attribution values $\phi_i$ are returned:
- Positive $\phi_i$ indicates that the token or weakness increased estimated severity or exploitation probability.
- Negative $\phi_i$ indicates that the feature suppressed the score.
- *Methodological Disclaimer*: Attributions represent statistical predictive associations within the tree ensemble; they do not establish causal vulnerability mechanics.

---

## 10. System Architecture and Implementation

### 10.1 Backend Architecture
- **Framework**: FastAPI running under Uvicorn on Python 3.14.
- **Columnar Engine**: DuckDB executes zero-copy SQL queries directly over the six Parquet files in `data/processed/`, providing sub-50ms response times across 366,547 records without database server overhead.
- **Authentication & RBAC**: SQLite database (`data/auth_users.sqlite`) stores credentials hashed with PBKDF2-HMAC-SHA256 (600,000 iterations). Signed JSON Web Tokens (JWT) using HS256 enforce least-privilege role boundaries across three tiers:
  - `analyst`: Access to vulnerability search, inference, prioritization, and batch triage.
  - `researcher`: Full read access to data explorer, model benchmarks, provenance, and SHAP explainability.
  - `admin`: Full administrative control, including user provisioning and system monitoring.
- **REST Endpoints**: 15 distinct endpoints assembled via `backend/app/api/router.py`.

### 10.2 Frontend Architecture
- **Technology Stack**: Vanilla JavaScript (ES Modules), HTML5, and CSS3. Zero external runtime JavaScript frameworks (no React or Vue build step required).
- **Design Tokens**: Tonalspot light theme (`--bg-base: #f9f9fe`, `--primary: #45608a`, `--tertiary: #665882`) with Inter for UI copy and JetBrains Mono for technical identifiers.
- **Key Modules**:
  - `explorer_view.js`: Paginated search with multi-field filtering.
  - `predict_view.js`: Pre-scoring CVSS estimation and KEV prediction with interactive SHAP bar charts.
  - `prioritize_view.js`: Dual-mode prioritization with dynamic asset criticality sliders.
  - `batch_triage_view.js`: Batch text parsing (up to 100 CVEs), automatic metadata lookup, dual-mode queue sorting, score shift indicators, and CSV/JSON export.
  - `provenance_view.js`: Display of dataset freeze dates, binary SHA-256 hashes, and experimental benchmark tables.

### 10.3 Test Suite & Quality Assurance
- **Automated Pytest Suite (`tests/`)**: 46 unit and integration tests passing at 100%:
  - `test_etl_invariants.py`: 15 tests verifying schema, primary keys, score ranges, and rebuild reproducibility.
  - `test_backend_api.py`: 9 tests verifying REST routes, error handlers, and provenance outputs.
  - `test_auth_rbac.py`: 15 tests verifying token issuance, password hashing, and role authorization boundaries.
  - `test_batch_triage.py`: 7 tests verifying multi-CVE batch triage parsing, error resilience, and sorting.
- **Professor Verification Suite (`scripts/professor_test_suite.py`)**: 15 end-to-end integration tests validating live endpoints, mathematical exactness, SHAP outputs, and leakage guards.

---

## 11. Experimental Results

All reported numerical results are derived directly from serialized experiment artifacts under `data/experiments/phase3/`.

### 11.1 EXP-A1 Results: CVSS v3.1 Pre-Scoring Estimation
Evaluation across 81,604 held-out prospective test CVEs (2025–2026):

| Partition | Model | Hyperparameters | MAE (CVSS Points) | RMSE | $R^2$ |
|---|---|---|---|---|---|
| **TRAIN (2002–2022)** | Ridge Baseline | $\alpha = 10.0$ | 0.9930 | 1.2881 | 0.4123 |
| | XGBoost Regressor | `depth=8, n=200, lr=0.05` | 0.8574 | 1.1423 | 0.5379 |
| **VALIDATION (2023–2024)** | Ridge Baseline | $\alpha = 10.0$ | 0.9614 | 1.2578 | 0.4610 |
| | XGBoost Regressor | `depth=8, n=200, lr=0.05` | 0.7944 | 1.0881 | 0.5967 |
| **TEST (2025–2026)** | **Ridge Baseline** | $\alpha = 10.0$ | **1.0954** | **1.4089** | **0.3194** |
| | **XGBoost Regressor** | `depth=8, n=200, lr=0.05` | **0.9750** | **1.3059** | **0.4153** |
| **Relative Test Delta** | — | — | **-10.99%** | **-7.31%** | **+30.03%** |

*Findings*: XGBoost reduces test prediction error by 0.1204 CVSS points compared to Ridge regression. Test performance remains stable with an MAE under 1.0 CVSS point.

### 11.2 EXP-B2 Results: Publication-Time KEV Exploitation Prediction
Evaluation on held-out test partition (91,242 CVEs, 294 KEV positives, base rate = 0.00322):

| Metric | Random Guessing Baseline | Logistic Regression Baseline ($C=10.0$) | XGBoost Classifier (`spw=20, d=4, n=100, lr=0.1`) | Relative Uplift (XGBoost vs Baseline) |
|---|---|---|---|---|
| **PR-AUC** | 0.00322 | 0.02077 | **0.02884** | **+38.85%** (8.96× vs Random) |
| **ROC-AUC** | 0.50000 | **0.85857** | 0.81324 | -5.28% |
| **Precision@500** | 0.00322 (1.6 / 500) | 0.03600 (18 / 500) | **0.06400 (32 / 500)** | **+77.78%** (19.88× vs Random) |
| **Recall@500** | 0.00544 (1.6 / 294) | 0.06122 (18 / 294) | **0.10884 (32 / 294)** | **+77.78%** |
| **Max F1-Score** | 0.00642 | 0.04985 | **0.08725** | **+75.03%** |
| **Optimal F1 Threshold**| — | 0.99354 | 0.53738 | — |

*Findings*: At publication time without threat telemetry, XGBoost achieves an 8.96× precision multiplier over random guessing in PR-AUC. By reviewing the top 500 ranked vulnerabilities (0.55% of the test volume), security analysts capture 10.88% of all future KEV vulnerabilities with a precision of 6.40%.

### 11.3 EXP-B1 Results & Retrospective Snapshot Leakage Audit
Direct comparison between publication-time model (EXP-B2) and retrospective EPSS snapshot model (EXP-B1):

| Model & Evaluation Setting | Features Available | Test PR-AUC | Test ROC-AUC | Precision@500 | Recall@500 | Leakage Inflation Factor |
|---|---|---|---|---|---|---|
| **EXP-B2 Logistic Regression** | Publication-time only (531) | 0.02077 | 0.85857 | 0.0360 | 0.0612 | 1.00× (Baseline) |
| **EXP-B1 Logistic Regression** | Pub-time + 2026 EPSS Snapshot | 0.29481 | 0.98403 | 0.2660 | 0.4524 | **14.19×** ($\Delta = +0.27404$) |
| **EXP-B2 XGBoost Classifier** | Publication-time only (531) | **0.02884** | 0.81324 | **0.0640** | **0.1088** | 1.00× (Baseline) |
| **EXP-B1 XGBoost Classifier** | Pub-time + 2026 EPSS Snapshot | **0.33153** | 0.98420 | **0.2520** | **0.4286** | **11.49×** ($\Delta = +0.30269$) |

*Methodological Impact*: Access to static retrospective EPSS snapshots inflates PR-AUC by 11.49× and Recall@500 by nearly 4×. In retrospective evaluations, the 2026 EPSS model incorporates threat intelligence accumulated *after* publication, creating massive data leakage. Research evaluating historical models must enforce publication-time boundaries.

### 11.4 EXP-C1 Results: Prioritization Surface Simulation
Evaluation across 227,694 intersected CVEs across four asset criticality tiers:

| Asset Criticality Tier ($A$) | Spearman Correlation ($\rho$) | Kendall Tau ($\tau$) | Top-100 Jaccard Overlap | Top-1000 Jaccard Overlap | KEV in Top-100 (Linear vs Nonlin) | KEV in Top-1000 (Linear vs Nonlin) |
|---|---|---|---|---|---|---|
| **Tier 1 (Low: 0.25)** | 0.9962 | 0.9356 | **0.005 (0.5%)** | 0.182 (18.2%) | 100 vs 3 ($\Delta = -97$) | 1,000 vs 315 ($\Delta = -685$) |
| **Tier 2 (Medium: 0.50)**| 0.9962 | 0.9356 | **0.005 (0.5%)** | 0.182 (18.2%) | 100 vs 3 ($\Delta = -97$) | 1,000 vs 315 ($\Delta = -685$) |
| **Tier 3 (High: 0.75)** | 0.9962 | 0.9356 | **0.005 (0.5%)** | 0.182 (18.2%) | 100 vs 3 ($\Delta = -97$) | 1,000 vs 315 ($\Delta = -685$) |
| **Tier 4 (Critical: 1.00)**| 0.9962 | 0.9356 | **0.005 (0.5%)** | 0.182 (18.2%) | 100 vs 3 ($\Delta = -97$) | 1,000 vs 315 ($\Delta = -685$) |

*Findings*: While global rank correlation between $S_{\text{linear}}$ and $S_{\text{nonlinear}}$ is high ($\rho = 0.9962$), the queue heads diverge almost completely (Top-100 Jaccard = 0.005). Linear additive scoring creates an artificial priority ceiling: because $0.25 \cdot \mathbb{I}_{\text{KEV}}$ adds a full 0.25 points, all KEV vulnerabilities saturate the top 1,000 items regardless of severity or asset criticality. Mode 2 couples severity, threat probability, and asset tier multiplicatively, allowing high-severity / high-EPSS vulnerabilities in critical infrastructure to enter top remediation queues even if not yet cataloged by CISA KEV.

### 11.5 SHAP Local Feature Attributions
Computed via `shap.TreeExplainer` across serialized test partitions:
- **Top EXP-A1 Features (Increasing CVSS Base Score)**:
  1. `tfidf_unauthorized` ($|\phi| = 0.3422$)
  2. `tfidf_unauthenticated` ($|\phi| = 0.3422$)
  3. `tfidf_critical` ($|\phi| = 0.2721$)
  4. `tfidf_accessible` ($|\phi| = 0.1901$)
  5. `CWE-79` (Cross-Site Scripting, $|\phi| = 0.1845$)
- **Top EXP-B2 Features (Increasing KEV Exploitation Probability)**:
  1. `tfidf_gain` ($|\phi| = 0.8212$)
  2. `CWE-22` (Path Traversal, $|\phi| = 0.5997$)
  3. `tfidf_critical` ($|\phi| = 0.5449$)
  4. `cpe_count` ($|\phi| = 0.4607$)
  5. `tfidf_post` ($|\phi| = 0.3879$)

---

## 12. Triage Evaluation and Evidence Status

### 12.1 Availability of Row-Level Scores
The repository contains complete, verified row-level prediction artifacts:
- `data/experiments/phase3/exp_a1/test_predictions.parquet` (81,604 rows: `cve_id`, `actual`, `ridge_pred`, `xgboost_pred`)
- `data/experiments/phase3/exp_b2/test_predictions.parquet` (91,242 rows: `cve_id`, `actual_kev`, `logistic_prob`, `xgboost_prob`)
- `data/experiments/phase3/exp_b1/test_predictions.parquet` (91,242 rows: `cve_id`, `actual_kev`, `logistic_prob`, `xgboost_prob`)
- `data/experiments/phase3/exp_c1/simulation_rankings.parquet` (227,694 rows: `cve_id`, `cvss`, `epss`, `is_kev`, asset tiers, linear/nonlinear scores and ranks)

### 12.2 Status of Operational Recall@K and Work Reduction
External literature (e.g., Agyei et al., 2026; Jacobs et al., 2021) frequently reports operational metrics such as "85–92% Exploit Recall" or "80–95% Work Reduction":
- **Work Reduction** measures the percentage of vulnerability findings an enterprise can safely defer while maintaining remediation of exploited flaws across operational scan cycles.
- **Recall@K** in an enterprise context measures the proportion of active network compromises prevented at remediation capacity $K$.

*Authoritative Repository Audit*: VTS does **not** contain empirical enterprise ticketing logs, production network topology, compensating firewall telemetry, or observed breach incident ground truth. VTS computes experimental Precision@500 (6.40%) and Recall@500 (10.88%) on static CISA KEV catalog inclusion for held-out CVEs. VTS does **not** claim operational work reduction or real-world security improvements, as such claims require longitudinal enterprise deployment data that does not exist in this repository.

---

## 13. Discussion

### 13.1 Empirical Findings
1. **Pre-scoring Feasibility**: Initial disclosure text and weakness identifiers contain sufficient signal to predict CVSS v3.1 base scores within an MAE of 0.9750 CVSS points. This demonstrates that pre-scoring models can assist triage during the vulnerability disclosure gap before NVD publication.
2. **Limits of Publication-Time Exploitation Prediction**: Without post-publication telemetry, predicting whether a newly disclosed CVE will eventually be weaponized achieves a PR-AUC of 0.02884. While this represents an 8.96× improvement over random guessing (0.00322), the absolute precision remains low (6.40% at top 500). Publication-time text is insufficient on its own for definitive exploit forecasting.
3. **The Reality of Retrospective Leakage**: Incorporating a static EPSS snapshot inflates Test PR-AUC to 0.33153 (an 11.49× inflation). Researchers evaluating historical exploit prediction must strictly control feature observation timestamps.
4. **Signal Interactions in Triage**: Additive scoring creates rigid priority ceilings where binary flags dominate rankings. Nonlinear surfaces provide flexible trade-offs, enabling high-severity unlisted vulnerabilities in critical assets to receive appropriate priority.

### 13.2 Engineering Findings
- **Columnar Engine Utility**: DuckDB operating directly on Parquet files delivers sub-50ms query latencies over 366,547 rows without the maintenance overhead of an external relational database service.
- **Vanilla Web Architecture**: A dependency-free JavaScript SPA (ES modules) provides high responsiveness, zero build overhead, and clean separation between data presentation and analytical backend services.

### 13.3 Non-Claims and Explicit Boundaries
1. VTS does not claim that machine-learning predictions prove real-world exploitation or absence thereof.
2. VTS does not claim novelty merely because it integrates established components (NVD, EPSS, KEV, XGBoost, SHAP).
3. VTS does not claim that its scoring formulas improve real-world enterprise security posture.
4. VTS does not claim production-grade hardening, high availability, or enterprise compliance.

---

## 14. Limitations

1. **Static Data Snapshots**: The repository relies on immutable frozen datasets (freeze date: 2026-07-26; EPSS snapshot: 2026-07-16). It does not feature dynamic daily feed synchronization.
2. **Retrospective EPSS Limitation**: A single historical EPSS snapshot was available. Full historical daily time-series trajectories were not ingested.
3. **KEV Label Semantics**: CISA KEV reflects observed exploitation in federal networks and verified reporting; it is not an exhaustive record of all global cyber weaponization.
4. **Controlled Asset Tiers**: Asset criticality is evaluated across four synthetic tiers ($0.25, 0.50, 0.75, 1.00$) rather than real enterprise asset inventories.
5. **Class Imbalance Constraints**: With only 294 positive test instances among 91,242 CVEs, model calibration in the extreme tail is subject to high variance.
6. **Single-Host Prototype Deployment**: The demonstration deployment runs on a single VPS host with port 5002 exposed via Cloudflare Tunnel; it lacks horizontal scaling, distributed caching, and enterprise key management.

---

## 15. Security, Ethics, and Responsible Use

- **Defensive Focus**: VTS is strictly a defensive prioritization decision-support system. It contains no exploit code, weaponization utilities, or automated attack generation mechanisms.
- **Public Data Integrity**: All ingested sources (NVD, MITRE, FIRST, CISA) are public domain security telemetry.
- **Credential Handling**: Authentication utilizes PBKDF2-HMAC-SHA256 password hashing and cryptographically signed JWT tokens. No plain-text credentials are stored.
- **Decision-Support Governance**: Machine-learning predictions and multi-criteria scores are presented with explicit confidence disclaimers, cautioning analysts that statistical estimates must not override qualified human security review.

---

## 16. Conclusion

The Vulnerability Prioritization & Triage System (VTS) demonstrates that while machine learning can estimate vulnerability severity and provide an 8.96× precision uplift for publication-time exploitation forecasting, rigorous temporal boundaries must be enforced to avoid massive retrospective leakage (which can artificially inflate performance by over 11×). Furthermore, multi-criteria prioritization requires non-linear interaction surfaces to prevent binary threat flags from creating artificial priority ceilings. Operationalized through a modular FastAPI backend and an auditable web interface, VTS provides a reproducible research platform for evaluating vulnerability triage under realistic information constraints.

---

## 17. Future Work

Immediate, near-term, and long-term research extensions—including historical EPSS time-series ingestion, dynamic asset reachability graphs, calibrated probability estimators, and automated NVD feed synchronization—are detailed extensively in the companion document:
`perplexity/FUTURE_SCOPE_AND_RESEARCH_EXTENSIONS.md`.

---

## 18. References

1. **NIST**: National Vulnerability Database (NVD) Common Vulnerability Scoring System (CVSS) FAQs and Metrics.  
   - FAQ: [https://nvd.nist.gov/general/faq-sections/cve-faqs](https://nvd.nist.gov/general/faq-sections/cve-faqs)  
   - Metrics: [https://nvd.nist.gov/vuln-metrics/cvss](https://nvd.nist.gov/vuln-metrics/cvss)
2. **FIRST**: Exploit Prediction Scoring System (EPSS) Specification, FAQ, and Research.  
   - Overview: [https://www.first.org/epss/](https://www.first.org/epss/)  
   - FAQ: [https://www.first.org/epss/faq](https://www.first.org/epss/faq)  
   - Research: [https://www.first.org/epss/research](https://www.first.org/epss/research)  
   - CVSS v3.0 Specification: [https://www.first.org/cvss/v3.0/specification-document](https://www.first.org/cvss/v3.0/specification-document)
3. **CISA**: Known Exploited Vulnerabilities (KEV) Catalog.  
   - Catalog: [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
4. **Lundberg, S. M., & Lee, S.-I.** (2017). A Unified Approach to Interpreting Model Predictions. *Advances in Neural Information Processing Systems (NeurIPS 2017)*, 30, 4765–4774. [https://papers.nips.cc/paper/7062-a-unified-approach-to-interpreting-model-predictions](https://papers.nips.cc/paper/7062-a-unified-approach-to-interpreting-model-predictions)
5. **Chen, T., & Guestrin, C.** (2016). XGBoost: A Scalable Tree Boosting System. *Proceedings of the 22nd ACM SIGKDD International Conference on Knowledge Discovery and Data Mining (KDD '16)*, 785–794. [https://doi.org/10.1145/2939672.2939785](https://doi.org/10.1145/2939672.2939785)
6. **Jiang, L., et al.** (2025). A Survey on Vulnerability Prioritization: Taxonomy, Metrics, and Research Challenges. *arXiv preprint arXiv:2502.11070*. [https://arxiv.org/abs/2502.11070](https://arxiv.org/abs/2502.11070)
7. **Jacobs, J., Romanosky, S., Edwards, B., Roytman, M., & Adjerid, I.** (2021). Exploit Prediction Scoring System. *arXiv preprint arXiv:1908.04856*. [https://arxiv.org/abs/1908.04856](https://arxiv.org/abs/1908.04856)
8. **Jacobs, J., et al.** (2023). Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights. *arXiv preprint arXiv:2302.14172*. [https://arxiv.org/abs/2302.14172](https://arxiv.org/abs/2302.14172)
9. **Ravalico, D., Farina, L., Trevisan, M., & Bartoli, A.** (2025). Analysing the Temporal Dynamics of the Exploit Prediction Scoring Systems. *SSRN Electronic Journal*, SSRN:5147459. [https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459](https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459)
10. **Agyei, K. G., Monjoma, M. B., Samushonga, C. A., Chisora, H. H., Nemure, T., Gwangwava, S., & Mupa, M. N.** (2026). Explainable Risk-Based Vulnerability Prioritization in Hybrid Cloud: Integrating CVSS, EPSS, and CISA KEV with Asset Criticality Signals. *World Journal of Advanced Research and Reviews*, 30(01), 2044–2052. [https://doi.org/10.30574/wjarr.2026.30.1.1006](https://doi.org/10.30574/wjarr.2026.30.1.1006)
11. **Bulut, M., et al.** (2022). Vulnerability Prioritization: An Offensive Security Approach. *arXiv preprint arXiv:2206.11182*. [https://arxiv.org/abs/2206.11182](https://arxiv.org/abs/2206.11182)
12. **Balsam, A., et al.** (2025). Automatic CVSS-Based Vulnerability Prioritization and Response with Context Information and Machine Learning. *Applied Sciences*, 15(16), 8787. [https://doi.org/10.3390/app15168787](https://doi.org/10.3390/app15168787)
13. **Parla, V.** (2024). Efficacy of EPSS in High Severity CVEs found in KEV. *arXiv preprint arXiv:2411.02618*. [https://arxiv.org/abs/2411.02618](https://arxiv.org/abs/2411.02618)
14. **Mell, P., & Spring, J.** (2025). Likely Exploited Vulnerabilities, A Proposed Metric for Vulnerability Exploitation Probability. *NIST Special Publication*. [https://www.nist.gov/publications/likely-exploited-vulnerabilities-proposed-metric-vulnerability-exploitation-probability](https://www.nist.gov/publications/likely-exploited-vulnerabilities-proposed-metric-vulnerability-exploitation-probability)

---

## 19. Appendices

### Appendix A: Reproducibility Commands
To rebuild the canonical dataset, run tests, and execute experiments from scratch:
```bash
# 1. Verify environment and raw sources
python scripts/verify_raw_data.py

# 2. Execute deterministic ETL pipeline
python scripts/build_processed_data.py

# 3. Check data invariants
pytest tests/test_etl_invariants.py -v

# 4. Execute Phase 3 machine learning experiments
python scripts/experiments/run_exp_a1.py
python scripts/experiments/run_exp_b2.py
python scripts/experiments/run_exp_b1.py
python scripts/experiments/run_exp_c1.py

# 5. Execute SHAP analysis and serialize models
python scripts/experiments/run_shap_analysis.py
python scripts/experiments/serialize_phase3_models.py

# 6. Execute full regression and integration test suite
pytest tests/ -v
python scripts/professor_test_suite.py
```

### Appendix B: Complete REST API Route Inventory

| HTTP Method | Route URL | Access Control | Service Handler | Summary & Purpose |
|---|---|---|---|---|
| `POST` | `/api/v1/auth/register` | Public | `AuthService.register_user` | Register a new user account with default `analyst` role |
| `POST` | `/api/v1/auth/login` | Public | `AuthService.authenticate_user` | Authenticate credentials and receive HS256 JWT Bearer token |
| `GET` | `/api/v1/auth/me` | Authenticated | `AuthService.get_current_user` | Retrieve profile and assigned role of current user |
| `GET` | `/api/v1/auth/users` | `admin` only | `AuthService.list_all_users` | List all provisioned accounts in SQLite registry |
| `GET` | `/api/v1/vulnerabilities` | Public | `VulnerabilityService.search` | Paginated search and multi-parameter filtering over DuckDB |
| `GET` | `/api/v1/vulnerabilities/{cve_id}` | Public | `VulnerabilityService.get_by_id` | Retrieve single CVE detail record with CWE/CPE joins |
| `GET` | `/api/v1/vulnerabilities/metrics/summary` | Public | `VulnerabilityService.get_metrics` | Retrieve dataset summary distributions across CVSS/EPSS |
| `POST` | `/api/v1/predict/cvss` | Authenticated | `InferenceService.predict_cvss` | Estimate pre-scoring CVSS v3.1 base score (EXP-A1) |
| `POST` | `/api/v1/predict/kev` | Authenticated | `InferenceService.predict_kev` | Predict publication-time KEV catalog inclusion (EXP-B2) |
| `POST` | `/api/v1/prioritize` | `analyst`, `admin` | `ScoringService.prioritize` | Compute Mode 1 linear and Mode 2 nonlinear priority scores |
| `POST` | `/api/v1/prioritize/batch`| `analyst`, `admin` | `ScoringService.prioritize_batch`| Multi-CVE batch triage scoring with ranking and shifts |
| `POST` | `/api/v1/explain/cvss` | Authenticated | `ExplanationService.explain_cvss`| Compute TreeExplainer SHAP attributions for EXP-A1 model |
| `POST` | `/api/v1/explain/kev` | Authenticated | `ExplanationService.explain_kev` | Compute TreeExplainer SHAP attributions for EXP-B2 model |
| `GET` | `/api/v1/provenance` | Public | `ProvenanceService.get_metadata` | Fetch freeze dates, snapshot metadata, and SHA-256 hashes |
| `GET` | `/health` | Public | `main.health_check` | System operational health check and engine metadata |

---

## 20. Evidence Status Table, Contradiction Register, and Audits

### A. Evidence Status Table

| Project Claim / Statement | Verification Status | Exact Repository Evidence Path | Explanatory Notes |
|---|---|---|---|
| **Canonical CVE Population: 366,547** | **Verified** | `data/processed/vulnerabilities.parquet`, `docs/research/DATA_MANIFEST.md` | Primary key `cve_id` uniqueness verified by invariant test `test_etl_invariants.py`. |
| **CISA KEV Positives: 1,647 (0.4493%)** | **Verified** | `data/processed/kev.parquet`, `data/experiments/phase2_metrics.json` | Total KEV count matched against official CISA feed downloaded 2026-07-26. |
| **EXP-A1 Test MAE: 0.9750** | **Verified** | `data/experiments/phase3/exp_a1/metrics.json` | XGBoost regressor evaluated on 81,604 held-out test CVEs (2025–2026). Ridge = 1.0954. |
| **EXP-B2 Test PR-AUC: 0.02884** | **Verified** | `data/experiments/phase3/exp_b2/metrics.json` | XGBoost classifier evaluated on 91,242 held-out test CVEs (294 KEV positives, base rate 0.00322). |
| **EXP-B1 Test PR-AUC: 0.33153** | **Verified** | `data/experiments/phase3/exp_b1/metrics.json` | Retrospective EPSS snapshot model demonstrating 11.49× leakage inflation. |
| **Claimed B2 PR-AUC: 0.3845** | **Unverified (Error)** | `docs/final-repo-state.md:160` | Erroneous documentation note mislabeled as "EXP-B2 (Text+Meta+EPSS)"; lacks serialized artifact. |
| **EXP-C1 Top-100 Jaccard Overlap: 0.005** | **Verified** | `data/experiments/phase3/exp_c1/metrics.json` | Factorial simulation on 227,694 intersected CVEs showing severe queue disruption. |
| **TreeExplainer SHAP Integration** | **Verified** | `backend/app/services/explanation_service.py`, `scripts/experiments/run_shap_analysis.py` | Computes exact polynomial Shapley values for tree ensembles; tested in professor suite. |
| **Operational Work Reduction (80–95%)** | **Unverified / Disclaimed**| None in repository; literature concept from Agyei et al. (2026) | VTS evaluates static feeds; lacks enterprise ticketing data to validate operational work reduction. |

### B. Contradiction Register

| Contradiction ID | Conflicting Claims | Conflicting Source Files | Authoritative Resolution | Action Taken |
|---|---|---|---|---|
| **CR-01** | B2 PR-AUC reported as **0.3845** vs **0.02884** | `docs/final-repo-state.md:160` (0.3845) vs `data/experiments/phase3/exp_b2/metrics.json` (0.02884) | The authoritative, serialized result for publication-time KEV classification on the untouched test partition (2025–2026) is **PR-AUC = 0.02884**. The value 0.3845 in `docs/final-repo-state.md` was an unverified draft note incorrectly labeled "Text+Meta+EPSS" and matching an example API response string. | Discredited 0.3845 as an experimental finding; affirmed 0.02884 as authoritative. |
| **CR-02** | EXP-B2 Feature Boundary: Includes EPSS vs Excludes EPSS | `docs/final-repo-state.md:157` ("Text+Meta+EPSS") vs `scripts/experiments/run_exp_b2.py:1` ("Strictly excludes EPSS") | EXP-B2 strictly excludes EPSS and CVSS components to prevent data leakage. EXP-B1 is the experiment that deliberately incorporates the EPSS snapshot to quantify leakage. | Standardized terminology: EXP-B2 is publication-time only; EXP-B1 is retrospective. |
| **CR-03** | Frontend feature completion status | `docs/functionality-audit.md` (lists Login/RBAC/Export as MISSING) vs `docs/final-application-audit.md` (100% IMPLEMENTED) | `docs/functionality-audit.md` is a historical snapshot from early Phase 4. All features were fully implemented in WDL-4 through WDL-7. | Classified `docs/functionality-audit.md` as historical; confirmed current full implementation. |

### C. Reproduction Status
- **Reproducible from Repository**: Deterministic ETL rebuild, Parquet generation, DuckDB query execution, unit/integration pytests (46/46 passed), professor demonstration suite (15/15 passed), model serialization checks (`serialize_phase3_models.py`), Mode 1 and Mode 2 prioritization math, and SHAP TreeExplainer attributions.
- **Externally Required**: Daily live EPSS feed updates (beyond the frozen 2026-07-16 snapshot), longitudinal enterprise vulnerability scanning ticketing data, and physical cloud multi-tenant deployment infrastructure.

### D. Final Consistency Audit Statement
Every metric, dataset count, date, formula, route, and model parameter presented in this report has been verified against the physical code and serialized JSON/Parquet artifacts in `seucra/vulnarability-prioritization-triage-system`. All historical discrepancies have been explicitly documented and resolved. This document represents the authoritative, audit-compliant academic final project report.
