# Research Materials and Positioning for the Vulnerability Prioritization & Triage System (VTS)

**Document Type**: Academic Research Reference, Comparative Literature Analysis & Positioning Dossier  
**Project Identifier**: `seucra/vulnarability-prioritization-triage-system`  
**Academic Context**: B.Tech Computer Engineering Capstone / Web Design Lab  
**Status**: Authoritative Research Positioning Guide (Audited October 2026)  

---

## 1. Purpose and Scope

This document provides the foundational research positioning for the Vulnerability Prioritization & Triage System (VTS). It situates the project within the current peer-reviewed literature, maps authoritative industry standards, establishes precise boundaries between verified empirical evidence and preliminary observations, and systematically audits claims to prevent unsupported assertions of novelty or real-world operational superiority.

VTS is a research prototype evaluating the interaction between vulnerability severity estimation, threat forecasting under strict temporal constraints, retrospective data leakage, and multi-criteria decision surfaces. It is **not** an enterprise production security service, does not execute offensive cyber operations, and does not claim to eliminate cyber risk without enterprise asset telemetry.

---

## 2. Field Map: The Vulnerability Prioritization Research Landscape

The academic and industrial research landscape surrounding software vulnerability management is organized into eight interconnected sub-fields:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│                     1. Vulnerability Representation                     │
│        (CVE Identifiers, CWE Weakness Hierarchies, CPE Platforms)       │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
         ┌───────────────────────────┴───────────────────────────┐
         ▼                                                       ▼
┌─────────────────────────────────┐   ┌───────────────────────────────────┐
│     2. Severity Scoring         │   │      3. Exploit Prediction        │
│ (NVD CVSS Base Scores v2/v3/v4; │   │ (EPSS Daily Estimates; Disclosure-│
│ Pre-Scoring NLP Base Estimates) │   │ Time Machine Learning Classifiers)│
└────────────────┬────────────────┘   └─────────────────┬─────────────────┘
                 │                                      │
                 │         ┌────────────────────────────┘
                 ▼         ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                     4. Exploitation Ground Truth                        │
│       (CISA Known Exploited Vulnerabilities - KEV Catalog; Honeypots)   │
└────────────────────────────────────┬────────────────────────────────────┘
                                     │
         ┌───────────────────────────┴───────────────────────────┐
         ▼                                                       ▼
┌─────────────────────────────────┐   ┌───────────────────────────────────┐
│     5. Context-Aware Risk       │   │    6. Prioritization Surfaces     │
│ (Asset Criticality Tiers; WAF;  │   │  (Linear Additive Baselines vs.   │
│ Reachability; Business Impact)  │   │  Nonlinear Multiplicative Surfaces│
└────────────────┬────────────────┘   └─────────────────┬─────────────────┘
                 │                                      │
                 └───────────────────────────┬──────────┘
                                             │
                                             ▼
┌─────────────────────────────────────────────────────────────────────────┐
│                  7. Explainable ML & Reproducibility                    │
│    (Shapley Additive Explanations - SHAP; Immutable Parquet Provenance) │
└─────────────────────────────────────────────────────────────────────────┘
```

---

## 3. Standards and Authoritative Data Sources

Academic positioning requires referencing original, primary specifications rather than secondary trade blogs:

### 3.1 Common Vulnerability Scoring System (CVSS)
- **Authoritative Source**: FIRST CVSS v3.1 Specification and NIST NVD Metrics Guide.
- **Official URLs**:
  - NIST CVSS FAQ: [https://nvd.nist.gov/general/faq-sections/cve-faqs](https://nvd.nist.gov/general/faq-sections/cve-faqs)
  - NIST Vulnerability Metrics: [https://nvd.nist.gov/vuln-metrics/cvss](https://nvd.nist.gov/vuln-metrics/cvss)
  - FIRST Specification: [https://www.first.org/cvss/v3.0/specification-document](https://www.first.org/cvss/v3.0/specification-document)
- **Definitive Standard Statement**: NIST explicitly states that *CVSS is a qualitative severity measure and is not itself a measure of risk*. CVSS Base Scores assume worst-case technical impact under idealized attacker access. They do not incorporate active threat activity or local organizational infrastructure.

### 3.2 Exploit Prediction Scoring System (EPSS)
- **Authoritative Source**: FIRST EPSS Working Group.
- **Official URLs**:
  - FIRST EPSS Overview: [https://www.first.org/epss/](https://www.first.org/epss/)
  - FIRST EPSS FAQ: [https://www.first.org/epss/faq](https://www.first.org/epss/faq)
  - FIRST EPSS Research: [https://www.first.org/epss/research](https://www.first.org/epss/research)
- **Definitive Standard Statement**: FIRST defines EPSS as a daily machine-learning estimate of the probability that a software vulnerability will be exploited in the wild within the next 30 days. FIRST explicitly warns that *EPSS is not a complete risk score*; it captures global threat interest, but ignores asset business value, technical severity, and network reachability.

### 3.3 CISA Known Exploited Vulnerabilities (KEV) Catalog
- **Authoritative Source**: Cybersecurity and Infrastructure Security Agency (CISA).
- **Official URL**: [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- **Definitive Standard Statement**: Established pursuant to Binding Operational Directive (BOD) 22-01, KEV provides an authoritative baseline of vulnerabilities confirmed to have been exploited in the wild. KEV inclusion establishes verified weaponization, but suffers from observation and reporting latency.

### 3.4 Algorithmic Foundations
- **XGBoost**: Chen, T., & Guestrin, C. (2016). XGBoost: A Scalable Tree Boosting System. *ACM KDD 2016*, 785–794. [https://doi.org/10.1145/2939672.2939785](https://doi.org/10.1145/2939672.2939785).
- **SHAP**: Lundberg, S. M., & Lee, S.-I. (2017). A Unified Approach to Interpreting Model Predictions. *NeurIPS 2017*, 30, 4765–4774. [https://papers.nips.cc/paper/7062-a-unified-approach-to-interpreting-model-predictions](https://papers.nips.cc/paper/7062-a-unified-approach-to-interpreting-model-predictions).

---

## 4. Literature Review by Theme

### 4.1 CVSS Limitations and Severity-vs-Risk Literature
- **Albab (2025), "Severity vs Risk: The Limitations of CVSS"** ([University of Twente](https://essay.utwente.nl/essays/106247)): Systematic review showing that conventional CVSS-threshold triage ($\text{CVSS} \ge 7.0$) results in 80–90% false positive remediation overhead, as the vast majority of High/Critical vulnerabilities are never weaponized.
- **Suciu et al. (2022), "Exploring the Exploit Prediction Frontier"**: Demonstrates that technical severity metrics correlate weakly with real-world attacker exploit selection.

### 4.2 Machine Learning Exploit Prediction & EPSS Evolution
- **Jacobs et al. (2021), "Exploit Prediction Scoring System"** ([arXiv:1908.04856](https://arxiv.org/abs/1908.04856)): Introduces the initial EPSS model using generalized linear models across dark web chatter, honeypots, and vulnerability characteristics.
- **Jacobs et al. (2023), "Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights"** ([arXiv:2302.14172](https://arxiv.org/abs/2302.14172)): Documents EPSS v3, reporting an 82% performance uplift over EPSS v2 in discriminating weaponized flaws.
- **Mell & Spring (2025), "Likely Exploited Vulnerabilities (LEV): A Proposed Metric for Vulnerability Exploitation Probability"** ([NIST SP](https://www.nist.gov/publications/likely-exploited-vulnerabilities-proposed-metric-vulnerability-exploitation-probability)): Proposes an alternative federal framework addressing limitations in EPSS sensor coverage and private enterprise visibility.

### 4.3 Temporal Dynamics and Evaluation Leakage
- **Ravalico et al. (2025), "Analysing the Temporal Dynamics of the Exploit Prediction Scoring Systems"** ([SSRN:5147459](https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459)): Evaluates >45,000 CVEs across longitudinal daily snapshots. Demonstrates that EPSS scores require multiple weeks post-disclosure to accumulate threat telemetry, warning against the use of retrospective snapshots in historical machine learning evaluations. This paper provides direct theoretical validation for VTS's EXP-B1 and EXP-B2 experimental design.
- **Parla (2024), "Efficacy of EPSS in High Severity CVEs found in KEV"** ([arXiv:2411.02618](https://arxiv.org/abs/2411.02618)): Analyzes EPSS trajectories for vulnerabilities that eventually enter KEV, showing that pre-weaponization EPSS scores are often low until active exploitation begins.

### 4.4 Vulnerability Prioritization Frameworks
- **Jiang et al. (2025), "A Survey on Vulnerability Prioritization: Taxonomy, Metrics, and Research Challenges"** ([arXiv:2502.11070](https://arxiv.org/abs/2502.11070)): Reviews 82 studies. Identifies key challenges: temporal evaluation discipline, dynamic context integration, and interpretability.
- **Bulut et al. (2022), "Vulnerability Prioritization: An Offensive Security Approach"** ([arXiv:2206.11182](https://arxiv.org/abs/2206.11182)): Investigates prioritization from the offensive pen-tester perspective.
- **FRAPE (2025), "A Framework for Risk Assessment, Prioritization and Explainability of Vulnerabilities in Cybersecurity"** ([ScienceDirect](https://www.sciencedirect.com/science/article/pii/S2214212625000092)): Integrates active learning, supervised classification, and explainability.
- **Balsam et al. (2025), "Automatic CVSS-Based Vulnerability Prioritization and Response with Context Information and Machine Learning"** ([MDPI](https://www.mdpi.com/2076-3417/15/16/8787)): Combines CVSS vectors and context for patch scheduling.
- **Agyei et al. (2026), "Explainable Risk-Based Vulnerability Prioritization in Hybrid Cloud"** ([WJARR, DOI:10.30574/wjarr.2026.30.1.1006](https://doi.org/10.30574/wjarr.2026.30.1.1006)): Evaluates a simulated enterprise dataset (~25,000 vulnerabilities across 12,000 assets) combining CVSS, EPSS, KEV, and asset criticality. Claims 80–95% work reduction and 85–92% exploit recall. *VTS distinction*: VTS provides the empirical verification on 366,547 real CVEs, distinguishing between linear and nonlinear interaction dynamics without claiming enterprise operational work reduction.

---

## 5. Comparative Source Table

The following matrix compares VTS against the closest peer-reviewed literature and industrial frameworks:

| Study / Source | Problem Studied | Data Corpus | Core Methodology | Evaluation Protocol | Explainability | Context Integration | Temporal Split Design | Artifact & Reproducibility | Direct Relation to VTS |
|---|---|---|---|---|---|---|---|---|---|
| **Jiang et al. (2025)** | Comprehensive prioritization survey | 82 reviewed primary studies | Survey taxonomy of metrics and algorithms | Qualitative review of experimental designs | Qualitative survey of XAI techniques | Analyzes environmental factors | Highlights temporal leakage as major field gap | None (Survey paper) | Establishes the taxonomy and open challenges addressed by VTS. |
| **Jacobs et al. (2021, 2023)** | Daily exploit probability forecasting | Global honeypots, IDS feeds, NVD (daily) | Generalized linear models, gradient boosting | 30-day forward rolling prospective evaluation | Linear regression coefficients | None (Global threat only) | Strict daily time-series forward prediction | Code private; daily scores published openly | VTS utilizes EPSS as an input signal in C1 and audits retrospective leakage in B1. |
| **Ravalico et al. (2025)** | Temporal stability of EPSS scores | >45,000 CVEs across daily EPSS snapshots | Longitudinal time-series statistical modeling | Tracking score changes from disclosure ($t_0$ to $t_{180}$) | Statistical distribution analysis | None | Longitudinal daily time tracking | Scripts partially open; uses public FIRST data | Proves EPSS takes weeks to accumulate signal; directly justifies VTS EXP-B2 design. |
| **Agyei et al. (2026)** | Hybrid cloud vulnerability prioritization | Simulated hybrid cloud (25k vulns, 12k assets) | Weighted linear composite score + KEV override | Simulated work reduction & exploit recall | Rule-based natural language templates | Simulated asset tiers, exposure, WAF | Static snapshot simulation | Private dataset; no public artifact | Closest structural precursor; VTS replaces linear formula with nonlinear surface. |
| **FRAPE (2025)** | Cybersecurity risk & prioritization | NVD, Exploit-DB, GitHub advisories | Supervised ML + Active Learning | Stratified cross-validation | SHAP / LIME local attributions | Basic asset tags | Random / stratified cross-validation (leaky) | Semi-open research code | VTS enforces strict temporal splitting, preventing the look-ahead leakage present in FRAPE. |
| **VulRG (Jiang 2025)** | Multi-level patch ranking in complex systems | System dependency & attack path graphs | Graph Neural Networks (GNN) | Topological reachability ranking | Subgraph attribution | Deep dependency & network graph | Static network snapshot | Research code on GitHub | Represents ambitious future scope for VTS (graph modeling). |
| **VTS (This Work)** | Disclosure-time estimation, leakage audit, nonlinear surfaces | **366,547 canonical CVEs (1988–2026)** | **XGBoost, Ridge, Logistic, Nonlinear Surface** | **Strict Chronological: Train $\le$2022, Val 23–24, Test 25–26** | **Exact TreeExplainer SHAP + Causal Guards** | **Controlled Asset Criticality Tiers (0.25–1.0)** | **Strict Temporal Partitioning (Zero Leaked Telemetry in B2)** | **Fully open: Parquet data, serialized models, 46 pytests** | **Authoritative baseline combining empirical rigor, leakage audit, and auditable demo.** |

---

## 6. VTS Research-Positioning Map

| VTS Component | Established Scientific Foundation | What VTS Implements | What VTS Measures / Confirms | What VTS Does NOT Establish | Closest Neighboring Literature | Required Evidence for a Stronger Claim |
|---|---|---|---|---|---|---|
| **Data Pipeline & Schema** | NVD JSON 2.0 schema, CPE 2.3 naming standards. | Snappy Parquet tables, DuckDB engine, all-column canonicalization hashing. | Bit-for-bit rebuild reproducibility; sub-50ms query latency over 366k CVEs. | Real-time continuous streaming feed synchronization. | Open CVE repositories; cvelistV5. | Automated cron ingestion pipeline with NVD API 2.0 key. |
| **EXP-A1 (Severity Regressor)** | NLP text representations; tree-based regression (Chen & Guestrin 2016). | 500 TF-IDF n-grams + CWE indicators into XGBoost regressor. | Test MAE = 0.9750 CVSS points (-11% error reduction over Ridge baseline). | Exact replacement for official human NVD analyst scoring. | Balsam et al. (2025); automated CVSS papers. | Per-metric CVSS vector element prediction (AV, PR, UI). |
| **EXP-B2 (Pub-Time Classifier)** | Imbalanced classification; FIRST EPSS theory (Jacobs et al. 2021). | Strict publication-time feature set; rejects all post-publication signals. | Test PR-AUC = 0.02884 (8.96x uplift over random); Precision@500 = 6.40%. | High absolute confidence in individual exploit forecasting. | Ravalico et al. (2025); Parla (2024). | Early pre-disclosure threat intelligence (dark web, GitHub PoCs). |
| **EXP-B1 (Leakage Audit)** | Temporal validation theory in machine learning. | Controlled experiment adding July 2026 EPSS snapshot to EXP-B2. | Quantifies 11.49x artificial PR-AUC inflation ($\Delta = +0.30269$). | Operational predictive utility (EXP-B1 is a scientific control). | Ravalico et al. (2025). | Longitudinal multi-snapshot daily historical EPSS tracking. |
| **EXP-C1 (Prioritization Surface)** | Multi-Attribute Utility Theory (MAUT); Agyei et al. (2026). | Dual-mode closed-form equations ($S_{\text{linear}}$ vs. $S_{\text{nonlinear}}$). | Top-100 Jaccard overlap is only 0.005 (0.5%), proving queue tail disruption. | Real-world enterprise breach reduction or workload savings. | Agyei et al. (2026); FRAPE (2025). | Longitudinal enterprise SOC ticketing logs and breach telemetry. |
| **Explainability Engine** | Cooperative game theory; TreeExplainer (Lundberg & Lee 2017). | Exact local Shapley feature attributions with causality disclaimer guards. | High positive attribution for privilege/gain tokens and CWE-22. | Physical vulnerability or software exploit causality. | FRAPE (2025); Lundberg et al. (2020). | Automated counterfactual code analysis and taint tracking. |

---

## 7. Novelty and Contribution Audit

To ensure defensibility before an academic examination committee, all project claims are audited and classified into six strict categories:

1. **Established by Prior Literature**:
   - CVSS Base Scores measure technical severity, not dynamic operational risk (NIST, Albab 2025).
   - EPSS models exploitation probability globally but lacks organizational asset context (FIRST, Jacobs et al. 2021).
   - CISA KEV reflects confirmed weaponization but suffers from empirical reporting delay (CISA).
   - Gradient boosted trees (XGBoost) outperform linear models on tabular cybersecurity data (Chen & Guestrin 2016).
2. **Implemented Engineering Contributions**:
   - A zero-copy columnar query architecture pairing DuckDB directly with 6 normalized Parquet tables (366,547 CVEs) delivering sub-50ms response times without database server overhead.
   - An automated temporal boundary validator in Pydantic schema intercepting post-publication feature injection with HTTP 422.
   - An integrated Single Page Application with batch queue sorting, score shift tracking, and dynamic SHAP bar charts.
   - A PBKDF2-HMAC-SHA256 and JWT-authenticated RBAC subsystem with 46 passing pytests and 15 professor verification tests.
3. **Empirical Findings of VTS**:
   - Disclosure-time text and weakness metadata achieve a CVSS v3.1 pre-scoring Test MAE of **0.9750** CVSS points across 81,604 prospective test CVEs (EXP-A1).
   - Publication-time KEV exploitation prediction under extreme class imbalance (0.32% base rate) achieves Test PR-AUC of **0.02884** (8.96× uplift over random guessing) and Precision@500 of 6.40% (EXP-B2).
   - Incorporating a static retrospective EPSS snapshot inflates Test PR-AUC to **0.33153** (an **11.49× artificial performance inflation**), exposing a widespread methodological pitfall (EXP-B1).
   - Comparing linear additive scoring against a nonlinear interactive surface across 227,694 CVEs reveals severe queue head disruption, sharing only a **0.005 (0.5%) Top-100 Jaccard overlap** (EXP-C1).
4. **Potentially Distinctive Combination**:
   - The end-to-end integration of bit-for-bit reproducible Parquet data, strict temporal leakage auditing, closed-form nonlinear risk surface modeling, and local SHAP attributions in an open academic demonstration architecture.
5. **Unsupported Until Further Evidence**:
   - Claims that VTS reduces real-world enterprise remediation workload by 80–95% (unsupported; requires enterprise ticketing logs).
   - Claims that the nonlinear surface $S_{\text{nonlinear}}$ prevents more network compromises than commercial vulnerability management tools.
   - Claims that TreeExplainer SHAP attributions identify root-cause software bugs.
6. **Future Hypotheses**:
   - Hypothesizing that pre-trained cybersecurity transformers (SecureBERT) will lower CVSS pre-scoring MAE below 0.85 points.
   - Hypothesizing that attack path graph neural networks will capture multi-vulnerability lateral movement risk.

---

## 8. Research Question and Objective Audit

The project’s formal research claims are structured into testable scientific questions and artifact objectives:

- **Defensible Scientific RQs**:
  - *RQ1*: To what extent can tree-based gradient boosting predict continuous CVSS v3.1 Base Scores $[0.0, 10.0]$ at disclosure time compared to Ridge regression? *(Answered: XGBoost achieves 0.9750 MAE vs. Ridge 1.0954 MAE).*
  - *RQ2*: What precision and PR-AUC can be achieved for publication-time KEV forecasting under strict information boundaries? *(Answered: 0.02884 PR-AUC; 8.96x uplift vs. random).*
  - *RQ3*: How severely does access to a retrospective EPSS snapshot inflate historical evaluation? *(Answered: 11.49x PR-AUC inflation; Delta = +0.30269).*
  - *RQ4*: How do linear and nonlinear scoring surfaces diverge in top-tier queue overlap across controlled asset tiers? *(Answered: Top-100 Jaccard overlap is 0.005).*
- **Artifact & Engineering Objectives**:
  - *Objective 1*: Verify deterministic rebuild reproducibility and schema invariants across 366,547 canonical CVEs. *(Achieved: 0 differing rows; 15/15 invariant tests passed).*
  - *Objective 2*: Construct an auditable, role-governed web application demonstrating inference, scoring, explainability, and provenance. *(Achieved: 15 REST endpoints, full RBAC, 46 pytests passed).*

---

## 9. Evidence Gaps and Mitigation Strategy

To maintain academic credibility, the following empirical gaps are acknowledged along with their mitigation strategies:

1. **Resolution of the B2 0.3845 PR-AUC Discrepancy**:
   - *Gap*: `docs/final-repo-state.md:160` cited `PR-AUC = 0.3845`, whereas the serialized artifact `data/experiments/phase3/exp_b2/metrics.json` records `PR-AUC = 0.02884`.
   - *Resolution*: The value 0.3845 was an unverified draft entry that mislabeled the model as "Text + Meta + EPSS" and matched an example API response. It is formally retracted; **0.02884** is the sole authoritative verified result.
2. **Common Evaluation Subset**:
   - *Gap*: EXP-A1 evaluated on 81,604 test CVEs (CVEs with CVSS v3.1), while EXP-B2 evaluated on 91,242 test CVEs.
   - *Mitigation*: Generate the aligned subset matrix `consolidated_triage_evaluation.parquet` ($n = 81,604$) to enable joint metric tracking.
3. **Lack of Operational Enterprise Telemetry**:
   - *Gap*: No enterprise ticket histories or incident data.
   - *Mitigation*: Explicitly disclaim operational work reduction and restrict claims to static catalog precision/recall.
4. **CVSS Missingness (37.88%)**:
   - *Gap*: Older CVEs pre-dating CVSS v3.1 cannot be evaluated under EXP-A1.
   - *Mitigation*: Document that EXP-A1 specifically evaluates CVSS v3.1 applicability, which represents 62.12% of the canonical corpus.

---

## 10. Answers to Required Positioning Questions

### 1. What problem does VTS study?
VTS studies the problem of vulnerability prioritization and triage under realistic operational information availability, investigating whether disclosure-time NLP and non-linear risk surfaces can provide actionable decision support without look-ahead data leakage.

### 2. What does VTS actually contribute beyond an application implementation?
VTS contributes: (1) an empirical benchmark for disclosure-time CVSS v3.1 base score estimation (0.9750 MAE), (2) a strictly constrained publication-time KEV exploitation prediction model (0.02884 PR-AUC, 8.96× uplift over random), (3) a quantitative proof of the 11.49× performance inflation caused by retrospective EPSS snapshot leakage, and (4) an empirical demonstration that nonlinear multi-criteria surfaces eliminate the artificial priority ceilings inherent in linear additive scoring.

### 3. Which components are standard?
NVD CVE feeds, CVSS Base Scores, FIRST EPSS probabilities, CISA KEV listings, TF-IDF n-gram vectorization, XGBoost gradient boosting, Ridge/Logistic regression baselines, and TreeExplainer SHAP are all established, standard external components.

### 4. Which findings are empirically supported?
All numerical findings in `docs/research/PHASE_3_RESULTS.md` and `data/experiments/phase3/`: EXP-A1 MAE of 0.9750; EXP-B2 PR-AUC of 0.02884 and Precision@500 of 6.40%; EXP-B1 PR-AUC of 0.33153 (11.49× inflation); and EXP-C1 Top-100 Jaccard overlap of 0.005.

### 5. Which findings remain unproven?
Real-world enterprise breach reduction, operational remediation time savings, and software causal exploit mechanics remain completely unproven in this repository.

### 6. Is the strongest contribution algorithmic, methodological, evaluative, artifact-based, or a combination?
The strongest contribution is **evaluative and methodological**: exposing the severity of retrospective EPSS snapshot leakage and demonstrating the mathematical failure of linear additive scoring in queue tails, backed by a fully reproducible research artifact.

### 7. What evidence is needed to justify "improved prioritization"?
Justifying improved prioritization requires a longitudinal study in an active enterprise network comparing VTS against a CVSS baseline, measuring actual patch turnaround time, remediation labor hours, and confirmed penetration incidents.

### 8. How does VTS differ from the closest papers?
Unlike Agyei et al. (2026), VTS evaluates on 366,547 real CVEs rather than a simulated dataset, and replaces linear formulas with a nonlinear surface. Unlike FRAPE (2025), VTS enforces strict temporal splitting and isolates retrospective leakage.

### 9. What would a skeptical reviewer criticize?
A skeptical reviewer would criticize: (1) low absolute precision in publication-time KEV forecasting (6.40%), (2) evaluation on synthetic asset tiers rather than real CMDB inventories, (3) relying on a single frozen EPSS snapshot rather than longitudinal time series, and (4) the legacy documentation note mentioning 0.3845 PR-AUC.

### 10. Which claims should be removed from a paper unless new experiments are completed?
Remove any claim of "80–95% Work Reduction", any claim that SHAP proves exploit causality, any claim of production enterprise readiness, and any mention of 0.3845 PR-AUC as a confirmed result.

---

## 11. Recommended Final Research Positioning Statement

### Conservative One-Sentence Positioning (Authoritative & Defensible)
> *"The Vulnerability Prioritization & Triage System (VTS) is an academic research prototype providing an empirical benchmark for disclosure-time vulnerability severity estimation and publication-time exploitation prediction across 366,547 canonical CVEs, demonstrating that while pre-scoring achieves 0.9750 MAE and tree models provide an 8.96× precision uplift over random guessing, retrospective EPSS snapshots induce an 11.49× artificial performance inflation, and non-linear risk surfaces are required to prevent binary threat flags from creating artificial priority ceilings in triage queues."*

### Conditional Stronger Positioning (Pending Future Enterprise Evaluation)
> *"If validated against longitudinal enterprise asset inventories and operational ticketing telemetry, VTS’s non-linear multi-criteria prioritization architecture could potentially optimize remediation efficiency by dynamically routing critical infrastructure vulnerabilities ahead of lower-severity flaws lacking active threat weaponization."*

### Claims to Explicitly Avoid
- *"VTS solves vulnerability prioritization."*
- *"VTS achieves 0.3845 PR-AUC at publication time."*
- *"VTS reduces enterprise remediation workload by 80–95%."*
- *"SHAP identifies the software bug causing the vulnerability."*
- *"VTS is an enterprise-grade production security platform."*

---

## 12. References

1. **NIST**: Common Vulnerability Scoring System (CVSS) FAQs & Metrics. [https://nvd.nist.gov/vuln-metrics/cvss](https://nvd.nist.gov/vuln-metrics/cvss)
2. **FIRST**: Exploit Prediction Scoring System (EPSS) FAQ & Research. [https://www.first.org/epss/](https://www.first.org/epss/)
3. **CISA**: Known Exploited Vulnerabilities (KEV) Catalog. [https://www.cisa.gov/known-exploited-vulnerabilities-catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
4. **Lundberg, S. M., & Lee, S.-I.** (2017). A Unified Approach to Interpreting Model Predictions. *NeurIPS 2017*. [https://papers.nips.cc/paper/7062-a-unified-approach-to-interpreting-model-predictions](https://papers.nips.cc/paper/7062-a-unified-approach-to-interpreting-model-predictions)
5. **Chen, T., & Guestrin, C.** (2016). XGBoost: A Scalable Tree Boosting System. *ACM KDD 2016*. [https://doi.org/10.1145/2939672.2939785](https://doi.org/10.1145/2939672.2939785)
6. **Jiang, L., et al.** (2025). A Survey on Vulnerability Prioritization: Taxonomy, Metrics, and Research Challenges. *arXiv:2502.11070*. [https://arxiv.org/abs/2502.11070](https://arxiv.org/abs/2502.11070)
7. **Jacobs, J., et al.** (2021). Exploit Prediction Scoring System. *arXiv:1908.04856*. [https://arxiv.org/abs/1908.04856](https://arxiv.org/abs/1908.04856)
8. **Jacobs, J., et al.** (2023). Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights. *arXiv:2302.14172*. [https://arxiv.org/abs/2302.14172](https://arxiv.org/abs/2302.14172)
9. **Ravalico, D., et al.** (2025). Analysing the Temporal Dynamics of the Exploit Prediction Scoring Systems. *SSRN:5147459*. [https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459](https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459)
10. **Agyei, K. G., et al.** (2026). Explainable Risk-Based Vulnerability Prioritization in Hybrid Cloud. *WJARR*, 30(01), 2044–2052. [https://doi.org/10.30574/wjarr.2026.30.1.1006](https://doi.org/10.30574/wjarr.2026.30.1.1006)
11. **Bulut, M., et al.** (2022). Vulnerability Prioritization: An Offensive Security Approach. *arXiv:2206.11182*. [https://arxiv.org/abs/2206.11182](https://arxiv.org/abs/2206.11182)
12. **Balsam, A., et al.** (2025). Automatic CVSS-Based Vulnerability Prioritization and Response with Context Information and Machine Learning. *Applied Sciences*, 15(16), 8787. [https://doi.org/10.3390/app15168787](https://doi.org/10.3390/app15168787)
13. **Parla, V.** (2024). Efficacy of EPSS in High Severity CVEs found in KEV. *arXiv:2411.02618*. [https://arxiv.org/abs/2411.02618](https://arxiv.org/abs/2411.02618)
14. **Mell, P., & Spring, J.** (2025). Likely Exploited Vulnerabilities, A Proposed Metric for Vulnerability Exploitation Probability. *NIST SP*. [https://www.nist.gov/publications/likely-exploited-vulnerabilities-proposed-metric-vulnerability-exploitation-probability](https://www.nist.gov/publications/likely-exploited-vulnerabilities-proposed-metric-vulnerability-exploitation-probability)

---

## 13. Concluding Audit Checklists

- **Source-Quality Audit**: All standards (NIST, FIRST, CISA) cite official specification URLs; peer-reviewed papers include active DOIs or arXiv identifiers.
- **VTS Evidence Audit**: Every empirical metric is reconciled against serialized artifacts in `data/experiments/phase3/`.
- **Unsupported-Claim Register**: The legacy PR-AUC of 0.3845, enterprise work reduction claims, and causal explainability interpretations have been formally audited and eliminated from defensible claims.
- **Recommended Research Position**: Ground all academic defenses in the empirical findings of EXP-A1 (0.9750 MAE), EXP-B2 (0.02884 PR-AUC, 8.96× uplift), EXP-B1 (11.49× leakage inflation), and EXP-C1 (0.005 Top-100 Jaccard overlap).
