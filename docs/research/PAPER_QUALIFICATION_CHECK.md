# Final Pre-Paper Verification & Qualification Check: VTS

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Document Status**: Authoritative Pre-Submission Paper Qualification Check  
**Target Submission**: IEEE-Style Academic Research Paper  
**Audit Date**: October 2, 2026  
**Auditor Reference**: `docs/research/EVIDENCE_AUDIT.md`  

---

## Executive Qualification Summary

This qualification audit evaluates three critical methodological questions for the Vulnerability Prioritization & Triage System (VTS) to ensure technical defensibility, prevent reviewer rejection, and ensure zero ungrounded claims appear in the research paper:

1. **Feature Availability**: The repository **does not** contain timestamped change logs proving that natural language descriptions, CWE weakness identifiers, or CPE platform configurations existed in their current form at initial CVE publication ($t_0$). The paper must describe the split as an empirical **temporal partition of post-analysis NVD snapshot records**, not a strictly prospective, real-time disclosure evaluation.
2. **EXP-C1 Consistency**: The reported nonlinear ranking containing only 3 KEV entries in its top 100 is confirmed to be mathematically reproducible, but it is caused by a **severe mathematical saturation defect**: for any vulnerability with CVSS = 10.0, the complement $(1 - x_1)$ equals zero, completely eliminating both the KEV multiplier and EPSS probability. All 731 CVEs with CVSS 10.0 tie at the maximum score, and the top 100 selection is an arbitrary artifact of database row order. **EXP-C1 must be excluded from the paper's primary claims and treated solely as an exploratory cautionary analysis.**
3. **Leakage Conclusion**: The 11.49× PR-AUC inflation (0.02884 $\rightarrow$ 0.33153) between EXP-B2 and EXP-B1 is an internally verified, controlled ablation demonstrating the extreme sensitivity of vulnerability classifiers to retrospective static threat snapshots. However, this finding **must not be generalized to discredit third-party research papers** without external replication.

---

## 1. Feature Availability Audit (EXP-A1 & EXP-B2)

### 1.1 Relevant Repository Files
- Ingestion modules: [`src/ingestion/nvd.py`](../../src/ingestion/nvd.py), [`src/ingestion/cpe.py`](../../src/ingestion/cpe.py)
- Pipeline builder: [`scripts/build_processed_data.py`](../../scripts/build_processed_data.py)
- Experiment scripts: [`scripts/experiments/run_exp_a1.py`](../../scripts/experiments/run_exp_a1.py), [`scripts/experiments/run_exp_b2.py`](../../scripts/experiments/run_exp_b2.py)
- Processed datasets: `data/processed/vulnerabilities.parquet`, `data/processed/cve_cwe.parquet`, `data/processed/cve_cpe.parquet`

### 1.2 Verified Facts
1. **Single Snapshot Provenance**: The raw NVD data consists of 25 yearly feed files (`nvdcve-2.0-2002.json.gz` to `...-2026.json.gz`) captured in a single snapshot on **July 26, 2026**.
2. **Available Timestamps**: The ingestion script (`src/ingestion/nvd.py:77-84`) extracts only two temporal attributes per vulnerability: `published` (initial disclosure date string) and `lastModified` (most recent record update timestamp).
3. **Absence of Change-Log Auditing**: The repository does not ingest the NVD CVE History API endpoint (`/cvehistory/2.0`) and contains no git commit history from NVD mirrors. There are no sub-record timestamps recording when:
   - English descriptions (`description_en`) were written, revised, or expanded.
   - Specific CWE identifiers (`cve_cwe.parquet`) were assigned by NVD analysts or CNAs.
   - CPE configuration applicability trees (`cve_cpe.parquet`) were structured.
4. **NVD Operational Reality**: In operational cybersecurity practice, initial CVE disclosures often contain preliminary descriptions, lack CWE classifications (`NVD-CWE-noinfo` or empty), and omit CPE platform trees until human analysts at NIST complete triage—a process often taking days to months.
5. **Transductive Preprocessing / Global Fitting**: In both `scripts/experiments/run_exp_a1.py:62` and `scripts/experiments/run_exp_b2.py:72`:
   ```python
   tfidf = TfidfVectorizer(max_features=500, stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
   desc_text = df["description_en"].fillna("")
   X_text = tfidf.fit_transform(desc_text)
   ```
   `TfidfVectorizer.fit_transform` is called over the **entire corpus** across all years (2002–2026) prior to splitting into train (2002–2022), validation (2023–2024), and test (2025–2026). Similarly, the top-20 semantic CWE list is determined globally over all records (`cwe[cwe["is_semantic_cwe"]]["cwe_id"].value_counts().head(20)`). This constitutes corpus-wide vocabulary and IDF weighting.

### 1.3 Unresolved Points
- It is impossible to determine from this repository what percentage of test CVE descriptions (2025–2026) were available verbatim on day zero versus enriched retroactively.
- It is impossible to determine whether the CPE trees for 2025–2026 CVEs were populated at initial publication or added after vendor patch releases.

### 1.4 Exact Safe Wording for the Paper

> **Methodology Section — Temporal Partitioning & Information Availability:**  
> *"To evaluate predictive generalization over time, we employ a strict temporal train/validation/test partition based on the official CVE publication year: training on records published between 2002 and 2022 ($n = 203,652$), tuning on 2023–2024 ($n = 71,653$), and testing on 2025–2026 ($n = 91,242$). We intentionally exclude post-publication dynamic telemetry (e.g., EPSS scores, exploit catalog inclusion dates, and CVSS vector components) from the publication-time models.*  
>  
> *However, we explicitly qualify that feature extraction operates on the NVD API 2.0 archive frozen as of July 26, 2026. Because NVD feed snapshots reflect cumulative analyst enrichment rather than immutable disclosure-day audit logs, text descriptions, CWE assignments, and CPE applicability configurations represent their post-analysis state rather than point-in-time disclosure telemetry. Our evaluation therefore benchmarks performance on temporally held-out vulnerability records under post-analysis metadata, rather than an operational, zero-hour prospective feed."*

---

## 2. EXP-C1 Consistency & Mathematical Defect Audit

### 2.1 Relevant Repository Files
- Simulation script: [`scripts/experiments/run_exp_c1.py`](../../scripts/experiments/run_exp_c1.py)
- Serialized metrics: `data/experiments/phase3/exp_c1/metrics.json`
- Serialized ranking table: `data/experiments/phase3/exp_c1/simulation_rankings.parquet`

### 2.2 Verified Facts & Metric Recomputations
1. **Evaluated Population**: Exactly 227,694 intersected CVEs possessing complete CVSS v3.1, EPSS snapshot, and KEV catalog annotations. Of these, exactly **1,643 CVEs are KEV positive** ($0.7216\%$).
2. **Formulations Tested**:
   - Linear Baseline ($S_{\text{linear}}$):
     $$S_{\text{linear}} = 0.25 \cdot x_1 + 0.25 \cdot x_2 + 0.25 \cdot x_3 + 0.25 \cdot x_4$$
     where $x_1 = \text{CVSS}/10$, $x_2 = \text{EPSS}$, $x_3 = \mathbb{I}_{\text{KEV}} \in \{0, 1\}$, and $x_4 \in \{0.25, 0.50, 0.75, 1.00\}$.
   - Nonlinear Interaction Surface ($S_{\text{nonlinear}}$):
     $$S_{\text{nonlinear}} = x_4 \cdot \left[ 1 - (1 - x_1)^{1 + 1.0 \cdot x_3} \cdot (1 - x_2)^{1 + 1.5 \cdot x_3} \right]$$
3. **Queue Sorting & Overlap Recomputations**:
   - `s_lin` and `s_nonlin` sorted in descending order (`np.argsort(-s)`):
     - **Top-100 KEV Count**: Linear = **100**, Nonlinear = **3** ($\Delta = -97$).
     - **Top-1000 KEV Count**: Linear = **1,000**, Nonlinear = **315** ($\Delta = -685$).
     - **Top-100 Jaccard Overlap**: $0.005025$ (**0.5%**).
     - **Top-1000 Jaccard Overlap**: $0.1820$ (**18.2%**).
     - **Global Spearman $\rho$**: $0.9962$; **Kendall $\tau$**: $0.9356$.
4. **Parquet Export Key Collision**: In `run_exp_c1.py:100`, `tier_name.split()[0].lower()` evaluates to `'tier'` for every tier. Consequently, `simulation_rankings.parquet` overwrote columns on each loop iteration and only saved Tier 4 scores ($x_4 = 1.00$).

### 2.3 Mathematical Explanation of the "3 KEV in Top 100" Paradox

Reviewers will immediately question why the nonlinear formula—which mathematically scales up the exponents when $x_3 = 1$, ostensibly increasing risk—yields only 3 KEV items in its top 100, while the linear baseline yields 100.

Independent mathematical audit reveals this is caused by a **critical saturation defect** in the complement-product formulation:

1. **Boundary Value Collapse**:
   Consider any vulnerability with a maximum CVSS score ($\text{CVSS} = 10.0 \implies x_1 = 1.0$):
   $$\text{sev\_factor} = (1 - x_1)^{1 + \alpha x_3} = (1 - 1.0)^{1 + 1.0 \cdot x_3} = 0.0^{1 + x_3} = 0.0$$
   Because $\text{sev\_factor} = 0.0$, the product $\text{sev\_factor} \cdot \text{threat\_factor}$ collapses to $0.0$, regardless of $x_2$ (EPSS) or $x_3$ (KEV):
   $$S_{\text{nonlinear}} = x_4 \cdot [1 - 0.0] = x_4 \cdot 1.0 = x_4$$
2. **Total Parameter Erasure**:
   When $\text{CVSS} = 10.0$, **both EPSS and KEV are completely erased from the formula**. The vulnerability saturates to the absolute maximum score ($x_4 = 0.25$ in Tier 1; $1.00$ in Tier 4) whether it is actively exploited or not, and whether EPSS is $0.0001$ or $0.9999$.
3. **Prevalence of CVSS 10.0 in the Dataset**:
   In the 227,694 intersected CVE dataset:
   - Exactly **731 CVEs have $\text{CVSS} = 10.0$**.
   - Among these 731 CVEs, **only 46 are in CISA KEV (6.30%)**, while **685 are NOT in KEV (93.70%)**.
   - **All 731 CVEs tie at the exact identical score** of $S_{\text{nonlinear}} = x_4$.
4. **Arbitrary Tie-Breaking Artifact**:
   When `np.argsort(-s_nonlin)[:100]` selects the top 100 items from 731 tied candidates, NumPy's introsort/introselect algorithm breaks ties according to the underlying row order in memory (inherited from DuckDB/Pandas table ordering).
   - In that arbitrary slice of 100 tied items, **only 3 happen to have $x_3 = 1$**.
   - In fact, **all 100 items in the nonlinear top-100 queue have the identical score ($0.250000$)**; 43 of the 46 known exploited CVSS 10.0 vulnerabilities are arbitrarily excluded simply because of database row positioning!
5. **Contrast with Linear Baseline**:
   In $S_{\text{linear}}$, KEV contributes an additive $+0.25$, while continuous EPSS ($0.25 \cdot x_2$) provides fine-grained, non-tied differentiation:
   $$\text{CVSS 10.0 + KEV 1 + EPSS 0.99999} \implies S_{\text{linear}} = 0.812497$$
   $$\text{CVSS 10.0 + KEV 0 + EPSS 0.01000} \implies S_{\text{linear}} = 0.565000$$
   Because of continuous EPSS differentiation, $S_{\text{linear}}$ has zero ties at the queue head. The top 100 items are uniquely and genuinely the highest-severity, actively exploited CVEs.

### 2.4 Unresolved Points
- The nonlinear interaction formula $S_{\text{nonlinear}}$ possesses an unintended mathematical singularity: it cannot differentiate between exploited and non-exploited vulnerabilities at the CVSS ceiling.
- The 0.005 Jaccard overlap does **not** reflect intelligent prioritization; it reflects that Mode 2's top 100 queue is an arbitrary subset of 731 tied items dominated by non-exploited CVEs.
- This limitation cannot be repaired without retraining models or modifying formulas, which is prohibited under the dataset/code freeze.

### 2.5 Recommendation & Exact Safe Wording for the Paper

> **Paper Action: Exclude EXP-C1 from primary claims.**  
> EXP-C1 must not be presented as a successful prioritization system or recommended triage policy. It should only be discussed in a Discussion/Limitations subsection as an exploratory finding regarding the dangers of multiplicative complement formulas.
>  
> **Safe Wording for Discussion / Exploratory Section:**  
> *"In exploratory simulation EXP-C1, we evaluated a nonlinear interactive surface ($S_{\text{nonlinear}}$) designed to couple severity, threat, and asset criticality. While the surface maintained strong global rank correlation with a linear additive baseline ($\rho = 0.9962$), analysis revealed an extreme queue head divergence (Top-100 Jaccard overlap of 0.005), with only 3 KEV items captured in the nonlinear top-100 versus 100 in the linear queue.*  
>  
> *Detailed inspection revealed that this divergence is driven by a mathematical saturation property: in complement-product formulations, when normalized CVSS reaches 1.0 (present in 731 dataset CVEs), the complement term $(1 - x_1)$ vanishes, collapsing the risk score to its ceiling ($x_4$) regardless of KEV status or EPSS probability. Consequently, ranking among these 731 tied maximum-severity items becomes arbitrary with respect to active threat signals. This highlights an important mathematical caution for vulnerability scoring designers: multiplicative complement formulations must incorporate continuity bounds to prevent ceiling saturation from masking active exploitation telemetry."*

---

## 3. Retrospective Leakage Conclusion Audit (EXP-B1 vs. EXP-B2)

### 3.1 Relevant Repository Files
- Prospective model: [`scripts/experiments/run_exp_b2.py`](../../scripts/experiments/run_exp_b2.py), `data/experiments/phase3/exp_b2/metrics.json`
- Retrospective model: [`scripts/experiments/run_exp_b1.py`](../../scripts/experiments/run_exp_b1.py), `data/experiments/phase3/exp_b1/metrics.json`
- Test predictions: `data/experiments/phase3/exp_b2/test_predictions.parquet`, `data/experiments/phase3/exp_b1/test_predictions.parquet`

### 3.2 Verified Facts
1. **Strict Internal Control**: EXP-B1 and EXP-B2 were executed on the identical prospective test partition:
   - 91,242 test CVEs (disclosed in 2025–2026).
   - Exactly 294 KEV positive labels ($0.3222\%$ base rate).
   - Identical XGBoost hyperparameter search space (`max_depth=4, n_estimators=100, learning_rate=0.1, scale_pos_weight=20`).
   - Identical 531 publication-time baseline features.
2. **The Leaked Variable**: EXP-B1 adds exactly two features: `epss` and `epss_percentile` drawn from the static snapshot of `2026-07-16` (EPSS model `v2026.06.15`).
3. **The Empirical Delta**:
   - **EXP-B2 (Prospective, No EPSS)**: Test PR-AUC = **0.02884** (`average_precision_score`), ROC-AUC = 0.81324, Precision@500 = **0.0640** (32/500 hits), Recall@500 = **0.1088** (32/294).
   - **EXP-B1 (Retrospective Static EPSS)**: Test PR-AUC = **0.33153** (`average_precision_score`), ROC-AUC = 0.98420, Precision@500 = **0.2520** (126/500 hits), Recall@500 = **0.4286** (126/294).
   - **Absolute Delta**: $\Delta \text{PR-AUC} = +0.30269$ (**11.49× inflation**; $+1,049\%$).
   - **Precision@500 Delta**: $+0.1880$ (**3.94× inflation**; 32 hits $\rightarrow$ 126 hits).

### 3.3 Boundary Between Internal Findings and External Literature
- **What VTS Proves**: When an identical model evaluating 2025–2026 vulnerabilities is given access to a mid-2026 EPSS snapshot, its measured precision-recall performance inflates by over an order of magnitude because the EPSS snapshot incorporates threat telemetry observed after vulnerability disclosure.
- **What VTS Does NOT Prove**: VTS did not replicate the exact data pipelines, daily prospective EPSS API logs, or specialized feature sets of external literature (e.g., Jacobs et al., 2021; Bullough et al., 2023; Agyei et al., 2026). We cannot prove that published PR-AUC scores in other papers are solely artifacts of leakage without auditing their specific training code and temporal alignment.

### 3.4 Exact Safe Wording for the Paper

> **Results & Discussion — Retrospective Snapshot Leakage:**  
> *"To quantify the impact of temporal look-ahead leakage in vulnerability prioritization research, we conducted a controlled ablation comparing our prospective publication-time classifier (EXP-B2) against an otherwise identical model granted access to a static post-hoc EPSS snapshot (EXP-B1, using scores from July 16, 2026). On the identical held-out test partition of 91,242 vulnerabilities (2025–2026 disclosures; 294 KEV positives), the prospective model achieved a PR-AUC of 0.02884 and Precision@500 of 0.0640 (32 true positives).*  
>  
> *When the static retrospective EPSS score and percentile were introduced, the measured Test PR-AUC surged to 0.33153 (an 11.49-fold increase; $\Delta = +0.30269$), and Precision@500 rose to 0.2520 (126 true positives). This controlled comparison demonstrates the acute sensitivity of tree-based exploit predictors to future threat intelligence: because modern EPSS snapshots reflect honeypot detections and exploitation activity observed well after disclosure, incorporating static snapshots into retrospective evaluations introduces substantial look-ahead leakage. We caution that machine learning models evaluated on historical CVEs must utilize time-indexed historical EPSS feeds aligned with each CVE's disclosure timestamp to avoid severe artificial inflation of operational predictive capability."*

---

## 4. Final Recommendations: Central Paper Claims vs. Exploratory Results

Based on the evidence audit, the paper must be structured with clear demarcation between defensible core contributions and exploratory analyses:

| Finding / Topic | Classification | Primary Evidence Artifact | Justification & Submission Guidance |
|---|---|---|---|
| **EXP-A1: Pre-Scoring CVSS v3.1 Regression** | **CENTRAL CLAIM** | `data/experiments/phase3/exp_a1/` | **MAE = 0.9750** CVSS points on 81,604 test CVEs (-10.99% error reduction over Ridge). Rock-solid, fully recomputed, methodologically defensible. |
| **EXP-B2: Publication-Time Exploitation Benchmark** | **CENTRAL CLAIM** | `data/experiments/phase3/exp_b2/` | **PR-AUC = 0.02884** (8.96× over random base rate 0.00322; P@500 = 6.40%, R@500 = 10.88%). Honest, realistic benchmark under extreme class imbalance (0.32% base rate). |
| **EXP-B1 vs. EXP-B2 Leakage Ablation** | **CENTRAL CLAIM** | `data/experiments/phase3/exp_b1/` & `exp_b2/` | **+0.3027 $\Delta$PR-AUC (11.49× inflation)**. Powerful methodological cautionary contribution for the security ML community regarding static EPSS snapshots. |
| **Dataset Invariant Architecture** | **CENTRAL CLAIM** | `tests/test_etl_invariants.py`, `docs/research/DATA_MANIFEST.md` | 366,547 canonical CVE Parquet lake, 15 invariant checks, 100% deterministic ETL reproducibility across independent rebuilds. |
| **EXP-C1: Multi-Criteria Prioritization Simulation** | **EXPLORATORY ONLY** | `data/experiments/phase3/exp_c1/` | **Do NOT present as an operational prioritization breakthrough.** Present as an exploratory study of interaction surfaces and saturation phenomena (explaining the CVSS 10.0 saturation defect). |
| **Post-Hoc SHAP TreeExplainer Attributions** | **EXPLORATORY / QUALIFIED** | `data/experiments/phase3/shap/` | Present as statistical ensemble feature attributions (identifying unauthenticated access and CWE-22), explicitly disclaiming causal exploit mechanics. |
| **Enterprise Workload Reduction (80–95%)** | **EXCLUDE ENTIRELY** | External Literature | No enterprise ticketing, patching, or telemetry logs exist in this repository. Cite only as related work motivation. |
| **Breach / Attack Prevention Claims** | **EXCLUDE ENTIRELY** | None | System is a decision-support prototype, not an active network mitigation or endpoint detection engine. |
| **PR-AUC = 0.3845** | **EXCLUDE ENTIRELY** | `docs/API.md:146` | Formally discredited as an illustrative API response typo. Serialized truth is 0.02884. |

---

## 5. Artifact Verification Matrix

```
+---------------------------------------------------------------------------------------------------------+
|                                    PRE-PAPER QUALIFICATION AUDIT MATRIX                                 |
+-----------------------------+------------------------------------+------------------+-------------------+
| Investigation Item          | Verified Empirical Fact            | Status           | Submission Action |
+-----------------------------+------------------------------------+------------------+-------------------+
| 1. Text/CWE/CPE Availability| No historical change logs in NVD   | Methodological   | Qualify temporal  |
|    at Disclosure ($t_0$)    | snapshot; global TF-IDF fitting    | Constraint       | split; no "zero-  |
|                             | across split boundaries            |                  | hour prospective" |
+-----------------------------+------------------------------------+------------------+-------------------+
| 2. EXP-C1 Queue Composition | Formula collapses to $x_4$ when    | Mathematical     | Exclude from main |
|    (3 KEV in Top 100)       | CVSS = 10.0; 731 CVEs tied;        | Saturation       | claims; retain as |
|                             | row-order tie-breaking artifact    | Defect           | exploratory study |
+-----------------------------+------------------------------------+------------------+-------------------+
| 3. Retrospective Leakage    | +0.30269 $\Delta$PR-AUC (11.49x)   | Defensible       | Report internal   |
|    (B1 vs. B2 Delta)        | verified in controlled ablation;   | Core Result      | ablation; avoid   |
|                             | external papers not audited        |                  | generalizing      |
+-----------------------------+------------------------------------+------------------+-------------------+
```
