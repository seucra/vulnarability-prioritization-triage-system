Yes. I did the external-search pass. Treat this as the **raw research corpus I found**, not the final literature review.

## 1. Most important: vulnerability-prioritization literature

### A. Survey — probably the single most useful starting point

**Jiang et al. (2025), “A Survey on Vulnerability Prioritization: Taxonomy, Metrics, and Research Challenges”**

* Reviews **82 studies**.
* Covers severity, exploitability, contextual/environmental factors, predictive metrics, and aggregation methods.
* Explicitly discusses dynamic/context-aware prioritization, ML explainability, validation approaches, and research gaps.
* It is particularly valuable because it gives us a map of the field rather than one competing method.

[ResearchGate — full paper](https://www.researchgate.net/publication/389091516_A_Survey_on_Vulnerability_Prioritization_Taxonomy_Metrics_and_Research_Challenges?utm_source=chatgpt.com)
[arXiv — paper](https://arxiv.org/abs/2502.11070?utm_source=chatgpt.com)
[DBLP — metadata](https://dblp.org/rec/journals/corr/abs-2502-11070.html?utm_source=chatgpt.com)

The survey itself says it screened 353 unique papers after database merging and ultimately reviewed 82 studies. ([ResearchGate][1])

---

### B. Offensive-security prioritization

**Bulut et al. (2022), “Vulnerability Prioritization: An Offensive Security Approach”**

Uses penetration-testing/offensive-security reasoning to prioritize vulnerabilities and investigates ML automation.

[Paper — arXiv](https://arxiv.org/abs/2206.11182?utm_source=chatgpt.com)

This is useful as a **competing prioritization philosophy** rather than something directly equivalent to your system. ([arXiv][2])

---

### C. FRAPE

**“FRAPE: A Framework for Risk Assessment, Prioritization and Explainability of vulnerabilities in cybersecurity” (2025)**

This one is particularly relevant because it combines:

* risk assessment
* vulnerability prioritization
* supervised ML
* active learning
* explainability

[ScienceDirect paper](https://www.sciencedirect.com/science/article/pii/S2214212625000092?utm_source=chatgpt.com)

It is a very useful comparison point for your **ML + prioritization + SHAP** combination. ([ScienceDirect][3])

---

### D. Automatic CVSS + context + ML

**Balsam et al. (2025), “Automatic CVSS-Based Vulnerability Prioritization and Response with Context Information and Machine Learning”**

Applied Sciences, 15(16), 8787.

DOI: `10.3390/app15168787`

[Paper](https://www.mdpi.com/2076-3417/15/16/8787?utm_source=chatgpt.com)

This is another important neighboring work because it combines **CVSS, contextual information and ML**. ([MDPI][4])

---

### E. VulRG

**Jiang et al. (2025), “VulRG: Multi-Level Explainable Vulnerability Patch Ranking for Complex Systems Using Graphs”**

Uses:

* asset criticality
* dependency graphs
* communication graphs
* attack paths
* vulnerability ranking
* explainability

[arXiv paper](https://arxiv.org/abs/2502.11143?utm_source=chatgpt.com)

This is especially relevant to your **future scope**, because graph/attack-path/context modelling is considerably beyond your current controlled asset-tier model. ([arXiv][5])

---

## 2. CVSS / severity-vs-risk material

### Official NVD

NIST explicitly states that **CVSS is a qualitative severity measure and is not itself a measure of risk**. It describes CVSS v2/v3.x/v4 and Base/Temporal/Environmental concepts. ([NVD][6])

[NVD — CVSS metrics](https://nvd.nist.gov/vuln-metrics/cvss?utm_source=chatgpt.com)

### FIRST CVSS specification

[FIRST — CVSS v3.0 specification](https://www.first.org/cvss/v3.0/specification-document?utm_source=chatgpt.com)

Useful because the distinction between **severity and prioritization** should ultimately be grounded in FIRST's own specification rather than secondary blogs. ([FIRST][7])

### CVSS limitations literature

**Albab (2025), “Severity vs Risk: The limitations of CVSS”**

A systematic literature review specifically examining CVSS limitations and alternative vulnerability-prioritization approaches.

[University of Twente thesis/paper](https://essay.utwente.nl/essays/106247?utm_source=chatgpt.com) ([UT Theses][8])

---

## 3. EPSS — foundational literature

### Original EPSS

**Jacobs, Romanosky, Edwards, Roytman & Adjerid (2021), “Exploit Prediction Scoring System”**

The foundational EPSS paper.

[arXiv paper](https://arxiv.org/abs/1908.04856?utm_source=chatgpt.com)

The original work frames EPSS as a data-driven estimate of exploitation probability rather than merely a severity score. ([arXiv][9])

---

### EPSS evolution / v3

**Jacobs et al. (2023), “Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights”**

This describes the development of EPSS v3 and the design decisions behind it.

[arXiv paper](https://arxiv.org/abs/2302.14172?utm_source=chatgpt.com)

The paper reports an **82% performance improvement over previous models** in distinguishing exploited vulnerabilities. ([arXiv][10])

FIRST's research page also lists this as the major EPSS v3 paper. ([FIRST][11])

---

### EPSS official research collection

[FIRST EPSS research page](https://www.first.org/epss/research.html?utm_source=chatgpt.com)

This is extremely useful because it already links the foundational EPSS papers and independent evaluations. ([FIRST][11])

---

### EPSS current methodology/data

[FIRST EPSS](https://www.first.org/epss/?utm_source=chatgpt.com)

FIRST currently describes EPSS as a daily ML-based probability of exploitation within the next 30 days. ([FIRST][12])

Historical EPSS data:

[Official historical EPSS repository](https://github.com/empiricalsec/epss_scores?utm_source=chatgpt.com)

Important for your project: historical EPSS has explicit model-version transition dates, including v2, v3 and v4. ([GitHub][13])

---

## 4. EPSS criticism / independent evaluation

### Temporal dynamics of EPSS

**Ravalico, Farina, Trevisan & Bartoli (2025), “Analysing the Temporal Dynamics of the Exploit Prediction Scoring Systems”**

This is **very relevant** to your temporal methodology.

They track >45,000 vulnerabilities and examine how EPSS changes after disclosure. They report that EPSS scores can require weeks to reach critical values and fluctuate over time. ([SSRN][14])

[Paper / SSRN PDF](https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459&mirid=1&utm_source=chatgpt.com)

---

### EPSS on high-severity KEVs

**Parla (2024), “Efficacy of EPSS in High Severity CVEs found in KEV”**

[arXiv paper](https://arxiv.org/abs/2411.02618?utm_source=chatgpt.com)

Specifically examines EPSS history for vulnerabilities subsequently appearing in CISA KEV. ([arXiv][15])

---

### EPSS / IoT limitations

**“Bits and Pieces: Piecing Together Factors of IoT Vulnerability Exploitation”**

ACM AsiaCCS.

Interesting because it finds cases where EPSS performs poorly on IoT vulnerabilities and investigates additional signals such as underground/community sources. ([DOI][16])

[ACM paper](https://doi.org/10.1145/3708821.3733875?utm_source=chatgpt.com)

---

### NIST alternative metric

**Mell & Spring (2025), “Likely Exploited Vulnerabilities, A Proposed Metric for Vulnerability Exploitation Probability”**

This is worth keeping.

NIST explicitly discusses limitations of EPSS and KEV and proposes **LEV — Likely Exploited Vulnerabilities** as another exploitation-probability metric. ([NIST][17])

[NIST publication](https://www.nist.gov/publications/likely-exploited-vulnerabilities-proposed-metric-vulnerability-exploitation-probability?utm_source=chatgpt.com)

---

## 5. KEV / exploitation ground truth

### Official CISA KEV

CISA describes KEV as a living catalog of vulnerabilities with evidence of active exploitation. ([GovDelivery][18])

[CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog?utm_source=chatgpt.com)

This is the primary source for your B2 target definition.

---

### Important conceptual limitation

The recent 2026 literature explicitly describes the complementary roles:

* CVSS → severity
* EPSS → predicted exploitation likelihood
* KEV → confirmed exploitation

and notes that KEV is retrospective and therefore cannot serve as a publication-time predictive feature. ([DOI][19])

That's directly relevant to the reasoning behind your **B2 feature boundary**.

---

## 6. Machine-learning exploitation prediction

### Expected Exploitability

**Suciu et al. (USENIX Security 2022), “Expected Exploitability: Predicting the Development of Functional Vulnerability Exploits”**

[USENIX paper](https://www.usenix.org/system/files/sec22summer_suciu.pdf?utm_source=chatgpt.com)

Important distinction:

Their target is **development of functional exploits**, not necessarily exploitation in the wild. The authors explicitly distinguish their task from predicting real-world exploitation. ([USENIX][20])

This is useful for positioning B2 against related prediction tasks.

---

### 2026 integrated risk/exploit prediction

**“Integrated risk scoring and exploit prediction for cyber-physical power system vulnerabilities”**

[Springer paper](https://doi.org/10.1186/s42162-026-00640-x?utm_source=chatgpt.com)

Combines CVSS, EPSS, KEV and contextual/sector-specific information. ([DOI][21])

---

## 7. Newer vulnerability-prioritization work

### Vulnerability Management Chaining

**“Vulnerability Management Chaining: An Integrated Framework for Efficient Cybersecurity Risk Prioritization” (2026)**

DOI:

`10.1109/ACCESS.2026.3665768`

[Paper](https://doi.org/10.1109/ACCESS.2026.3665768?utm_source=chatgpt.com)

Combines:

* KEV
* EPSS
* CVSS
* decision-tree prioritization

It is directly adjacent to your project and therefore **must be considered during eventual novelty analysis**. ([DOI][19])

---

### Decision-oriented vulnerability prioritization

**“Decision-oriented vulnerability prioritization via context-aware probabilistic risk estimation”**

Computers & Security, 2026.

[ScienceDirect paper](https://www.sciencedirect.com/science/article/pii/S0167404826002385?utm_source=chatgpt.com)

Combines exploitation probability with:

* asset criticality
* internet exposure
* exploit availability
* business impact
* constrained Top-K remediation

Again, highly relevant to your **C1/future scope territory**. ([ScienceDirect][22])

---

### KRI framework

**“Bridging the Gap Between Security Metrics and Key Risk Indicators: An Empirical Framework for Vulnerability Prioritization” (2026)**

[arXiv paper](https://arxiv.org/abs/2603.12450?utm_source=chatgpt.com)

Interesting because it explicitly compares CVSS, EPSS and a context/impact-oriented KRI. ([arXiv][23])

---

## 8. Explainability / SHAP

### Original SHAP paper

**Lundberg & Lee (2017), “A Unified Approach to Interpreting Model Predictions”**

[arXiv paper](https://arxiv.org/abs/1705.07874?utm_source=chatgpt.com)

[NeurIPS paper](https://proceedings.neurips.cc/paper/7062-a-unified-approach-tointerpreting-model-predictions.pdf?utm_source=chatgpt.com)

This is the foundational reference for your SHAP layer. It defines additive feature attribution and the SHAP framework. ([arXiv][24])

---

## 9. XGBoost

### Original XGBoost paper

**Chen & Guestrin (2016), “XGBoost: A Scalable Tree Boosting System”**

[arXiv paper](https://arxiv.org/abs/1603.02754?utm_source=chatgpt.com)

[KDD paper PDF](https://arxiv.org/pdf/1603.02754?utm_source=chatgpt.com)

This is the foundational citation for the model family used in A1/B2. ([arXiv][25])

---

## 10. Official data standards

### NVD

[NIST NVD](https://www.nist.gov/itl/nvd?utm_source=chatgpt.com)

Interesting current development: NIST changed its enrichment priorities in April 2026 to prioritize KEV entries, federal-government software, and critical software. ([NIST][26])

### MITRE CWE

[MITRE CWE](https://cwe.mitre.org/?utm_source=chatgpt.com)

### MITRE CVE

[MITRE CVE Program](https://www.cve.org/?utm_source=chatgpt.com)

### CPE

[NIST CPE](https://nvd.nist.gov/products/cpe?utm_source=chatgpt.com)

---

# The particularly important papers for *your* project

If I reduce everything above to the papers I'd definitely put into the raw corpus:

| Priority | Source                                 | Why                                                |
| -------- | -------------------------------------- | -------------------------------------------------- |
| **1**    | Jiang et al. 2025 survey               | Maps the entire vulnerability-prioritization field |
| **2**    | Jacobs et al. 2021 EPSS                | EPSS foundation                                    |
| **3**    | Jacobs et al. 2023 EPSS v3             | Modern EPSS methodology                            |
| **4**    | Ravalico et al. 2025                   | EPSS temporal dynamics                             |
| **5**    | Suciu et al. 2022                      | Alternative exploit-prediction problem             |
| **6**    | FRAPE 2025                             | ML + prioritization + explainability               |
| **7**    | Balsam et al. 2025                     | CVSS + context + ML                                |
| **8**    | VulRG 2025                             | Context/asset/dependency/graph prioritization      |
| **9**    | Mell & Spring 2025                     | EPSS/KEV limitations + LEV                         |
| **10**   | Vulnerability Management Chaining 2026 | Direct modern competitor                           |
| **11**   | Decision-oriented prioritization 2026  | Direct context-aware competitor                    |
| **12**   | KRI 2026                               | Modern empirical risk/prioritization comparison    |
| **13**   | Bulut et al. 2022                      | Alternative prioritization philosophy              |
| **14**   | Parla 2024                             | EPSS vs later KEV exploitation                     |
| **15**   | Jiang et al. 2025 VulRG                | Explainable/contextual ranking                     |
| **16**   | Lundberg & Lee 2017                    | SHAP foundation                                    |
| **17**   | Chen & Guestrin 2016                   | XGBoost foundation                                 |

And the **official foundations**:

* NVD/CVSS
* MITRE CVE/CWE/CPE
* CISA KEV
* FIRST EPSS

That is enough of a raw external corpus to hand to the next research stage. I would **not keep expanding indefinitely at this point**.

[1]: https://www.researchgate.net/publication/389091516_A_Survey_on_Vulnerability_Prioritization_Taxonomy_Metrics_and_Research_Challenges?_tp=eyJjb250ZXh0Ijp7InBhZ2UiOiJzY2llbnRpZmljQ29udHJpYnV0aW9ucyIsInByZXZpb3VzUGFnZSI6bnVsbCwic3ViUGFnZSI6bnVsbH19&utm_source=chatgpt.com "(PDF) A Survey on Vulnerability Prioritization: Taxonomy, Metrics, and Research Challenges"
[2]: https://arxiv.org/abs/2206.11182?utm_source=chatgpt.com "Vulnerability Prioritization: An Offensive Security Approach"
[3]: https://www.sciencedirect.com/science/article/pii/S2214212625000092?utm_source=chatgpt.com "FRAPE: A Framework for Risk Assessment, Prioritization and Explainability of vulnerabilities in cybersecurity - ScienceDirect"
[4]: https://www.mdpi.com/2076-3417/15/16/8787?utm_source=chatgpt.com "Automatic CVSS-Based Vulnerability Prioritization and Response with Context Information and Machine Learning"
[5]: https://arxiv.org/abs/2502.11143?utm_source=chatgpt.com "VulRG: Multi-Level Explainable Vulnerability Patch Ranking for Complex Systems Using Graphs"
[6]: https://nvd.nist.gov/vuln-metrics/cvss?force_isolation=true&utm_source=chatgpt.com "NVD - Vulnerability Metrics"
[7]: https://www.first.org/cvss/v3.0/specification-document?utm_source=chatgpt.com "CVSS v3.0 Specification Document"
[8]: https://essay.utwente.nl/essays/106247?utm_source=chatgpt.com "Severity vs Risk : The limitations of CVSS"
[9]: https://arxiv.org/abs/1908.04856?utm_source=chatgpt.com "Exploit Prediction Scoring System (EPSS)"
[10]: https://arxiv.org/abs/2302.14172?utm_source=chatgpt.com "Enhancing Vulnerability Prioritization: Data-Driven Exploit Predictions with Community-Driven Insights"
[11]: https://www.first.org/epss/research.html?utm_source=chatgpt.com "Research"
[12]: https://www.first.org/epss/?utm_source=chatgpt.com "Exploit Prediction Scoring System (EPSS)"
[13]: https://github.com/empiricalsec/epss_scores?utm_source=chatgpt.com "GitHub - empiricalsec/epss_scores: Historical scores for EPSS · GitHub"
[14]: https://papers.ssrn.com/sol3/Delivery.cfm/dd423b30-e009-427d-a603-b0d42f2e4585-MECA.pdf?abstractid=5147459&mirid=1&utm_source=chatgpt.com "Analysing the Temporal Dynamics of the Exploit Prediction Scoring Systems (Epss) by Damiano Ravalico, Mauro Farina, Martino Trevisan, Alberto Bartoli :: SSRN"
[15]: https://arxiv.org/abs/2411.02618?utm_source=chatgpt.com "Efficacy of EPSS in High Severity CVEs found in KEV"
[16]: https://doi.org/10.1145/3708821.3733875?utm_source=chatgpt.com "Bits and Pieces: Piecing Together Factors of IoT Vulnerability Exploitation | Proceedings of the 20th ACM Asia Conference on Computer and Communications Security"
[17]: https://www.nist.gov/publications/likely-exploited-vulnerabilities-proposed-metric-vulnerability-exploitation-probability?utm_source=chatgpt.com "Likely Exploited Vulnerabilities, A Proposed Metric for Vulnerability Exploitation Probability | NIST"
[18]: https://content.govdelivery.com/accounts/USDHSCISA/bulletins/3a644fe?utm_source=chatgpt.com "CISA Adds One Known Exploited Vulnerability to Catalog"
[19]: https://doi.org/10.1109/ACCESS.2026.3665768?utm_source=chatgpt.com "Vulnerability Management Chaining: An Integrated Framework for Efficient Cybersecurity Risk Prioritization"
[20]: https://www.usenix.org/system/files/sec22summer_suciu.pdf?utm_source=chatgpt.com "Expected Exploitability: Predicting the Development of Functional Vulnerability Exploits"
[21]: https://doi.org/10.1186/s42162-026-00640-x?utm_source=chatgpt.com "Integrated risk scoring and exploit prediction for cyber-physical power system vulnerabilities | Energy Informatics | Springer Nature Link"
[22]: https://www.sciencedirect.com/science/article/pii/S0167404826002385?utm_source=chatgpt.com "Decision-oriented vulnerability prioritization via context-aware probabilistic risk estimation - ScienceDirect"
[23]: https://arxiv.org/abs/2603.12450?utm_source=chatgpt.com "Bridging the Gap Between Security Metrics and Key Risk Indicators: An Empirical Framework for Vulnerability Prioritization"
[24]: https://arxiv.org/abs/1705.07874?utm_source=chatgpt.com "A Unified Approach to Interpreting Model Predictions"
[25]: https://arxiv.org/abs/1603.02754?utm_source=chatgpt.com "XGBoost: A Scalable Tree Boosting System"
[26]: https://www.nist.gov/itl/nvd?utm_source=chatgpt.com "National Vulnerability Database | NIST"

