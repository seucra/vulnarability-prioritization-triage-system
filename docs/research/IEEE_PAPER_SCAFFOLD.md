---
title: "Vulnerability Prioritization & Triage System"
author: "Seucra et al."
date: \today
documentclass: IEEEtran
classoption:
  - conference
  - letterpaper
fontsize: 10pt
geometry: margin=0.7in
bibliography: references.bib
csl: ieee.csl
link-citations: true
colorlinks: false
---

<!--
WORKING DRAFT SCAFFOLD — not submission-ready.
Replace every [TODO] and verify every reported result against repository artifacts.
For an IEEE conference-style PDF, use an IEEEtran-compatible Pandoc/LaTeX setup.
A CSL file formats citations/references; it does not by itself create the IEEE two-column layout.
-->

# Abstract

Vulnerability management requires security teams to prioritize a large and continually changing set of disclosed vulnerabilities under limited remediation resources. Severity scores alone do not fully represent exploitation evidence, prediction uncertainty, or the criticality of the affected assets. This paper presents the **Vulnerability Prioritization & Triage System**, a research prototype that combines vulnerability data processing, machine-learning experiments, explainability, and a web-based triage workflow. The experimental study evaluates (i) CVSS score estimation using regression, (ii) prediction of known-exploited vulnerability status under a temporal evaluation design, and (iii) a simulation of vulnerability-ranking strategies. The system also provides model-output explanations and a user-facing interface for exploring and prioritizing vulnerabilities. Results are reported only for experiments whose saved metrics and prediction artifacts can be verified. Particular attention is paid to temporal feature availability, class imbalance, and the distinction between predictive performance and operational remediation benefit. [TODO: insert verified dataset counts, split dates, key metrics, and the precise contribution after the evidence audit.]

**Index Terms—** vulnerability management, vulnerability prioritization, CVE, CVSS, Known Exploited Vulnerabilities, machine learning, explainable AI, temporal evaluation.

# I. Introduction

The volume of publicly disclosed software vulnerabilities creates a prioritization problem: organizations generally cannot remediate every finding immediately, so they must decide which vulnerabilities deserve attention first. Common vulnerability metadata provides useful signals, but severity, evidence of exploitation, and the importance of the affected asset represent different dimensions of a remediation decision.

This work presents the **Vulnerability Prioritization & Triage System**, a research prototype intended to support vulnerability analysis through a data pipeline, predictive experiments, ranking simulations, and a web application. The project studies three related but distinct tasks: estimating CVSS scores, predicting whether a vulnerability is listed in the Known Exploited Vulnerabilities (KEV) catalog, and simulating prioritization strategies.

The study makes the following contributions, subject to verification against the implementation and saved artifacts:

1. A data-processing workflow that combines vulnerability records with related metadata from documented sources.
2. A temporally partitioned evaluation of machine-learning models for CVSS estimation and KEV-status prediction.
3. An analysis of how retrospective feature availability can affect reported predictive performance.
4. A simulation-based comparison of vulnerability-ranking strategies, together with a web prototype for exploring results and supporting triage.

These contributions are deliberately separated: model prediction, ranking simulation, and application functionality are not treated as interchangeable evidence of real-world security effectiveness.

# II. Background and Related Work

## A. Vulnerability Severity and Exploitation Evidence

The Common Vulnerability Scoring System (CVSS) expresses vulnerability severity under a defined scoring specification. A severity score is not, by itself, a complete estimate of exploitation likelihood or organization-specific risk. [TODO: cite the applicable official CVSS specification.]

The CISA Known Exploited Vulnerabilities (KEV) catalog records vulnerabilities known to have been exploited in the wild. KEV membership is an important exploitation signal, but the timing at which a vulnerability entered the catalog must be considered when constructing prediction labels and features. [TODO: cite the official CISA KEV catalog and its documentation.]

The Exploit Prediction Scoring System (EPSS) provides a probability estimate of exploitation activity for a CVE over a defined future window. A model using an EPSS snapshot collected after the prediction cutoff may benefit from information unavailable at the intended decision time. [TODO: cite official FIRST EPSS documentation and state the exact snapshot date used in this project.]

## B. Machine Learning and Explainability for Vulnerability Analysis

Prior work has applied statistical learning to vulnerability severity, exploit prediction, and vulnerability prioritization. [TODO: summarize verified papers; distinguish peer-reviewed publications from preprints and technical reports.] Feature-attribution methods such as SHAP can help describe which features influence a model's output. Such explanations describe model behavior and do not establish causation. [TODO: cite the original SHAP paper and relevant methodological literature.]

## C. Research Gap and Scope

[TODO: Define a narrow, evidence-backed gap after reviewing the literature. Do not claim that no prior work exists unless the literature search supports that claim. Explain what this project evaluates that is distinct from the closest related studies.]

# III. System Overview

The system consists of a vulnerability-data pipeline, saved experimental artifacts, backend API services, and a web frontend. The implementation details in this section must be checked against the current repository before submission.

## A. Data Sources and Processing

[TODO: List each source, exact download/snapshot date, fields used, processing steps, deduplication rules, join keys, and missing-data handling. Cite official source documentation. Do not imply that the current snapshot represents historical information available at each CVE's publication date.]

## B. Experimental Components

- **EXP-A1 — CVSS regression:** estimates CVSS scores from the documented input features.
- **EXP-B2 — KEV prediction baseline:** predicts KEV status using features available under the experiment's stated temporal assumptions.
- **EXP-B1 — retrospective EPSS comparison:** evaluates a setup that includes a later EPSS snapshot. Treat this as a retrospective sensitivity comparison, not as a valid prospective deployment result unless feature availability at prediction time is demonstrated.
- **EXP-C1 — ranking simulation:** compares the documented prioritization score with its baseline under the simulation assumptions.
- **SHAP analysis:** describes selected model predictions or aggregate feature attributions, according to the saved analysis.

[TODO: Verify model types, feature lists, target definitions, split boundaries, random seeds, and saved artifact provenance from the code and metrics files.]

## C. Web Application

[TODO: Describe only implemented and tested capabilities: relevant pages, API endpoints, user inputs, prioritization modes, explanations, provenance, exports, and authentication/authorization if applicable. Distinguish a research prototype from a production security service.]

# IV. Methodology

## A. Dataset Construction

[TODO: Give the number of records at each processing stage; date range; inclusion/exclusion rules; label prevalence; missingness; and how joins were performed. Provide separate counts for experiments if they use different populations.]

## B. Temporal Evaluation

[TODO: State the exact training, validation, and test periods for each experiment. Explain the prediction cutoff and the timestamp at which every feature would have been available. Do not describe a split as leakage-free without checking feature provenance and label construction.]

## C. EXP-A1: CVSS Regression

The target is [TODO: exact CVSS field and version]. The input features are [TODO: verified feature list or concise feature groups]. Models and hyperparameter selection are [TODO: exact methods]. Performance is measured using [TODO: MAE, RMSE, and any other saved metrics], on the same test population.

## D. EXP-B1 and EXP-B2: KEV-Status Prediction

The target is [TODO: exact KEV label definition and observation cutoff]. Because positive labels may be rare, report class prevalence and precision-recall metrics, including PR-AUC / average precision as implemented. State the thresholding procedure for any precision, recall, or F1 result.

EXP-B2 is the baseline configuration. EXP-B1 adds [TODO: exact EPSS feature and snapshot date]. Explain whether that value was available at the intended prediction time. If it was not, interpret EXP-B1 as a retrospective comparison illustrating sensitivity to feature timing, not as a deployable prospective model.

## E. EXP-C1: Prioritization Simulation

[TODO: Give the exact ranking formula, every term and weight, asset-criticality mapping, tie-breaking rule, and baseline. Define the simulated workload or top-K budget. State evaluation measures and whether the comparison uses a common set of CVEs with row-level scores from every method.]

## F. Explainability

[TODO: State which model was explained, which SHAP explainer was used, the background/sample population, and whether the figure shows global or local attribution. Interpret SHAP as model attribution, not causal evidence.]

## G. Reproducibility

[TODO: List software/library versions, seeds, scripts/commands, input snapshot identifiers, and paths to metrics/predictions. Record which artifacts were available for independent verification.]

# V. Results

Do not fill this section from memory or copy figures without checking their source files. Use the saved `metrics.json`, prediction Parquet files, and experiment scripts as the source of truth.

## A. EXP-A1: CVSS Regression

[TODO: Insert verified test-set size and metrics for every compared model. Include a table with model, MAE, RMSE, and any other directly measured metric. State the CVSS version and test period.]

## B. EXP-B1/B2: KEV Prediction

[TODO: Insert test-set size, number of positive and negative cases, prevalence, PR-AUC / average precision, and other verified metrics. Explain why PR-AUC is relevant under class imbalance. Report the B1/B2 comparison with explicit feature-timing caveats.]

## C. EXP-C1: Ranking Simulation

[TODO: Report the actual simulation population, score formula, baseline, workload/top-K definition, and verified ranking metrics. Do not claim improved remediation outcomes unless these were measured.]

## D. SHAP Results

[TODO: Describe the actual saved SHAP results and their scope. Avoid causal language.]

## E. Application Verification

[TODO: Report tests that were actually run, their result, date/commit if available, and the scope of testing. Separate automated tests from manual end-to-end checks.]

# VI. Discussion

The experiments address different questions and should be interpreted separately. CVSS regression evaluates approximation of a severity score; it does not directly measure exploitation probability. KEV-status prediction evaluates discrimination against a defined label and time window; it does not establish that the model will generalize to other periods or organizations. Ranking simulation evaluates the consequences of a specified formula under its assumptions; it does not by itself demonstrate reduced compromise risk or improved remediation outcomes.

[TODO: Discuss verified findings, plausible explanations, comparison with the closest prior work, practical implications, and unexpected results. Avoid causal claims unless the experimental design supports them.]

# VII. Limitations and Threats to Validity

Address, where applicable:

1. **Temporal validity:** current snapshots of EPSS or KEV may contain information unavailable at the historical prediction cutoff.
2. **Label limitations:** KEV membership is a catalog-based label and is not equivalent to all exploitation activity.
3. **Class imbalance:** aggregate accuracy can be misleading when positive cases are rare.
4. **Dataset coverage:** missing CVSS versions, incomplete vendor/product mappings, and differing experiment populations can affect comparability.
5. **Metric comparability:** scores from different test populations must not be compared as if they were evaluated on the same cases.
6. **Simulation assumptions:** ranking results depend on the score formula, asset weights, budget, and selected evaluation metric.
7. **External validity:** public vulnerability data and a prototype environment do not represent every organization's asset inventory or remediation process.
8. **Reproducibility:** unavailable raw artifacts, changing source snapshots, or undocumented preprocessing may limit independent reproduction.
9. **Explainability:** SHAP describes model attribution and should not be interpreted as causal explanation.
10. **Deployment scope:** a public demonstration deployment is not evidence of production-grade security, availability, or operational effectiveness.

[TODO: Retain only limitations relevant to the actual implementation and explain their effect.]

# VIII. Conclusion and Future Work

This paper presented the Vulnerability Prioritization & Triage System, a research prototype combining vulnerability-data processing, machine-learning experiments, ranking simulation, explainability, and a web-based triage interface. The conclusions must be limited to the results verified in the preceding sections.

[TODO: State two or three concrete, measured findings. Do not introduce new metrics or claims here.]

Future work may include strict historical feature snapshots, evaluation on a common CVE population, calibration and threshold analysis, external temporal validation, richer asset-context integration, user studies with security practitioners, and operational evaluation of remediation workload. These are future directions unless already implemented and evaluated.

# References

<!--
Use numbered IEEE-style citations in the text, e.g., [1], [2].
Add only sources that have been checked and actually cited in the paper.
Maintain references.bib and ieee.csl alongside this Markdown file.
-->

[TODO: Add verified references: official NVD documentation, official CVSS specification, CISA KEV catalog, FIRST EPSS documentation, original SHAP paper, and relevant peer-reviewed vulnerability-prioritization studies. Label preprints and technical reports accurately.]

# Appendix A: Artifact and Claim Audit

[TODO: For every reported metric, record the artifact path, metric key, test population, script/commit, and verification status. This appendix can be removed from the submitted paper if not required.]

# Appendix B: Reproducibility Checklist

- [ ] Dataset snapshot dates and sources documented.
- [ ] Exact target definitions and feature availability documented.
- [ ] Train/validation/test periods verified.
- [ ] Metrics copied from saved artifacts and independently recomputed where possible.
- [ ] Experiment populations and positive-label counts reported.
- [ ] Ranking comparisons use a common population or clearly state why not.
- [ ] Figures and tables trace to scripts or saved outputs.
- [ ] Citations checked against original sources.
- [ ] Claims distinguish measured results, interpretation, and future work.
- [ ] No secrets, credentials, or private user data included.
