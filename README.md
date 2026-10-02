# Vulnerability Prioritization & Triage System (VTS)

[![Build & Test Status](https://img.shields.io/badge/pytest-52%20passed-success)](tests/)
[![Python Version](https://img.shields.io/badge/python-3.10%20%7C%203.11%20%7C%203.12%20%7C%203.14-blue)](https://www.python.org/)
[![FastAPI](https://img.shields.io/badge/FastAPI-0.115+-009688?logo=fastapi&logoColor=white)](https://fastapi.tiangolo.com)
[![DuckDB](https://img.shields.io/badge/DuckDB-1.0+-FFF000?logo=duckdb&logoColor=black)](https://duckdb.org)
[![Dataset Freeze](https://img.shields.io/badge/dataset--freeze-2026--07--26-blue)](data/README.md)
[![EPSS Snapshot](https://img.shields.io/badge/epss--snapshot-2026--07--16-informational)](data/README.md)
[![Research Paper](https://img.shields.io/badge/paper-PDF%20Available-red)](docs/research/vts_research_paper.pdf)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A research prototype, reproducible machine learning pipeline, and decision-support web application for vulnerability prioritization, pre-scoring CVSS v3.1 estimation, publication-time exploitation prediction, and multi-criteria triage queue optimization under feature-timing constraints.

**Repository**: [https://github.com/seucra/vulnarability-prioritization-triage-system](https://github.com/seucra/vulnarability-prioritization-triage-system)  
**Research Paper**: [docs/research/vts_research_paper.md](docs/research/vts_research_paper.md) | [docs/research/vts_research_paper.pdf](docs/research/vts_research_paper.pdf)  
**Academic Institution**: Department of Computer Engineering, Vidyalankar Institute of Technology (VIT), Mumbai  

---

## Research Authors & Project Team

* **Shams Tabrez Ahmed** — *Lead Author & Core Developer*
* **Abaan Mhaisker** — *Co-author*
* **Om Shelke** — *Co-author*
* **Ayush Singasane** — *Co-author*
* **Lakshya Walurkar** — *Co-author*

*Project Guidance & Academic Supervision*: **Prof. Divya Nimbalkar**, Department of Computer Engineering, Vidyalankar Institute of Technology (VIT), Mumbai.

---

## Table of Contents

1. [Executive Overview](#executive-overview)
2. [Research Findings & Experimental Benchmarks](#research-findings--experimental-benchmarks)
   - [EXP-A1: CVSS v3.1 Regression](#exp-a1-cvss-v31-regression)
   - [EXP-B2: KEV Prediction Without EPSS](#exp-b2-kev-prediction-without-epss-under-temporal-split)
   - [EXP-B1: Retrospective EPSS Sensitivity Analysis](#exp-b1-retrospective-epss-snapshot-sensitivity-analysis)
   - [EXP-C1: Triage Simulation & Boundary Saturation](#exp-c1-triage-simulation--boundary-saturation-defect)
   - [SHAP Feature Explainability](#shap-feature-explainability)
3. [Local Dataset Architecture & Provenance](#local-dataset-architecture--provenance)
4. [System Architecture & Capabilities](#system-architecture--capabilities)
5. [Quickstart & Installation](#quickstart--installation)
6. [Automated Test Suite](#automated-test-suite)
7. [Reproducing Research Experiments](#reproducing-research-experiments)
8. [Consolidated Documentation Index](#consolidated-documentation-index)
9. [Code & Data Availability](#code-and-data-availability)
10. [Acknowledgment](#acknowledgment)

---

## Executive Overview

Enterprise security operations teams face an unmanageable volume of newly disclosed Common Vulnerabilities and Exposures (CVEs). Official National Vulnerability Database (NVD) CVSS assessments routinely suffer from publication disclosure lag (ranging from weeks to months), while Exploit Prediction Scoring System (EPSS) scores and CISA Known Exploited Vulnerabilities (KEV) listings reflect dynamic, post-disclosure intelligence.

A common pitfall in vulnerability machine-learning literature is the **feature-timing fallacy**: training models on cumulative historical snapshots where text descriptions, CWE classifications, and threat scores incorporate information that was not available at initial disclosure.

**VTS** investigates these challenges through:
1. **A Reproducible Data Pipeline**: Ingestion and canonicalization of **366,547 CVE records** (1988–2026) into columnar Parquet tables queried via DuckDB.
2. **Leakage-Safe Temporal Evaluation**: A strict two-stage inductive preprocessing protocol that prevents test-set vocabulary or distributional leakage across chronological split boundaries.
3. **Controlled Feature-Timing Sensitivity Analysis**: Quantifying the dramatic performance inflation ($12.35\times$ increase in average precision) caused by leaking post-disclosure EPSS threat telemetry.
4. **Queue Optimization & Boundary Analysis**: Identifying exact mathematical boundary saturation ($S \equiv x_4$ at CVSS 10.0) in multi-criteria nonlinear triage surfaces.
5. **Interactive Operational Decision Support**: A FastAPI backend and role-aware frontend providing an analyst-facing **Batch Vulnerability Triage Queue (WDL-7)** for immediate operational triage.

> **Operational Boundary Notice**: VTS is an academic research prototype and decision-support system. It is not an automated active defense tool, does not block attacks, and has not been validated on enterprise incident-response outcomes.

---

## Research Findings & Experimental Benchmarks

All models are evaluated on a strict **temporal partition** by official CVE publication year:
* **Train Partition ($\le 2022$)**: 203,652 canonical records (78,172 with CVSS v3.1).
* **Validation Partition ($2023–2024$)**: 71,653 canonical records (67,918 with CVSS v3.1).
* **Test Partition ($\ge 2025$)**: 91,242 canonical records (81,604 with CVSS v3.1).

### Preprocessing Protocol
All feature transformations (500-term TF-IDF n-grams, top-20 semantic CWE category rankings, CPE aggregates) are **fitted solely on the training partition ($\le 2022$)** during model selection/tuning on validation data, and **refitted on train-plus-validation data ($\le 2024$)** before evaluating on the held-out test partition ($\ge 2025$). No test split information leaks into model fitting.

```
       Historical Train (<= 2022)       Val (2023-2024)         Held-Out Test (>= 2025)
[====================================] [===============]     [=========================]
  Fit LeakageSafePreprocessor           Transform & Tune      
  Select Hyperparameters (Val AP/MAE)  
[======================================================]     [=========================]
  Refit LeakageSafePreprocessor on Train + Val (<= 2024) ---> Transform & Final Test Eval
```

---

### EXP-A1: CVSS v3.1 Regression
Predicts numeric CVSS v3.1 base scores ($[0.0, 10.0]$) directly from disclosure text descriptions and structural metadata (531 features), strictly excluding CVSS vector strings, EPSS, and KEV status. Evaluated on **81,604 held-out test CVEs** (2025–2026).

| Model | Selected Hyperparameters | Test MAE | Test RMSE | Test $R^2$ | Relative Error Reduction |
| :--- | :--- | :---: | :---: | :---: | :---: |
| **Ridge Regression (Baseline)** | $\alpha = 1.0$ | 1.0918 | 1.4051 | 0.3231 | Baseline |
| **XGBoost Regressor (Nonlinear)** | $\text{depth}=8, n=200, \eta=0.05$ | **0.9721** | **1.3046** | **0.4165** | **~10.96% MAE reduction** |

*Note: Differences between baseline and corrected runs compound the effects of leakage-safe inductive preprocessing and hyperparameter re-selection ($\alpha: 10.0 \to 1.0$).*

---

### EXP-B2: KEV Prediction Without EPSS Under Temporal Split
Predicts CISA KEV catalog inclusion by the freeze date using archived publication metadata alone (531 features), strictly excluding EPSS. Evaluated on **91,242 held-out test CVEs** with **294 KEV positives** (extreme class imbalance: **0.3222% positive base rate**).

| Metric | Logistic Regression ($C=1.0$) | XGBoost Classifier ($spw=100, d=6, n=200, \eta=0.05$) |
| :--- | :---: | :---: |
| **Average Precision (AP)** | 0.01737 | **0.02718** ($8.4\times$ random base rate) |
| **ROC-AUC** | **0.84969** | 0.82874 |
| **Precision@500** | 0.0300 (15 / 500) | **0.0720 (36 / 500)** |
| **Recall@500** | 0.05102 (15 / 294) | **0.12245 (36 / 294)** |
| **Random Baseline AP** | 0.00322 | 0.00322 |

*Note: Due to lack of historical NVD change logs, text and metadata reflect the July 26, 2026 archive snapshot; this represents evaluation on held-out records rather than verified zero-hour states.*

---

### EXP-B1: Retrospective EPSS-Snapshot Sensitivity Analysis
Evaluates the exact same test partition and model families when supplied with a static EPSS snapshot dated **July 16, 2026** (Model `v2026.06.15`), which postdates the 2025–2026 test CVE disclosures. Serves as an explicit **negative control**.

| Metric | EXP-B2 (No EPSS) | EXP-B1 (Retrospective EPSS) | Difference ($\Delta$) | Look-Ahead Inflation Ratio |
| :--- | :---: | :---: | :---: | :---: |
| **Average Precision (AP)** | 0.02718 | **0.33578** | +0.30860 | **$12.35\times$ increase** |
| **ROC-AUC** | 0.82874 | **0.98295** | +0.15421 | +18.6% |
| **Precision@500** | 0.0720 | **0.2680** | +0.1960 | $3.72\times$ increase |
| **True Positives in Top 500** | 36 / 500 | **134 / 500** | **+98 hits** | Captures 134 of 294 KEVs |
| **Recall@500** | 0.12245 (36/294) | **0.45578 (134/294)** | +0.33333 | $3.72\times$ increase |

*Methodological Warning: This massive performance jump reflects post-disclosure threat intelligence embedded in the July 2026 EPSS model, not superior publication-time modeling.*

---

### EXP-C1: Triage Simulation & Boundary Saturation Defect
Evaluates linear scoring vs. a nonlinear complement-product surface across 4 asset criticality tiers ($x_4 \in \{0.25, 0.50, 0.75, 1.00\}$) over **227,694 intersected CVEs**:
* **Linear**: $S_{\text{linear}} = 0.25 x_1 + 0.25 x_2 + 0.25 x_3 + 0.25 x_4$
* **Nonlinear**: $S_{\text{nonlinear}} = x_4 \left[ 1 - (1 - x_1)^{1 + \alpha x_3} (1 - x_2)^{1 + \beta x_3} \right], \quad \alpha=1.0, \beta=1.5$

| Asset Criticality Tier | Top-100 KEV (Linear) | Top-100 KEV (Nonlinear) | Top-1000 KEV (Linear) | Top-1000 KEV (Nonlinear) | Top-100 Jaccard Overlap | Spearman $\rho$ |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Tier 1 ($x_4=0.25$)** | 100 / 100 | **3 / 100** | 1000 / 1000 | **315 / 1000** | 0.005 (0.5%) | 0.9962 |
| **Tier 2 ($x_4=0.50$)** | 100 / 100 | **3 / 100** | 1000 / 1000 | **315 / 1000** | 0.005 (0.5%) | 0.9962 |
| **Tier 3 ($x_4=0.75$)** | 100 / 100 | **3 / 100** | 1000 / 1000 | **315 / 1000** | 0.005 (0.5%) | 0.9962 |
| **Tier 4 ($x_4=1.00$)** | 100 / 100 | **3 / 100** | 1000 / 1000 | **315 / 1000** | 0.005 (0.5%) | 0.9962 |

#### The Mathematical Saturation Cause
When CVSS base score is **10.0**, $x_1 = 1.0 \implies (1 - x_1) = 0$. Consequently, $(1 - x_1)^{1 + \alpha x_3} = 0$, completely erasing EPSS ($x_2$) and KEV status ($x_3$). The score collapses identically to:
$$S_{\text{nonlinear}} \equiv x_4$$
* Exactly **731 CVEs** in the corpus have CVSS 10.0 and tie at maximum score $x_4$.
* Of these 731 CVEs, **only 46 (6.3%) are KEV-positive**, while **685 (93.7%) are not listed in KEV**.
* Sorting descending scores without a secondary tie-breaker makes the top-100 queue selection sensitive to internal dataset row order (yielding only 3 KEV items).
* In contrast, the linear formula adds $+0.25 x_3$, directly rewarding KEV membership and floating KEV items to the top (100/100 capture is a retrospective artifact of directly inputting the label).

---

### SHAP Feature Explainability
Post-hoc TreeExplainer analysis on 2,000 test CVEs identifies key associative patterns:
* **EXP-A1 (CVSS Regressor)**: Top attributions include `tfidf_unauthorized` (0.34222), `tfidf_unauthenticated` (0.34216), `tfidf_critical` (0.27210), and `CWE-79` (Cross-Site Scripting, 0.18454).
* **EXP-B2 (KEV Classifier)**: Top attributions include `tfidf_gain` (0.82117), `CWE-22` (Path Traversal, 0.59967), and `tfidf_critical` (0.54493).
* *Disclaimer: SHAP values explain internal tree behavior and do not establish real-world causal mechanisms.*

---

## Local Dataset Architecture & Provenance

To maintain repository efficiency and comply with upstream data constraints, all raw feeds, processed Parquet tables, SQLite databases, and experiment binaries are **stored locally** and excluded from Git tracking via `.gitignore`. Complete schemas and reconstruction instructions are documented in [data/README.md](data/README.md).

```text
data/
├── README.md                          # Comprehensive dataset schema guide (tracked)
├── custom_test_results.json           # Pipeline test execution output (tracked)
├── auth_users.sqlite                  # [Local] SQLite user database with PBKDF2 hashes
├── raw/                               # [Local] Upstream raw feeds
│   ├── nvd/                           # NVD yearly JSON archives (1988–2026, frozen 2026-07-26)
│   ├── known_exploited_vulnerabilities.json # CISA KEV catalog (1,647 CVEs)
│   └── epss_scores-2026-07-16.csv.gz  # FIRST EPSS snapshot (Model v2026.06.15)
├── processed/                         # [Local] Canonical Parquet tables (Snappy compressed)
│   ├── vulnerabilities.parquet        # 366,547 canonical CVE records (1988–2026)
│   ├── cve_cwe.parquet                # 374,210 CWE weakness mappings
│   ├── cve_cpe.parquet                # 1,529,842 CPE software applicability entries
│   ├── cve_epss.parquet               # 366,547 EPSS scores and percentiles
│   ├── kev.parquet                    # 1,647 KEV records with ransomware flags
│   └── cve_vendor_statements.parquet  # 8,124 official vendor statements & mitigations
└── experiments/                       # [Local] Experiment models & predictions
    ├── phase3_baseline/               # 15 immutable original baseline artifacts (SHA-256 verified)
    └── phase3_corrected/              # 14 corrected leakage-safe artifacts (EXP-A1, B2, B1, C1)
```

---

## System Architecture & Capabilities

```
+---------------------------------------------------------------------------------+
|                       Frontend Single-Page Application (SPA)                    |
|       (Vanilla JS ES Modules, Light Theme CSS Design System, Responsive UI)     |
+---------------------------------------------------------------------------------+
           |                                                   ^
           | REST API Requests                                 | JSON Responses
           v                                                   |
+---------------------------------------------------------------------------------+
|                         FastAPI REST Backend (Port 5002)                        |
|                                                                                 |
|   +-------------------+  +--------------------+  +--------------------------+   |
|   | /api/v1/auth      |  | /api/v1/triage     |  | /api/v1/triage/batch     |   |
|   | RBAC Session Auth |  | Search, Filter,    |  | Analyst Batch Queue      |   |
|   | PBKDF2 Hashing    |  | Detail Drawers     |  | (Multi-CVE Triage)       |   |
|   +-------------------+  +--------------------+  +--------------------------+   |
|                                     |                                           |
|                                     v                                           |
|   +-------------------------------------------------------------------------+   |
|   |                      DuckDB Columnar Query Engine                       |   |
|   |              Vectorized SQL execution over local Parquet files          |   |
|   +-------------------------------------------------------------------------+   |
|                                     |                                           |
|                                     v                                           |
|   +-------------------------------------------------------------------------+   |
|   |                        Machine Learning Models                          |   |
|   |     - EXP-A1: XGBoost Regressor (Pre-scoring CVSS v3.1 estimation)      |   |
|   |     - EXP-B2: XGBoost Classifier (Publication-time KEV prediction)      |   |
|   |     - SHAP TreeExplainer (Local feature attribution)                    |   |
|   +-------------------------------------------------------------------------+   |
+---------------------------------------------------------------------------------+
```

### Core Application Capabilities
* **Vulnerability Explorer**: Query, filter, and inspect 366,547 canonical CVE records by vendor, product, CWE, CVSS severity range, and KEV status with CSV/JSON export.
* **Batch Vulnerability Triage Queue (WDL-7)**: Analyst workflow accepting lists of up to 100 CVE IDs, auto-populating CVSS/EPSS/KEV metadata, applying Mode 1 (Linear) vs. Mode 2 (Nonlinear) prioritization, and exporting ranked triage queues.
* **Role-Based Access Control (RBAC)**: Role-differentiated capabilities for **Security Analyst**, **Academic Researcher**, and **Administrator** backed by SQLite.
* **Printable Triage Reports**: One-click print-friendly vulnerability reports clearly distinguishing authoritative NVD records, machine-learning inferences, and decision-support scores.

---

## Quickstart & Installation

### Prerequisites
* Linux, macOS, or Windows (WSL2 recommended)
* Python 3.10+ (tested through Python 3.14.7)
* Pandoc & XeLaTeX (optional, for compiling the research paper PDF)

### Quickstart (Single Command)
Run the entire platform with one script (automatically configures venv, installs dependencies, initializes the local environment, and launches the server on port 5002):

```bash
./run.sh
```

### Manual Setup

1. **Clone the repository**:
   ```bash
   git clone https://github.com/seucra/vulnarability-prioritization-triage-system.git
   cd vulnarability-prioritization-triage-system
   ```

2. **Create and activate a virtual environment**:
   ```bash
   python3 -m venv .venv
   source .venv/bin/activate
   ```

3. **Install dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Launch the FastAPI Backend & SPA**:
   ```bash
   PYTHONPATH=. uvicorn backend.app.main:app --port 5002 --reload
   ```

5. **Access the application**:
   * Web Interface: [http://localhost:5002/#home](http://localhost:5002/#home)
   * System Health: [http://localhost:5002/health](http://localhost:5002/health)
   * OpenAPI Swagger Documentation: [http://localhost:5002/api/v1/docs](http://localhost:5002/api/v1/docs)

---

## Automated Test Suite

The test suite validates backend API contracts, authentication and RBAC security, batch triage algorithms, ETL data invariants, and the leakage-safe preprocessing pipeline:

```bash
PYTHONPATH=. .venv/bin/pytest tests/ -v
```

```text
tests/test_auth_rbac.py ...............                                  [ 28%]
tests/test_backend_api.py .........                                      [ 46%]
tests/test_batch_triage.py .......                                       [ 59%]
tests/test_etl_invariants.py ...............                             [ 88%]
tests/test_preprocessing_and_experiments.py ......                       [100%]

======================= 52 passed in 14.10s =======================
```

---

## Reproducing Research Experiments

All experimental scripts are located in `scripts/experiments/` and default to generating artifacts under `data/experiments/phase3_corrected/`:

```bash
# 1. Multi-Criteria Triage Simulation (EXP-C1)
PYTHONPATH=. .venv/bin/python scripts/experiments/run_exp_c1.py

# 2. CVSS v3.1 Regression with Inductive Preprocessing (EXP-A1)
PYTHONPATH=. .venv/bin/python scripts/experiments/run_exp_a1.py

# 3. KEV Exploitation Prediction Without EPSS (EXP-B2)
PYTHONPATH=. .venv/bin/python scripts/experiments/run_exp_b2.py

# 4. Retrospective EPSS Sensitivity Analysis (EXP-B1)
PYTHONPATH=. .venv/bin/python scripts/experiments/run_exp_b1.py

# 5. Compile Research Paper to PDF
pandoc docs/research/vts_research_paper.md -o docs/research/vts_research_paper.pdf --pdf-engine=xelatex
```

---

## Consolidated Documentation Index

Documentation is organized into single-source-of-truth modules:

* **Research Paper**:
  * [docs/research/vts_research_paper.md](docs/research/vts_research_paper.md) — Complete IEEE-style Markdown manuscript.
  * [docs/research/vts_research_paper.pdf](docs/research/vts_research_paper.pdf) — Compiled camera-ready PDF.
  * [docs/research/EVIDENCE_AUDIT.md](docs/research/EVIDENCE_AUDIT.md) — Comprehensive experiment audit and verification log.
  * [docs/research/DATA_MANIFEST.md](docs/research/DATA_MANIFEST.md) — Cryptographic hashes and dataset provenance.
* **System Architecture & Design**:
  * [docs/architecture/ARCHITECTURE.md](docs/architecture/ARCHITECTURE.md) — Full technical architecture, DuckDB engine, and security specs.
  * [docs/architecture/API.md](docs/architecture/API.md) — Complete REST API reference, request/response schemas, and error codes.
  * [docs/design/DESIGN.md](docs/design/DESIGN.md) — Design system tokens, color palettes, and typography specifications.
  * [docs/prd/PRD.md](docs/prd/PRD.md) — Product requirements, personas, scope, and acceptance criteria.
* **Institutional Memory & Invariants**:
  * [docs/memory/MEMORY.md](docs/memory/MEMORY.md) — Chronological history, architectural decisions, and project defense model.
  * [docs/rules/RULES.md](docs/rules/RULES.md) — System invariants, cardinal non-claims, and coding standards.
  * [docs/legacy/README.md](docs/legacy/README.md) — Preserved historical notes, phase reports, and audit logs.

---

## Code and Data Availability

The implementation and experimental code for this study are available in the project repository:

* **Repository:** [https://github.com/seucra/vulnarability-prioritization-triage-system](https://github.com/seucra/vulnarability-prioritization-triage-system)
* **Experimental Artifacts:** See the repository's `data/`, `scripts/`, and relevant experiment documentation, where available.
* **Reproducibility:** The reported results were obtained using the dataset snapshots, temporal partitions, feature configurations, and model settings described in the methodology. Exact reproduction requires access to the corresponding data and experiment artifacts.

The dataset is based on the National Vulnerability Database (NVD), with exploitation labels derived from the CISA Known Exploited Vulnerabilities (KEV) catalog and EPSS data from FIRST. These sources are available at [NVD](https://nvd.nist.gov/), [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog), and [FIRST EPSS](https://www.first.org/epss/).

---

## Acknowledgment

The authors would like to thank **Prof. Divya Nimbalkar** for her guidance and academic support throughout this project. We also acknowledge the **Department of Computer Engineering, Vidyalankar Institute of Technology (VIT), Mumbai**, for providing the academic environment in which this work was undertaken.

---

## License

This project is licensed under the [MIT License](LICENSE).
