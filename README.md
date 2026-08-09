# Vulnerability Prioritization & Triage System

[![Build & Test Status](https://img.shields.io/badge/pytest-39%20passed-success)](https://github.com/seucra/vulnarability-prioritization-triage-system)
[![Dataset Freeze](https://img.shields.io/badge/dataset--freeze-2026--07--26-blue)](docs/research/PROCESSED_DATA_MANIFEST.md)
[![EPSS Snapshot](https://img.shields.io/badge/epss--snapshot-2026--07--16-informational)](docs/research/PROCESSED_DATA_MANIFEST.md)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)

A research-backed decision-support web application for vulnerability prioritization, pre-scoring CVSS v3.1 estimation, publication-time KEV threat risk prediction, SHAP explainability, and multi-criteria triage simulation.

**Repository**: `seucra/vulnarability-prioritization-triage-system`

---

## Executive Overview

Security operations teams face an overwhelming annual volume of newly disclosed Common Vulnerabilities and Exposures (CVEs). Official National Vulnerability Database (NVD) CVSS base score assessments often suffer from publication disclosure lag (weeks to months), while EPSS scores and CISA Known Exploited Vulnerabilities (KEV) listings reflect post-publication observations.

This project implements a reproducible data engineering pipeline (Phase 0–1), temporal machine learning evaluation protocol (Phase 2–3), FastAPI REST application layer (Phase 4), and role-aware single-page application (WDL-1–4) to support immediate vulnerability triage upon initial public disclosure.

---

## Key Features & Capabilities

- **Vulnerability Explorer**: Search, filter, and triage **366,547 canonical CVE records** (2002–2026) across vendor, product, CWE weakness, CVSS severity range, and CISA KEV status. Includes CSV and JSON export tools.
- **Pre-Scoring CVSS Estimation (EXP-A1)**: Pre-scoring XGBoost regressor predicting official NVD CVSS v3.1 base scores ($MAE = 0.9750$) from initial text descriptions and metadata available at disclosure time.
- **Publication-Time KEV Risk Prediction (EXP-B2)**: XGBoost binary classifier predicting eventual CISA KEV catalog inclusion ($PR\text{-}AUC = 0.02884$, $8.96\times$ precision uplift over random baseline) strictly excluding post-publication telemetry to prevent data leakage (EXP-B1).
- **Dual-Mode Prioritization Engine (EXP-C1)**: Combines vulnerability severity, threat likelihood, and 4 controlled asset criticality tiers ($A \in \{0.25, 0.50, 0.75, 1.00\}$) using **Mode 1** (Linear Equal Weights $S_{\text{linear}}$) or **Mode 2** (Nonlinear Interactive Surface $S_{\text{nonlinear}}$).
- **SHAP Feature Explainability**: Local Shapley additive explanations decomposing predictions into positive and negative term attributions.
- **Role-Based Access Control (RBAC)**: Server-enforced authorization matrix supporting **Security Analyst**, **Academic Researcher**, and **Administrator** roles backed by SQLite storage (`data/auth_users.sqlite`) and PBKDF2-HMAC-SHA256 password security.
- **Printable Triage Reports**: One-click print-friendly vulnerability report generator clearly distinguishing authoritative NVD metadata, predictive model inference, and decision-support prioritization.

---

## Machine Learning Experiment Benchmarks

All models follow strict **temporal evaluation partitioning** to prevent temporal cross-year data leakage:
- **TRAIN Partition (2002–2022)**: 208,602 CVEs for model parameter learning.
- **VALIDATION Partition (2023–2024)**: 71,061 CVEs for hyperparameter tuning.
- **TEST Partition (2025–2026)**: 86,884 CVEs held out for final model evaluation.

| Experiment ID | Model Objective | Feature Boundary | Evaluation Metric | Performance |
| :--- | :--- | :--- | :--- | :--- |
| **EXP-A1** | Pre-Scoring CVSS v3.1 Base Regressor | Publication-Time Text + CWE | Mean Absolute Error (MAE) | **0.9750** |
| **EXP-B2** | Publication-Time KEV Classifier | Publication-Time Text + CPE + CWE | PR-AUC (vs Random 0.00322) | **0.02884 ($8.96\times$ Uplift)** |
| **EXP-B1** | Retrospective EPSS/CVSS Leakage Finding | Post-Publication Telemetry | PR-AUC Baseline | **0.3010** *(Strictly Excluded)* |
| **EXP-C1** | Multi-Criteria Triage Simulation | Dual-Mode Surface + Asset Tier | Rank Reordering Sensitivity | **Verified Across 4 Tiers** |

---

## Technology Stack

- **Backend API**: Python 3.10+, FastAPI, Uvicorn, Pydantic v2, Pytest.
- **Query & Storage Layer**: DuckDB high-performance SQL query engine over 6 read-only Parquet datasets (`data/processed/*.parquet`), SQLite user store (`data/auth_users.sqlite`).
- **Machine Learning**: XGBoost, Scikit-Learn, SHAP TreeExplainer, SciPy.
- **Frontend Architecture**: Vanilla JavaScript ES Modules, HTML5, Vanilla CSS Design System with light theme tokens and responsive media queries.

---

## Quickstart & Local Setup

### Prerequisites
- Linux / macOS / Windows with Python 3.10+ installed.

### Installation Steps

1. **Clone Repository & Set Up Environment**:
   ```bash
   git clone git@github.com:seucra/vulnarability-prioritization-triage-system.git
   cd vulnarability-prioritization-triage-system
   python3 -m venv .venv
   source .venv/bin/activate
   pip install -r requirements.txt
   ```

2. **Start Backend API & SPA Server**:
   ```bash
   PYTHONPATH=. uvicorn backend.app.main:app --port 5002
   ```

3. **Access Application**:
   - Web Application: `http://localhost:5002/#home`
   - System Health: `http://localhost:5002/health`
   - OpenAPI Swagger Specifications: `http://localhost:5002/api/v1/docs`

---

## Automated Testing Suite

Execute the complete 39-test automated Pytest suite:

```bash
.venv/bin/python -m pytest tests/test_auth_rbac.py tests/test_backend_api.py tests/test_etl_invariants.py
```

```text
======================= 39 passed in 11.92s =======================
```

---

## Public Demonstration Deployment Status

The application is prepared for **Research Prototype / Public Demonstration Deployment**.

- **Frontend SPA**: `https://vuln-triage.seucra.tech` (Hosted on **GitHub Pages** via GitHub Actions workflow `.github/workflows/deploy_frontend.yml`).
- **Backend REST API**: `https://vuln-triage-api.seucra.tech` (Exposed via **Cloudflare Tunnel** to local FastAPI Uvicorn listener on port 5002).
- Full deployment details: See [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

---

## Documentation Index

Detailed documentation is available in the repository:
- [USER_MANUAL.md](docs/USER_MANUAL.md): User workflow manual.
- [API.md](docs/architecture/API.md): REST API specification.
- [SYSTEM_REQUIREMENTS.md](docs/SYSTEM_REQUIREMENTS.md): System requirements & constraints.
- [PHASE_4_BACKEND_ARCHITECTURE.md](docs/architecture/PHASE_4_BACKEND_ARCHITECTURE.md): Backend system architecture.
- [AUTHENTICATION_AND_RBAC.md](docs/architecture/AUTHENTICATION_AND_RBAC.md): Auth & RBAC security design.
- [ROLE_DASHBOARDS_AND_WORKFLOWS.md](docs/architecture/ROLE_DASHBOARDS_AND_WORKFLOWS.md): Role dashboards architecture.
- [DEPLOYMENT.md](docs/DEPLOYMENT.md): Deployment guide.
- [PHASE_3_EXPERIMENT_REPORT.md](docs/research/PHASE_3_EXPERIMENT_REPORT.md): Research experiment report.

---

## Research Immutability & Reproducibility Guarantee

The canonical processed dataset (`data/processed/*.parquet`), ETL scripts (`scripts/build_processed_data.py`), research experiment configurations (`scripts/experiments/`), and serialized XGBoost model binaries (`data/experiments/phase3/`) are frozen and cryptographically hash-verified.
