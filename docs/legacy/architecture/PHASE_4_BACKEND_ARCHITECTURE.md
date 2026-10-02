# Phase 4 — Backend Architecture Document

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Phase**: Phase 4 — Application / Backend Layer  
**Status**: Complete & Verified  

---

## 1. Overview & Objectives

The Phase 4 application layer converts the validated research artifacts from Phase 3 into a high-performance REST API backend built with **FastAPI**, **DuckDB**, **Scikit-Learn**, **XGBoost**, and **SHAP**. 

The backend provides:
1. Vulnerability search, keyword filtering, and detail retrieval over 366,547 canonical CVE records.
2. Pre-scoring CVSS v3.1 base score estimation (**EXP-A1 XGBoost Regressor**).
3. Publication-time CISA KEV catalog risk prediction (**EXP-B2 XGBoost Classifier**).
4. Separate exposure of current static EPSS snapshot data (`2026-07-16T12:03:48Z`).
5. Dual-mode multi-criteria prioritization across controlled Asset Criticality Tiers (Tier 1–4):
   - **Mode 1 — Transparent Linear Baseline**: $S_{\text{linear}} = 0.25 x_1 + 0.25 x_2 + 0.25 x_3 + 0.25 x_4$ (Project-controlled equal weights baseline).
   - **Mode 2 — Nonlinear Interactive Surface**: $S_{\text{nonlinear}} = x_4 \cdot \left[ 1 - (1 - x_1)^{1 + 1.0 x_3} \cdot (1 - x_2)^{1 + 1.5 x_3} \right]$ ($\alpha=1.0, \beta=1.5$).
6. Model explainability via SHAP (`shap.TreeExplainer`).
7. Complete system and dataset research provenance.

---

## 2. Architecture & Data Flow

```
                                  [ Client / API Request ]
                                             │
                                             ▼
                             ┌───────────────────────────────┐
                             │    FastAPI Application        │
                             │     (backend.app.main)        │
                             └───────────────┬───────────────┘
                                             │
                                             ▼
                             ┌───────────────────────────────┐
                             │       APIRouter (v1)          │
                             └───────────────┬───────────────┘
                                             │
      ┌───────────────────┬──────────────────┼───────────────────┬───────────────────┐
      │                   │                  │                   │                   │
      ▼                   ▼                  ▼                   ▼                   ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│Vulnerabilities│  │ Predictions  │   │ Prioritization│  │ Explanations │   │  Provenance  │
│  Endpoint    │   │  (A1 & B2)   │   │(Linear/Nonlin)│  │    (SHAP)    │   │   Endpoint   │
└──────┬───────┘   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘   └──────┬───────┘
       │                  │                  │                  │                  │
       ▼                  ▼                  ▼                  ▼                  ▼
┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐   ┌──────────────┐
│Vulnerability │   │  Inference   │   │   Scoring    │   │ Explanation  │   │  Provenance  │
│   Service    │   │   Service    │   │   Service    │   │   Service    │   │   Service    │
└──────┬───────┘   └──────┬───────┘   └──────────────┘   └──────┬───────┘   └──────────────┘
       │                  │                                     │
       ▼                  ▼                                     ▼
┌──────────────┐   ┌──────────────┐                      ┌──────────────┐
│    DuckDB    │   │ Reconstructed│                      │ TreeExplainer│
│Query Engine  │   │ Phase 3 XGB  │                      │   (SHAP)     │
└──────┬───────┘   └──────────────┘                      └──────────────┘
       │
       ▼
┌──────────────────────────────────────────────────────────────────┐
│   Frozen Parquet Datasets (data/processed/*.parquet - READ ONLY)│
└──────────────────────────────────────────────────────────────────┘
```

---

## 3. Core Component Design

### 3.1 Database Query Engine (`backend/app/core/database.py`)
- Uses `duckdb` to query immutable Parquet files directly in memory without loading full datasets.
- Executes SQL joins across `vulnerabilities.parquet`, `cve_cwe.parquet`, `cve_cpe.parquet`, `epss.parquet`, `kev.parquet`, and `vendor_statements.parquet`.
- Enforces strict pagination (`page_size` capped at 100).

### 3.2 Model Inference Service (`backend/app/services/inference_service.py`)
- Loads reconstructed frozen Phase 3 XGBoost models (`model.xgb`) and TF-IDF vectorizers (`vectorizer.joblib`) once at startup.
- **A1 CVSS Regressor**: Predicts estimated CVSS v3.1 base score $[0.0, 10.0]$ from text and metadata.
- **B2 KEV Classifier**: Predicts publication-time KEV catalog inclusion probability.
- **Boundary Enforcement**: Strictly rejects post-publication EPSS features and CVSS vector components on B2 requests.

### 3.3 Prioritization Scoring Service (`backend/app/services/scoring_service.py`)
- **Mode 1 Linear Baseline**:
  $$S_{\text{linear}} = 0.25 x_1 + 0.25 x_2 + 0.25 x_3 + 0.25 x_4$$
  where $x_1 = \text{CVSS}/10$, $x_2 = \text{EPSS}$, $x_3 = \mathbb{I}_{\text{KEV}}$, $x_4 = \text{Asset Tier Weight} \in [0.25, 1.00]$.
- **Mode 2 Nonlinear Surface**:
  $$S_{\text{nonlinear}} = x_4 \cdot \left[ 1 - (1 - x_1)^{1 + 1.0 x_3} \cdot (1 - x_2)^{1 + 1.5 x_3} \right]$$
  with research-locked parameters $\alpha=1.0, \beta=1.5$.

### 3.4 SHAP Explanation Service (`backend/app/services/explanation_service.py`)
- Uses `shap.TreeExplainer` on the frozen XGBoost tree ensembles to calculate exact local feature attributions.
- Returns top-10 feature contributions and directional impact (`INCREASES_RISK` vs `DECREASES_RISK`).

---

## 4. Strict Research Boundaries

1. **Publication-Time Boundary**: EPSS scores are snapshot values (`2026-07-16`) and are **NEVER** fed into the EXP-B2 prediction path.
2. **Authoritative vs Predicted Distinction**: Estimated CVSS scores from EXP-A1 are clearly labeled as model predictions and distinguished from NVD analyst scores.
3. **Causal Disclaimer**: SHAP feature attributions describe tree decision boundaries, not physical causal mechanisms.
