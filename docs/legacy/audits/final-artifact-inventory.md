# FINAL RESEARCH & DOCUMENTATION CORPUS ARTIFACT INVENTORY

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Audit Date**: August 23, 2026  
**Document Status**: Official Research Corpus & Artifact Inventory  

---

## 1. Classified Artifact Inventory

Every major file and artifact in the repository is inventoried below across 15 research categories:

### 1. Dataset / Provenance Artifacts
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `data/raw/*` (32 files) | Raw compressed NVD, CPE, EPSS, KEV, and Vendor feeds (~1.05 GB uncompressed). | Source ground truth feeds for ETL data pipeline. | Hashed in Manifest | Downloaded | **YES (Provenance)** |
| `data/processed/vulnerabilities.parquet` | 366,547 normalized CVE records (2002–2026). | Primary canonical vulnerability dataset. | **YES** | Reconstructed | **YES** |
| `data/processed/cve_cwe.parquet` | 430,273 CWE weakness mapping records. | Normalized 1-to-many weakness taxonomy mappings. | **YES** | Reconstructed | **YES** |
| `data/processed/cve_cpe.parquet` | 3,133,450 CPE applicability node records. | Platform applicability and vendor/product mappings. | **YES** | Reconstructed | **YES** |
| `data/processed/epss.parquet` | 348,900 EPSS snapshot records (`2026-07-16T12:03:48Z`). | FIRST EPSS score snapshot (Model `v2026.06.15`). | **YES** | Reconstructed | **YES** |
| `data/processed/kev.parquet` | 1,647 CISA Known Exploited catalog records. | Authoritative real-world exploitation labels. | **YES** | Reconstructed | **YES** |
| `data/processed/vendor_statements.parquet` | 1,486 vendor response statement records. | Official vendor response advisories. | **YES** | Reconstructed | **YES** |
| `docs/research/DATA_MANIFEST.md` | SHA-256 cryptographic hashes for 32 raw archives. | Ensures raw feed integrity and auditability. | **YES** | Hand-verified | **YES** |
| `docs/research/PROCESSED_DATA_MANIFEST.md` | Binary & logical SHA-256 hashes for Parquet tables. | Ensures 100% deterministic ETL reproducibility. | **YES** | Hand-verified | **YES** |

### 2. ETL / Data-Processing Artifacts
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `src/ingestion/schemas.py` | PyArrow schema definitions for 6 target Parquet tables. | Enforces strict column data typing and nullability. | **YES** | NO | **YES** |
| `src/ingestion/nvd.py`, `cpe.py`, `epss.py`, `kev.py`, `vendor.py` | Python stream decompression and parsing modules. | Loss-minimizing ETL pipeline logic. | **YES** | NO | **YES** |
| `scripts/build_processed_data.py` | Master ETL build and audit orchestration script. | Rebuilds canonical Parquet datasets from raw feeds. | **YES** | NO | **YES** |
| `scripts/compare_rebuilds.py` | Direct DataFrame comparison tool across builds. | Validates row-by-row identity across environment builds. | **YES** | NO | **YES** |
| `scripts/fingerprint_processed_data.py` | 64-character SHA-256 hashing utility. | Computes binary and logical hashes for data verification. | **YES** | NO | **YES** |

### 3. Experiment Artifacts
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `scripts/experiments/run_exp_a1.py` | EXP-A1 CVSS regression experiment runner script. | Pre-scoring CVSS v3.1 estimation experiment. | **YES** | NO | **YES** |
| `scripts/experiments/run_exp_b2.py` | EXP-B2 publication-time KEV classifier script. | Primary publication-time threat prediction experiment. | **YES** | NO | **YES** |
| `scripts/experiments/run_exp_b1.py` | EXP-B1 retrospective EPSS sensitivity script. | Retrospective EPSS snapshot leakage audit experiment. | **YES** | NO | **YES** |
| `scripts/experiments/run_exp_c1.py` | EXP-C1 multi-criteria simulation runner script. | Prioritization surface simulation across asset tiers. | **YES** | NO | **YES** |
| `scripts/experiments/run_shap_analysis.py` | SHAP TreeExplainer calculation script. | Post-hoc model interpretability feature attributions. | **YES** | NO | **YES** |
| `scripts/experiments/serialize_phase3_models.py` | Phase 3 model reconstruction & validation script. | Reconstructs and validates frozen model binaries. | **YES** | NO | **YES** |

### 4. Model Artifacts
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `data/experiments/phase3/exp_a1/model.xgb` | Serialized XGBoost Regressor model binary. | Predicts CVSS v3.1 base score from text/metadata. | **YES** | Reconstructed | **YES** |
| `data/experiments/phase3/exp_b2/model.xgb` | Serialized XGBoost Classifier model binary. | Predicts CISA KEV listing at publication time. | **YES** | Reconstructed | **YES** |

### 5. Feature / Vectorizer Artifacts
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `data/experiments/phase3/exp_a1/vectorizer.joblib` | Scikit-Learn TF-IDF vectorizer (500 features). | Text feature extraction for CVSS estimation. | **YES** | Reconstructed | **YES** |
| `data/experiments/phase3/exp_a1/feature_names.json` | Complete 531 feature list manifest for EXP-A1. | Maps feature indices to human-readable names. | **YES** | Reconstructed | **YES** |
| `data/experiments/phase3/exp_b2/vectorizer.joblib` | Scikit-Learn TF-IDF vectorizer (500 features). | Text feature extraction for KEV prediction. | **YES** | Reconstructed | **YES** |
| `data/experiments/phase3/exp_b2/feature_names.json` | Complete 531 feature list manifest for EXP-B2. | Maps feature indices to human-readable names. | **YES** | Reconstructed | **YES** |

### 6. Metrics / Results Artifacts
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `data/experiments/phase3/exp_a1/metrics.json` | EXP-A1 evaluation metrics (MAE, RMSE, $R^2$, best params). | Quantitative proof for CVSS pre-scoring estimation. | **YES** | Reconstructed | **YES** |
| `data/experiments/phase3/exp_b2/metrics.json` | EXP-B2 metrics (PR-AUC, ROC-AUC, Precision@500, Recall@500). | Quantitative proof for publication-time KEV prediction. | **YES** | Reconstructed | **YES** |
| `data/experiments/phase3/exp_b1/metrics.json` | EXP-B1 retrospective EPSS snapshot leakage metrics. | Quantifies 11.49x retrospective leakage inflation. | **YES** | Reconstructed | **YES** |
| `data/experiments/phase3/exp_c1/metrics.json` | EXP-C1 simulation metrics (Spearman $\rho$, Jaccard overlap). | Demonstrates tail queue disruption in linear vs non-linear. | **YES** | Reconstructed | **YES** |
| `data/experiments/phase3/shap/shap_summary.json` | Top SHAP feature attributions for EXP-A1 and EXP-B2. | Explains feature importance rankings for paper tables. | **YES** | Reconstructed | **YES** |
| `data/experiments/phase3/exp_a1/test_predictions.parquet` | Test set prediction outputs for EXP-A1. | Record-level test predictions for validation. | **YES** | Reconstructed | **YES** |
| `data/experiments/phase3/exp_b2/test_predictions.parquet` | Test set prediction outputs for EXP-B2. | Record-level test predictions for validation. | **YES** | Reconstructed | **YES** |
| `data/experiments/phase3/exp_c1/simulation_rankings.parquet` | Prioritization rankings across 4 asset tiers. | Record-level prioritization score comparisons. | **YES** | Reconstructed | **YES** |

### 7. Research Figures
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `docs/research/figures/phase2/` (5 files) | Plots: CVSS distributions, temporal availability, EPSS percentiles, KEV delay, KEV class balance. | Visual figures for Phase 2 dataset characterization. | **YES** | Reconstructed | **YES** |
| `docs/research/figures/phase3/` (4 files) | Plots: EXP-A1 predictions, EXP-B2 PR/ROC curves, EXP-C1 priority distributions, SHAP summary. | High-resolution publication figures for paper draft. | **YES** | Reconstructed | **YES** |

### 8. Research Documentation
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `docs/research/PHASE_0_DATA_AUDIT.md` | Phase 0 data audit report. | Feasibility and raw feed audit documentation. | **YES** | NO | **YES** |
| `docs/research/PROCESSED_DATA_SCHEMA.md` | Parquet schema specifications. | Formal data dictionary for processed tables. | **YES** | NO | **YES** |
| `docs/research/PHASE_1_ETL_REPORT.md` | Phase 1 ETL execution report. | ETL architecture and transformation documentation. | **YES** | NO | **YES** |
| `docs/research/PHASE_2_DATA_PROFILE.md` | Empirical dataset characterization report. | Comprehensive descriptive statistics of datasets. | **YES** | NO | **YES** |
| `docs/research/PHASE_2_EXPERIMENTAL_PROTOCOL.md` | Research protocol formulation document. | Theoretical framework, splits, and metrics. | **YES** | NO | **YES** |
| `docs/research/PHASE_3_EXPERIMENT_REPORT.md` | Full Phase 3 experiment report. | Detailed experimental findings and discussion. | **YES** | NO | **YES** |
| `docs/research/PHASE_3_RESULTS.md` | Paper-ready quantitative results summary. | Concise metrics and abstract draft integration text. | **YES** | NO | **YES** |
| `docs/final-research-fact-sheet.md` | Official research ground truth fact sheet. | Single-source-of-truth numbers, formulas, and splits. | **YES** | NO | **YES** |

### 9. Backend Implementation
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `backend/app/main.py` | FastAPI application entrypoint, CORS, static server. | REST API server implementation. | **YES** | NO | **YES** |
| `backend/app/config.py` | Application settings and CORS allowed origins. | Configuration layer. | **YES** | NO | **YES** |
| `backend/app/api/router.py` | APIRouter assembly module. | API route module routing. | **YES** | NO | **YES** |
| `backend/app/api/v1/*.py` (6 files) | Auth, vulnerabilities, predict, prioritize, explain, provenance endpoints. | Endpoint request handlers. | **YES** | NO | **YES** |
| `backend/app/core/database.py` | DuckDB Parquet query manager. | Fast SQL query execution over Parquet datasets. | **YES** | NO | **YES** |
| `backend/app/services/*.py` (6 files) | Auth, vulnerability, inference, scoring, explanation, provenance services. | Core business logic layer. | **YES** | NO | **YES** |

### 10. Frontend Implementation
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `frontend/index.html` | SPA DOM shell container. | Web application entrypoint HTML. | **YES** | NO | **YES** |
| `frontend/css/styles.css` | Design system CSS with tokens, print styles, and media queries. | Visual styling and responsive rules. | **YES** | NO | **YES** |
| `frontend/js/config.js` | Environment-aware API target resolution. | Dynamic API URL routing (`localhost` vs `seucra.tech`). | **YES** | NO | **YES** |
| `frontend/js/state.js` | Reactive AppState manager with localStorage hydration. | Centralized state management. | **YES** | NO | **YES** |
| `frontend/js/api.js` | REST ApiClient layer with Bearer token injection. | API network request layer. | **YES** | NO | **YES** |
| `frontend/js/app.js` | SPA router, hashchange listener, client route guards. | Client navigation and authorization guards. | **YES** | NO | **YES** |
| `frontend/js/components/*.js` (19 files) | View controllers and role dashboards (`analyst`, `researcher`, `admin`). | User interface component views. | **YES** | NO | **YES** |

### 11. Authentication / RBAC
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `backend/app/core/security.py` | PBKDF2 password hashing & HMAC-SHA256 JWT tokens. | Password security and token generation. | **YES** | NO | **YES** |
| `backend/app/core/auth_db.py` | SQLite user database manager. | Persistence for user accounts and roles. | **YES** | NO | **YES** |
| `backend/app/api/deps.py` | `get_current_user` and `require_role(...)` dependencies. | Server-side role-based authorization enforcement. | **YES** | NO | **YES** |
| `data/auth_users.sqlite` | SQLite database storing pre-seeded admin user and registered accounts. | Auth user data store. | **YES** | Reconstructed | **YES** |

### 12. Tests
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `tests/test_auth_rbac.py` | 16 Pytest tests for Auth and RBAC API. | Automated verification of security and RBAC. | **YES** | NO | **YES** |
| `tests/test_backend_api.py` | 8 Pytest tests for core REST API endpoints. | Automated verification of REST endpoints. | **YES** | NO | **YES** |
| `tests/test_etl_invariants.py` | 15 Pytest tests for ETL dataset invariants. | Automated verification of data invariants. | **YES** | NO | **YES** |

### 13. Deployment / CI
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `.github/workflows/deploy_frontend.yml` | GitHub Actions CI test & Pages deploy workflow. | CI/CD automation pipeline. | **YES** | NO | **YES** |
| `frontend/CNAME` | Custom domain mapping (`vuln-triage.seucra.tech`). | GitHub Pages DNS binding. | **YES** | NO | **YES** |
| `docs/DEPLOYMENT.md` | Deployment architecture and setup guide. | Infrastructure setup documentation. | **YES** | NO | **YES** |
| `docs/final-deployment-audit.md` | Deployment topology audit document. | Final deployment topology verification. | **YES** | NO | **YES** |

### 14. Architecture Diagrams
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `usecase_diagram.png` | Visual system use-case diagram. | System architecture visualization. | **YES** | NO | **YES** |
| `usecase_diagram_short.png` | Concise system use-case diagram. | System overview visualization. | **YES** | NO | **YES** |
| `docs/architecture/PHASE_4_BACKEND_ARCHITECTURE.md` | Backend architecture document. | System backend design specs. | **YES** | NO | **YES** |
| `docs/architecture/AUTHENTICATION_AND_RBAC.md` | Auth architecture document. | Security design specs. | **YES** | NO | **YES** |
| `docs/architecture/ROLE_DASHBOARDS_AND_WORKFLOWS.md` | Role dashboards architecture. | Frontend role UX specs. | **YES** | NO | **YES** |

### 15. User / Project Documentation
| Artifact Path | Description & Contents | Research Purpose / Significance | Committed? | Reconstructed? | In Research Corpus? |
|---|---|---|---|---|---|
| `README.md` | Root repository documentation and quickstart guide. | Project landing README. | **YES** | NO | **YES** |
| `SKILL-frontend-design.md` | Frontend visual design guidelines. | UI aesthetic design system rules. | **YES** | NO | **YES** |
| `toRead/WJARR-2026-1006.pdf` & `.md` | Reference paper text (Agyei et al., 2026). | Theoretical baseline reference paper. | **YES** | NO | **YES** |
| `toRead/Deep-Understanding-Document.md` | In-depth technical synthesis notes. | Academic background synthesis. | **YES** | NO | **YES** |
| `toRead/Formal-Presentation-Viva-Preparation.md` | Viva presentation defense guide. | Academic viva defense notes. | **YES** | NO | **YES** |
| `toRead/Consolidated-Project-History-Research-Decisions-Architecture.md` | Complete project history document. | Comprehensive chronological history. | **YES** | NO | **YES** |
| `docs/final-application-audit.md` | Web application audit document. | Application requirement verification. | **YES** | NO | **YES** |
| `docs/final-repository-consistency-audit.md` | Repository consistency audit document. | Repository hygiene verification. | **YES** | NO | **YES** |

---

## 2. Missing Artifact Analysis

1. **`requirements.txt` / `pyproject.toml` Manifest File**:
   - *Status*: Missing from repository root.
   - *Impact*: CI workflow installs dependencies directly. Quickstart instructions in `README.md` reference `requirements.txt`.
   - *Recommendation*: Create a clean `requirements.txt` listing exact package versions (`fastapi==0.115.0`, `uvicorn==0.30.0`, `duckdb==1.2.1`, `xgboost==3.4.0`, `scikit-learn==1.9.0`, `shap==0.52.0`, `pyarrow==19.0.1`, `pytest==9.1.1`, `pydantic-settings==2.13.0`).
2. **Historical Daily EPSS Trajectories**:
   - *Status*: Intentionally missing due to public archive unavailability (only static snapshot `2026-07-16` available).
   - *Impact*: Evaluated via retrospective snapshot leakage comparison (EXP-B1 vs EXP-B2).

---

## 3. SOURCE MATERIAL CHECKLIST FOR RESEARCH-PAPER STAGE

The following source material assets MUST be preserved and exported prior to beginning the academic paper manuscript write-up:

- [x] **1. Research Ground Truth Document**: `docs/final-research-fact-sheet.md` (Contains exact MAE, PR-AUC, splits, formulas, and SHAP features).
- [x] **2. High-Resolution Phase 3 Figures**: `docs/research/figures/phase3/` (`exp_a1_predictions.png`, `exp_b2_pr_roc_curves.png`, `exp_c1_priority_distributions.png`, `shap_summary_b2.png`).
- [x] **3. Quantitative Results Metrics**: `data/experiments/phase3/exp_a1/metrics.json`, `exp_b2/metrics.json`, `exp_b1/metrics.json`, `exp_c1/metrics.json`, `shap/shap_summary.json`.
- [x] **4. Reference Paper Document**: `toRead/WJARR-2026-1006.pdf` (DOI: 10.30574/wjarr.2026.30.1.1006).
- [x] **5. Canonical Dataset Fingerprints**: `docs/research/PROCESSED_DATA_MANIFEST.md` and `docs/research/DATA_MANIFEST.md`.
- [x] **6. Reproducibility Scripts**: `scripts/experiments/run_exp_a1.py`, `run_exp_b2.py`, `run_exp_b1.py`, `run_exp_c1.py`, `run_shap_analysis.py`, `serialize_phase3_models.py`.
- [x] **7. Automated Verification Suite**: `tests/test_auth_rbac.py`, `test_backend_api.py`, `test_etl_invariants.py` (39 passing tests).
