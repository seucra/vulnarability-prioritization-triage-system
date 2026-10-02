# FINAL REPOSITORY-WIDE CONSISTENCY AUDIT REPORT

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Audit Date**: August 23, 2026  
**Document Status**: Official Repository Consistency & Hygiene Audit  

---

## 1. Audit Scope & Methodology

This audit scanned the entire codebase and documentation corpus for potential inconsistencies, outdated URLs, stale port references, legacy repository names, historical metrics, and outdated functional claims.

---

## 2. Inconsistency & Reference Analysis Table

| File | Stale / Questionable Reference | Current Codebase & Runtime Reality | Severity | Recommended Action | Reference Categorization |
|---|---|---|---|---|---|
| [README.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/README.md#L72) | `pip install -r requirements.txt` (Line 72) | `requirements.txt` does not exist in the repository; dependencies are installed directly into the virtual environment. | Low | Update quickstart command to `pip install fastapi uvicorn duckdb xgboost scikit-learn shap pyarrow pytest pydantic pydantic-settings httpx`. | **Genuinely Stale** |
| [docs/functionality-audit.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/functionality-audit.md) | Table lists Register, Login, RBAC, Landing, Export, Deployment as `MISSING` / `PARTIAL`. Mentions `login.html`/`register.html`. | All features are 100% `IMPLEMENTED` in WDL-4 to WDL-6. Legacy detached HTML files were removed in WDL-5 cleanup. | Medium | Add a header banner indicating this document is a historical audit snapshot from early Phase 4, superseded by `docs/final-application-audit.md`. | **Historical Information (Preserved Snapshot)** |
| [scripts/*.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/scripts/) & [docs/research/*.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/) | Header comments: `Repository: wdl-vuln-prioritization` | Official repository name in `config.py`, `README.md`, and GitHub is `seucra/vulnarability-prioritization-triage-system`. | Low | Keep as historical record or update docstring header comments during future maintenance. | **Historical Information (Initial Working Name)** |
| [backend/app/config.py](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/backend/app/config.py#L25) & [docs/DEPLOYMENT.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/DEPLOYMENT.md#L48) | `"http://localhost:8000"` in `ALLOWED_ORIGINS` | Active backend default port is `5002`. Port `8000` is retained in CORS as a local development fallback. | Low | Retain in `ALLOWED_ORIGINS` as a permissive local dev origin fallback. | **Local Development Example** |
| [docs/research/PHASE_0_DATA_AUDIT.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/research/PHASE_0_DATA_AUDIT.md#L53) | Directory structure tree: `wdl-vuln-prioritization/` | Local workspace directory is `vulnarability-prioritization-triage-system/`. | Low | None required. Preserved Phase 0 setup documentation. | **Historical Information (Preserved Snapshot)** |
| [.github/workflows/deploy_frontend.yml](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/.github/workflows/deploy_frontend.yml) | (History) Early run failed due to `cache: 'pip'` | Removed `cache: 'pip'` parameter in commit `60b56db`. | None (Resolved) | Workflow is fully up-to-date and passing. | **Correct Documentation** |
| [docs/DEPLOYMENT.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/DEPLOYMENT.md) | Deployment guide referencing `http://localhost:5002` and `https://vuln-triage-api.seucra.tech` | Matches production topology and port `5002` FastAPI backend setup. | None | Fully accurate. | **Correct Documentation** |

---

## 3. Reference Categorization Breakdown

1. **Genuinely Stale Information**:
   - `README.md` quickstart line 72 referencing `pip install -r requirements.txt`.
2. **Historical Information (Intentionally Preserved)**:
   - `docs/functionality-audit.md` (Captures intermediate WDL audit state).
   - Early research docs and script headers referencing working name `wdl-vuln-prioritization`.
3. **Local Development Examples (Intentionally Preserved)**:
   - `http://localhost:8000` in CORS `ALLOWED_ORIGINS` (`backend/app/config.py`).
4. **Correct Documentation**:
   - `docs/DEPLOYMENT.md`, `docs/final-research-fact-sheet.md`, `docs/final-application-audit.md`, `docs/final-deployment-audit.md`, `.github/workflows/deploy_frontend.yml`.

---

## 4. Priority List of Files Requiring Documentation Updates

1. **[README.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/README.md#L72)** (High Priority for Quickstart accuracy):
   - Replace line 72 `pip install -r requirements.txt` with explicit package installation command:  
     `pip install fastapi uvicorn duckdb xgboost scikit-learn shap pyarrow pytest pydantic pydantic-settings httpx`
2. **[docs/functionality-audit.md](file:///home/seucra/Runes/projects/research/vulnarability-prioritization-triage-system/docs/functionality-audit.md)** (Medium Priority for Clarity):
   - Prepend a banner header marking this file as an intermediate Phase 4 audit snapshot superseded by `docs/final-application-audit.md`.
3. **Script Header Comments** (`scripts/**/*.py`) (Low Priority / Cosmetic):
   - Update `Repository: wdl-vuln-prioritization` headers to `Repository: seucra/vulnarability-prioritization-triage-system`.
