# Archived Historical Records & Legacy Documentation

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Status**: Archived / Superseded Snapshots  

> [!CAUTION]
> The documents in this directory (`docs/legacy/`) are preserved strictly for historical provenance, audit trails, and chronological record-keeping. They represent point-in-time drafts and intermediate states.
> 
> **Do NOT cite files in this directory for authoritative system requirements, architecture, or research metrics.**
> 
> For active, authoritative single-source-of-truth documentation, refer to:
> - Product Requirements: [`docs/prd/PRD.md`](../prd/PRD.md)
> - UI/UX & Design System: [`docs/design/DESIGN.md`](../design/DESIGN.md)
> - System Architecture & Deployment: [`docs/architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md)
> - REST API Reference: [`docs/architecture/API.md`](../architecture/API.md)
> - Institutional Memory & Viva Preparation: [`docs/memory/MEMORY.md`](../memory/MEMORY.md)
> - System Rules, Invariants & Non-Claims: [`docs/rules/RULES.md`](../rules/RULES.md)
> - Experimental Protocol & Empirical Results: [`docs/research/EXPERIMENTAL_PROTOCOL_AND_RESULTS.md`](../research/EXPERIMENTAL_PROTOCOL_AND_RESULTS.md)
> - IEEE Research Evidence Audit: [`docs/research/EVIDENCE_AUDIT.md`](../research/EVIDENCE_AUDIT.md)
> - Research Data Manifest: [`docs/research/DATA_MANIFEST.md`](../research/DATA_MANIFEST.md)

---

## Directory Organization

### 1. `audits/`
Intermediate and pre-consolidation audit reports:
- `audit_session_log.md`: Raw session notes from early repository audits.
- `functionality-audit.md`: Early Phase 4 web application functionality gap audit.
- `final-application-audit.md`: Application functionality verification checklist.
- `final-artifact-inventory.md`: Complete repository file and artifact inventory.
- `final-deployment-audit.md`: Cloudflare Tunnel and GitHub Pages deployment audit.
- `final-repository-consistency-audit.md`: Cross-file reference consistency audit.
- `final-repo-state.md`: Intermediate repository snapshot and metric ledger.
- `final-research-fact-sheet.md`: Pre-consolidation ground truth metric reference.

### 2. `phases/`
Granular Phase 0 through Phase 3 research logs:
- `phase0-task-checklist.md`: Initial task list for Phase 0.
- `PHASE_0_DATA_AUDIT.md`: Raw NVD and EPSS ingestion audit.
- `PHASE_1_ETL_REPORT.md`: Initial DuckDB/Parquet ETL report.
- `PHASE_2_DATA_PROFILE.md`: Explanatory statistical profiling of engineered features.
- `PHASE_2_EXPERIMENTAL_PROTOCOL.md`: Protocol design draft for EXP-A1, B1, B2.
- `PHASE_3_EXPERIMENT_REPORT.md`: Experiment execution log for machine learning benchmarks.
- `PHASE_3_RESULTS.md`: Preliminary tabular results.
- `PROCESSED_DATA_MANIFEST.md` & `PROCESSED_DATA_SCHEMA.md`: Initial schema drafts.
- `FIGURE_NUMERICAL_DATA.md`: Intermediate figure plotting coordinates.

### 3. `architecture/`
Component-level architecture notes merged into [`docs/architecture/ARCHITECTURE.md`](../architecture/ARCHITECTURE.md):
- `AUTHENTICATION_AND_RBAC.md`: PBKDF2 and JWT authentication design.
- `PHASE_4_BACKEND_ARCHITECTURE.md`: DuckDB connection lifecycle and FastAPI service design.
- `ROLE_DASHBOARDS_AND_WORKFLOWS.md`: Frontend persona routing and view switching.
- `DEPLOYMENT.md`: Infrastructure topology and startup guide.
- `SKILL-frontend-design.md`: Material Design 3 and Tonalspot aesthetic guidelines.

### 4. `drafts/`
Superseded narrative drafts, working notes, and early synthesis iterations:
- Working files from `toRead/` (`vuln3.md`, `vuln4.md`, `Future-Scope.md`, etc.).
- Intermediate synthesis drafts from `perplexity/` (`perplexity_final_draft.md`, `perplexity_phase_draft.md`, `perplexity_project_final_draft.md`).

### 5. `literature/`
Background reference papers and external search dossiers:
- `WJARR-2026-1006.md` / `WJARR-2026-1006.pdf`: Reference baseline paper.
- `search_results.md`: External threat intelligence literature query outputs.
