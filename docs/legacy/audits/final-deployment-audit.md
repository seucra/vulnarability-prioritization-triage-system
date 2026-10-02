# FINAL DEPLOYMENT & INFRASTRUCTURE AUDIT REPORT

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Audit Date**: August 23, 2026  
**Document Status**: Official Deployment Ground Truth  

---

## 1. Verified Intended Architecture & Deployment Topology

The application uses a hybrid decoupled deployment architecture:

```text
               [ Public Internet Users / Web Browsers ]
                                  │
         ┌────────────────────────┴────────────────────────┐
         ▼                                                 ▼
https://vuln-triage.seucra.tech                   https://vuln-triage-api.seucra.tech
(GitHub Pages Static SPA)                         (Cloudflare Tunnel Edge)
         │                                                 │
         │                                                 │ (Public HTTPS Proxy)
         │ (Client REST API Calls)                         ▼
         └──────────────────────────────────────► http://127.0.0.1:5002/api/v1
                                                   (FastAPI Uvicorn Backend)
```

---

## 2. Infrastructure & Configuration Findings

### Q1: What is actually configured in the repository?
- **Custom Domain (`frontend/CNAME`)**: Bound to `vuln-triage.seucra.tech`.
- **CI/CD Workflow (`.github/workflows/deploy_frontend.yml`)**:
  - Triggers on push or PR to branch `main`.
  - Runs validation test suite (`PYTHONPATH=. pytest tests/test_auth_rbac.py`).
  - Uploads `./frontend` artifact via `actions/upload-pages-artifact@v3`.
  - Deploys static site to GitHub Pages via `actions/deploy-pages@v4`.
- **Dynamic Frontend Environment Routing (`frontend/js/config.js`)**:
  - Resolves `API_BASE_URL` based on `window.location.hostname`.
  - If `localhost` or `127.0.0.1`: Uses `http://localhost:5002/api/v1`.
  - Otherwise (e.g. `vuln-triage.seucra.tech`): Uses `https://vuln-triage-api.seucra.tech/api/v1`.
- **Backend Port & Settings (`backend/app/config.py`)**:
  - Port `5002` default configuration.
  - Allowed CORS origins: `http://localhost:5002`, `http://127.0.0.1:5002`, `http://localhost:8000`, `http://127.0.0.1:8000`, `https://vuln-triage.seucra.tech`, `https://vuln-triage-api.seucra.tech`.
- **FastAPI Engine (`backend/app/main.py`)**:
  - `CORSMiddleware` configured with `allow_origins=settings.ALLOWED_ORIGINS` and `allow_credentials=True`.
  - HTTP middleware adding `no-cache` headers for non-API static routes.
  - Lightweight `/health` endpoint.
  - Fallback `StaticFiles` mounting serving `./frontend` for all-in-one local execution.
- **Deployment Documentation (`docs/DEPLOYMENT.md`)**:
  - Detailed guides for local development vs production demonstration startup.

### Q2: What is externally configured (cannot be verified from repository alone)?
1. **Cloudflare DNS Records**:
   - CNAME `vuln-triage.seucra.tech` -> `<username>.github.io`.
   - CNAME/A `vuln-triage-api.seucra.tech` -> Cloudflare Tunnel UUID.
2. **Cloudflare Tunnel (`cloudflared`) Daemon & Credentials**:
   - Local installation of `cloudflared` binary on backend host machine.
   - Active system service running `cloudflared tunnel run <tunnel-name>`.
   - Local configuration (`/root/.cloudflared/config.yml`) routing ingress hostname `vuln-triage-api.seucra.tech` to `http://localhost:5002`.
3. **GitHub Repository Pages Settings**:
   - Enabling GitHub Pages source as "GitHub Actions" in repository settings.

### Q3: What does GitHub Pages deploy?
- **ONLY the `./frontend` directory** (containing `index.html`, `CNAME`, `css/styles.css`, `js/config.js`, `js/state.js`, `js/api.js`, `js/app.js`, and `js/components/*.js`).

### Q4: What is excluded from the static frontend artifact?
- Python source code (`backend/app/*`), SQLite database (`data/auth_users.sqlite`), DuckDB Parquet datasets (`data/processed/*.parquet`), raw data feeds (`data/raw/*`), XGBoost model binaries (`data/experiments/phase3/*`), test suite (`tests/*`), scripts (`scripts/*`), and documentation (`docs/*`).

### Q5: How does GitHub Actions work?
- Workflow file `.github/workflows/deploy_frontend.yml`:
  1. `validate-and-test` job: Installs Python 3.10 and CI dependencies (`fastapi`, `pytest`, `pydantic`, `httpx`, `duckdb`, `xgboost`, `scikit-learn`, `shap`), runs `pytest tests/test_auth_rbac.py`.
  2. `deploy-pages` job: Runs if test job passes and commit is a push to `main`. Configures GitHub Pages, uploads `./frontend` directory artifact, and deploys to production site.

### Q6: How does the frontend choose local vs production API?
- Implemented in `frontend/js/config.js`:
  ```javascript
  const isLocalhost = window.location.hostname === 'localhost' || window.location.hostname === '127.0.0.1';
  export const CONFIG = {
      API_BASE_URL: isLocalhost 
          ? "http://localhost:5002/api/v1" 
          : "https://vuln-triage-api.seucra.tech/api/v1",
      PUBLIC_FRONTEND_DOMAIN: "https://vuln-triage.seucra.tech",
      PUBLIC_API_DOMAIN: "https://vuln-triage-api.seucra.tech",
  };
  ```

### Q7: CORS configuration
- Implemented in `backend/app/config.py` and `backend/app/main.py`:
  - `ALLOWED_ORIGINS` = `["http://localhost:5002", "http://127.0.0.1:5002", "http://localhost:8000", "http://127.0.0.1:8000", "https://vuln-triage.seucra.tech", "https://vuln-triage-api.seucra.tech"]`
  - Explicitly configured with `allow_credentials=True`, `allow_methods=["*"]`, `allow_headers=["*"]`.

### Q8: Backend startup command
- **Local Development**:
  ```bash
  PYTHONPATH=. uvicorn backend.app.main:app --host 127.0.0.1 --port 5002 --reload
  ```
- **Production Demonstration Host**:
  ```bash
  PYTHONPATH=. uvicorn backend.app.main:app --host 127.0.0.1 --port 5002 --workers 4
  ```

### Q9: Cloudflare Tunnel assumptions
- Assumes local `cloudflared` daemon process is actively running on the backend host machine.
- Assumes tunnel ingress routes incoming requests for `https://vuln-triage-api.seucra.tech` directly to `http://127.0.0.1:5002`.

### Q10: Health endpoint
- Route: `/health`
- Response: HTTP 200 OK
  ```json
  {
    "status": "healthy",
    "project": "WDL Vulnerability Prioritization Triage Backend",
    "repository": "seucra/vulnarability-prioritization-triage-system",
    "dataset_freeze_date": "2026-07-26",
    "epss_snapshot_date": "2026-07-16T12:03:48Z"
  }
  ```

### Q11: Required local services/processes on backend host
1. `uvicorn backend.app.main:app` (FastAPI backend listening on `127.0.0.1:5002`).
2. `cloudflared tunnel run <tunnel-name>` (Tunnel daemon forwarding public HTTPS traffic).

### Q12: Designation of public deployment
- Designated as **Research Prototype / Public Demonstration Deployment**. Explicitly documented in `docs/DEPLOYMENT.md` lines 12–13. Designed for academic evaluation, research demonstration, and triage workflow testing.

### Q13: Stale references to port 8000 or old URLs
- Port `8000` is retained in `ALLOWED_ORIGINS` in `backend/app/config.py` for backwards compatibility with legacy local dev setups, but port `5002` is the active default.
- Early Phase 4 architectural draft (`docs/architecture/PHASE_4_BACKEND_ARCHITECTURE.md`) referenced port `8000` before standardizing on port `5002`.

### Q14: Deployment documentation status
- `docs/DEPLOYMENT.md` is updated and reflects current GitHub Actions, port `5002`, and Cloudflare Tunnel setup.

---

## 3. Summary Sections

### A. CURRENT DEPLOYMENT TOPOLOGY
- **Frontend SPA**: `https://vuln-triage.seucra.tech` (GitHub Pages static hosting via `.github/workflows/deploy_frontend.yml`).
- **Backend API**: `https://vuln-triage-api.seucra.tech` (Cloudflare Tunnel ingress -> local Uvicorn process listening on `127.0.0.1:5002`).

### B. VERIFIED FROM REPOSITORY
- `frontend/CNAME` contains `vuln-triage.seucra.tech`.
- `.github/workflows/deploy_frontend.yml` automates testing and deployment of `./frontend` to GitHub Pages.
- `frontend/js/config.js` correctly selects `http://localhost:5002/api/v1` for local execution and `https://vuln-triage-api.seucra.tech/api/v1` for production.
- `backend/app/config.py` contains `https://vuln-triage.seucra.tech` in `ALLOWED_ORIGINS` with `allow_credentials=True`.
- `/health` endpoint is implemented and lightweight.

### C. REQUIRES MANUAL / LIVE VERIFICATION
- DNS CNAME mapping of `vuln-triage.seucra.tech` to GitHub Pages in Cloudflare dashboard.
- DNS A/CNAME mapping of `vuln-triage-api.seucra.tech` to Cloudflare Tunnel.
- Uvicorn and `cloudflared` daemon process execution status on the physical host machine.

### D. STALE DEPLOYMENT REFERENCES
- Early draft references to port `8000` in `PHASE_4_BACKEND_ARCHITECTURE.md` (active port is `5002`).
