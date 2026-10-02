# Deployment Guide — Research Prototype / Public Demonstration Deployment

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Deployment Type**: `Research Prototype / Public Demonstration Deployment`

---

## 1. Overview & Verified Architecture

This document outlines the deployment procedure for hosting the **Vulnerability Prioritization & Triage System** as a public demonstration prototype.

> [!IMPORTANT]
> This application is designated as a **Research Prototype / Public Demonstration Deployment**. It is designed for academic evaluation, research demonstration, and triage workflow testing. It is not presented as an enterprise production cybersecurity service.

---

## 2. Infrastructure Architecture & Production Topology

The system uses a decoupled hosting model:

- **Static Frontend**: Hosted on **GitHub Pages** (`https://vuln-triage.seucra.tech`) via GitHub Actions CI/CD workflow (`.github/workflows/deploy_frontend.yml`) publishing the `frontend/` directory with `CNAME` binding.
- **Backend REST API**: Hosted locally on `localhost:5002` and exposed publicly through a **Cloudflare Tunnel** (`https://vuln-triage-api.seucra.tech`).

```text
               [ Public Internet Users ]
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
https://vuln-triage.seucra.tech   https://vuln-triage-api.seucra.tech
   (GitHub Pages SPA)                (Cloudflare Tunnel Edge)
         │                                 │
         │ (REST API Fetch)                ▼
         └────────────────────────► http://localhost:5002/api/v1
                                    (FastAPI Uvicorn Backend)
```

---

## 3. Environment Variables Configuration

Create a `.env` file in the project root directory (refer to `.env.example`):

```bash
# Secret Key for HMAC-SHA256 Token Signing
SECRET_KEY="your-secure-random-hmac-secret-key-here"

# Allowed CORS Origins
ALLOWED_ORIGINS=["https://vuln-triage.seucra.tech","https://vuln-triage-api.seucra.tech","http://localhost:5002","http://localhost:8000"]
```

---

## 4. Local Development vs Production Demonstration Startup

### A. Local Development Startup

1. **Activate Virtual Environment**:
   ```bash
   source .venv/bin/activate
   ```

2. **Start Backend API Server (Port 5002)**:
   ```bash
   PYTHONPATH=. uvicorn backend.app.main:app --host 127.0.0.1 --port 5002 --reload
   ```

3. **Access Local Application**:
   - Web Application: `http://localhost:5002/#home`
   - System Health: `http://localhost:5002/health`
   - OpenAPI Swagger Specs: `http://localhost:5002/api/v1/docs`

---

### B. Production Demonstration Backend Startup (Port 5002)

1. **Uvicorn Service Startup**:
   Run Uvicorn locally on port 5002:
   ```bash
   PYTHONPATH=. uvicorn backend.app.main:app --host 127.0.0.1 --port 5002 --workers 4
   ```

2. **Cloudflare Tunnel (`cloudflared`) Configuration**:
   The Cloudflare Tunnel routes public HTTPS traffic to the local listener on port 5002:
   ```yaml
   tunnel: your-tunnel-uuid
   credentials-file: /root/.cloudflared/your-tunnel-uuid.json

   ingress:
     - hostname: vuln-triage-api.seucra.tech
       service: http://localhost:5002
     - service: http_status:404
   ```

3. **Frontend Deployment**:
   Pushes to `main` automatically trigger `.github/workflows/deploy_frontend.yml`, deploying `frontend/` to GitHub Pages under `https://vuln-triage.seucra.tech`.

---

## 5. Health Check & Operational Readiness Verification

Verify application readiness using the lightweight health endpoint:

```bash
curl -s http://localhost:5002/health
```

Expected Response:
```json
{
  "status": "healthy",
  "project": "WDL Vulnerability Prioritization Triage Backend",
  "repository": "seucra/vulnarability-prioritization-triage-system",
  "dataset_freeze_date": "2026-07-26",
  "epss_snapshot_date": "2026-07-16T12:03:48Z"
}
```

The health endpoint provides instant availability confirmation without triggering heavy DuckDB SQL queries or XGBoost model inferences.
