# Deployment Guide — Research Prototype / Public Demonstration Deployment

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Deployment Type**: `Research Prototype / Public Demonstration Deployment`

---

## 1. Overview

This document outlines the deployment procedure for hosting the **Vulnerability Prioritization & Triage System** as a public demonstration prototype.

> [!IMPORTANT]
> This application is designated as a **Research Prototype / Public Demonstration Deployment**. It is designed for academic evaluation, research demonstration, and triage workflow testing. It is not presented as an enterprise production cybersecurity service.

---

## 2. Intended Infrastructure Architecture

The deployment topology uses Uvicorn behind a Cloudflare Tunnel for secure HTTPS termination and edge DNS routing:

```text
               [ Public Internet Users ]
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
https://vuln-triage.seucra.tech   https://vuln-triage-api.seucra.tech
 (Frontend Single-Page App)          (FastAPI Uvicorn Backend)
         │                                 │
         └────────────────┬────────────────┘
                          ▼
              [ Cloudflare Tunnel Edge ]
                          │
                 (cloudflared daemon)
                          │
         ┌────────────────┴────────────────┐
         ▼                                 ▼
http://localhost:8000 (Static SPA)  http://localhost:8000/api/v1 (REST API)
```

---

## 3. Environment Variables Configuration

Create a `.env` file in the project root directory (refer to `.env.example`):

```bash
# Secret Key for HMAC-SHA256 Token Signing
SECRET_KEY="your-secure-random-hmac-secret-key-here"

# Allowed CORS Origins
ALLOWED_ORIGINS=["https://vuln-triage.seucra.tech","https://vuln-triage-api.seucra.tech","http://localhost:8000"]
```

---

## 4. Local Development vs Public Demonstration Startup

### A. Local Development Startup

1. **Activate Virtual Environment**:
   ```bash
   source .venv/bin/activate
   ```

2. **Start Backend & SPA Server**:
   ```bash
   PYTHONPATH=. uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --reload
   ```

3. **Access Local Application**:
   - Frontend: `http://localhost:8000/#home`
   - API Health Check: `http://localhost:8000/health`
   - OpenAPI Swagger Specs: `http://localhost:8000/api/v1/docs`

---

### B. Public Demonstration Deployment Procedure

1. **Service Configuration (`systemd` or Supervisor)**:
   Run Uvicorn in production mode:
   ```bash
   PYTHONPATH=. uvicorn backend.app.main:app --host 127.0.0.1 --port 8000 --workers 4
   ```

2. **Cloudflare Tunnel (`cloudflared`) Setup Concept**:
   Create a Cloudflare ingress configuration (`~/.cloudflared/config.yml`):
   ```yaml
   tunnel: your-tunnel-uuid
   credentials-file: /root/.cloudflared/your-tunnel-uuid.json

   ingress:
     - hostname: vuln-triage.seucra.tech
       service: http://localhost:8000
     - hostname: vuln-triage-api.seucra.tech
       service: http://localhost:8000
     - service: http_status:404
   ```

3. **DNS Route Association**:
   ```bash
   cloudflared tunnel route dns your-tunnel-name vuln-triage.seucra.tech
   cloudflared tunnel route dns your-tunnel-name vuln-triage-api.seucra.tech
   ```

---

## 5. Health Check & Operational Readiness Verification

Verify application readiness using the lightweight health endpoint:

```bash
curl -s http://localhost:8000/health
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
