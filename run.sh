#!/usr/bin/env bash
# ==============================================================================
# Vulnerability Prioritization & Triage System - Unified Run Script
# Repository: seucra/vulnarability-prioritization-triage-system
# ==============================================================================

set -eo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# Defaults
HOST="${HOST:-127.0.0.1}"
PORT="${PORT:-5002}"
RELOAD=false
WORKERS=1

# Parse arguments
while [[ $# -gt 0 ]]; do
  case "$1" in
    -h|--host)
      HOST="$2"
      shift 2
      ;;
    -p|--port)
      PORT="$2"
      shift 2
      ;;
    -r|--reload)
      RELOAD=true
      shift
      ;;
    -w|--workers)
      WORKERS="$2"
      shift 2
      ;;
    --help)
      echo "Usage: ./run.sh [options]"
      echo ""
      echo "Options:"
      echo "  -p, --port <port>       Port to listen on (default: 5002)"
      echo "  -h, --host <host>       Host to bind to (default: 127.0.0.1)"
      echo "  -r, --reload            Enable auto-reload on file changes"
      echo "  -w, --workers <n>       Number of worker processes (default: 1)"
      echo "  --help                  Display this help message"
      exit 0
      ;;
    *)
      echo "Unknown option: $1"
      echo "Run with --help for usage details."
      exit 1
      ;;
  esac
done

echo "========================================================================"
echo " Starting Vulnerability Prioritization & Triage System"
echo "========================================================================"

# 1. Ensure Python 3 is available
if ! command -v python3 &> /dev/null; then
  echo "Error: python3 is not installed or not found in PATH." >&2
  exit 1
fi

# 2. Set up / activate virtual environment
if [ ! -d ".venv" ]; then
  echo "[+] Creating Python virtual environment in .venv..."
  python3 -m venv .venv
fi

# Activate virtual environment
if [ -f ".venv/bin/activate" ]; then
  # shellcheck source=/dev/null
  source .venv/bin/activate
else
  echo "Error: Virtual environment activation script (.venv/bin/activate) not found." >&2
  exit 1
fi

# 3. Check / install dependencies
if ! python3 -c "import fastapi, uvicorn, duckdb, xgboost, shap" &> /dev/null; then
  echo "[+] Installing missing Python dependencies from requirements.txt..."
  pip install -r requirements.txt
fi

# 4. Ensure .env exists
if [ ! -f ".env" ] && [ -f ".env.example" ]; then
  echo "[+] Initializing .env from .env.example..."
  cp .env.example .env
fi

# 5. Build Uvicorn command
UVICORN_ARGS=("--host" "$HOST" "--port" "$PORT")

if [ "$RELOAD" = true ]; then
  UVICORN_ARGS+=("--reload")
elif [ "$WORKERS" -gt 1 ]; then
  UVICORN_ARGS+=("--workers" "$WORKERS")
fi

echo ""
echo "========================================================================"
echo " [OK] System is ready. Starting server on http://${HOST}:${PORT}"
echo "------------------------------------------------------------------------"
echo "  * Web Application (SPA) : http://${HOST}:${PORT}/#home"
echo "  * System Health Status  : http://${HOST}:${PORT}/health"
echo "  * REST API Documentation: http://${HOST}:${PORT}/api/v1/docs"
echo "------------------------------------------------------------------------"
echo "  Default Demo Admin Account:"
echo "    Email    : admin@vuln-triage.sec"
echo "    Password : AdminDemoPassword123!"
echo "========================================================================"
echo ""

export PYTHONPATH="$SCRIPT_DIR"

exec uvicorn backend.app.main:app "${UVICORN_ARGS[@]}"
