"""
Configuration Module for Phase 4 Backend
Repository: seucra/vulnarability-prioritization-triage-system
"""

from pathlib import Path
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    PROJECT_NAME: str = "WDL Vulnerability Prioritization Triage Backend"
    REPOSITORY_NAME: str = "seucra/vulnarability-prioritization-triage-system"
    API_V1_PREFIX: str = "/api/v1"
    
    # Base paths
    REPO_ROOT: Path = Path(__file__).resolve().parent.parent.parent
    PROCESSED_DATA_DIR: Path = REPO_ROOT / "data" / "processed"
    EXPERIMENTS_DIR: Path = REPO_ROOT / "data" / "experiments" / "phase3"
    
    # Security & CORS settings
    SECRET_KEY: str = "demo-secret-key-change-in-production-via-env"
    ALLOWED_ORIGINS: list[str] = [
        "http://localhost:8000",
        "http://127.0.0.1:8000",
        "https://vuln-triage.seucra.tech",
        "https://vuln-triage-api.seucra.tech",
    ]
    
    # Research parameters
    DATASET_FREEZE_DATE: str = "2026-07-26"
    EPSS_SNAPSHOT_DATE: str = "2026-07-16T12:03:48Z"
    EPSS_MODEL_VERSION: str = "v2026.06.15"
    
    # Prioritization parameters
    C1_ALPHA_KEV_SEVERITY_MULT: float = 1.0
    C1_BETA_KEV_THREAT_MULT: float = 1.5

    class Config:
        case_sensitive = True


settings = Settings()
