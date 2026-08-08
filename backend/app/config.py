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
