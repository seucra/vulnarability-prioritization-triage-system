"""
Prioritization Request & Response Schemas
Repository: seucra/vulnarability-prioritization-triage-system
"""

from enum import Enum
from typing import Dict, Optional
from pydantic import BaseModel, Field


class AssetCriticalityTier(str, Enum):
    TIER_1_LOW = "Tier 1 (Low Criticality: 0.25)"
    TIER_2_MEDIUM = "Tier 2 (Medium Criticality: 0.50)"
    TIER_3_HIGH = "Tier 3 (High Criticality: 0.75)"
    TIER_4_CRITICAL = "Tier 4 (Critical Infrastructure: 1.00)"


class PrioritizationRequest(BaseModel):
    cve_id: Optional[str] = Field(None, description="Optional CVE ID to populate vulnerability parameters")
    cvss_score: float = Field(..., ge=0.0, le=10.0, description="CVSS base score [0.0, 10.0]")
    epss_score: float = Field(..., ge=0.0, le=1.0, description="EPSS score [0.0, 1.0]")
    is_kev: bool = Field(..., description="Whether vulnerability is listed in CISA KEV")
    asset_criticality: float = Field(0.75, ge=0.0, le=1.0, description="Asset criticality weight [0.25, 0.50, 0.75, 1.00]")


class PrioritizationScoreDetail(BaseModel):
    priority_score: float = Field(..., description="Calculated priority score [0.0, 1.0]")
    scoring_mode: str = Field(..., description="MODE 1 Linear Baseline or MODE 2 Nonlinear Surface")
    asset_criticality_tier: str
    asset_criticality_x4: float
    inputs: Dict[str, float]


class PrioritizationResponse(BaseModel):
    cve_id: Optional[str] = None
    linear_baseline_mode_1: PrioritizationScoreDetail
    nonlinear_surface_mode_2: PrioritizationScoreDetail
    methodology_note: str = Field(
        "Mode 1 uses project-controlled equal weights (0.25 CVSS, 0.25 EPSS, 0.25 KEV, 0.25 Asset). "
        "Mode 2 uses non-additive interactive surface scaling (alpha=1.0, beta=1.5).",
        description="Methodological summary"
    )
