"""
Batch Prioritization Request & Response Schemas
Repository: seucra/vulnarability-prioritization-triage-system
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field, field_validator


class BatchItemInput(BaseModel):
    cve_id: Optional[str] = Field(None, description="Primary lookup key: CVE Identifier (e.g. CVE-2021-44228)")
    asset_criticality: Optional[float] = Field(None, ge=0.0, le=1.0, description="Item-specific asset criticality weight [0.25, 0.50, 0.75, 1.00]")
    
    # Optional Analyst Overrides (Clearly demarcated as analyst-supplied, not authoritative system metadata)
    cvss_score: Optional[float] = Field(None, ge=0.0, le=10.0, description="Analyst-supplied CVSS score override [0.0, 10.0]")
    epss_score: Optional[float] = Field(None, ge=0.0, le=1.0, description="Analyst-supplied EPSS score override [0.0, 1.0]")
    is_kev: Optional[bool] = Field(None, description="Analyst-supplied KEV status override")
    custom_label: Optional[str] = Field(None, max_length=100, description="Analyst tracking label or asset context identifier")

    @field_validator("cve_id")
    @classmethod
    def clean_cve_id(cls, v: Optional[str]) -> Optional[str]:
        if v is not None:
            v_clean = v.strip().upper()
            return v_clean if v_clean else None
        return None


class BatchPrioritizationRequest(BaseModel):
    items: List[BatchItemInput] = Field(..., description="List of batch items to prioritize (Max 100 items)")
    default_asset_criticality: float = Field(0.75, ge=0.0, le=1.0, description="Default asset criticality tier weight if item asset_criticality is missing")
    primary_sort: str = Field("mode_2", description="Primary sorting score: 'mode_2' (Nonlinear Surface) or 'mode_1' (Linear Baseline)")
    sort_dir: str = Field("desc", description="Sort direction: 'desc' or 'asc'")

    @field_validator("items")
    @classmethod
    def validate_batch_size(cls, v: List[BatchItemInput]) -> List[BatchItemInput]:
        if not v:
            raise ValueError("Batch prioritization request must contain at least 1 item.")
        if len(v) > 100:
            raise ValueError("Batch request exceeds maximum allowed limit of 100 items per request.")
        return v


class BatchItemResult(BaseModel):
    rank: int = Field(1, ge=1, description="Deterministic queue priority rank (1-indexed)")
    cve_id: Optional[str] = None

    custom_label: Optional[str] = None
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    is_kev: Optional[bool] = None
    asset_criticality: float
    asset_criticality_tier: str
    linear_score: Optional[float] = None
    nonlinear_score: Optional[float] = None
    score_shift: Optional[float] = None
    status: str = Field("success", description="Item status: 'success', 'not_found', or 'validation_error'")
    error_message: Optional[str] = None
    is_analyst_override: bool = Field(False, description="True if parameters use analyst-supplied overrides instead of system metadata")


class BatchSummaryKPI(BaseModel):
    total_requested: int
    total_processed: int
    total_errors: int
    high_priority_count: int = Field(..., description="Count of items with Mode 2 priority score >= 0.70")
    kev_count: int = Field(..., description="Count of KEV-listed items in batch")
    avg_mode_2_score: float
    max_score_shift: float


class BatchPrioritizationResponse(BaseModel):
    total_requested: int
    total_processed: int
    total_errors: int
    primary_sort: str
    sort_dir: str
    summary: BatchSummaryKPI
    items: List[BatchItemResult]
