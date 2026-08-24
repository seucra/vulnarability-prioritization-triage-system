"""
Prioritization Scoring API Endpoint (Linear Baseline vs Nonlinear Decision Surface)
Repository: seucra/vulnarability-prioritization-triage-system
"""

from fastapi import APIRouter, Depends, status
from backend.app.api.deps import require_roles
from backend.app.schemas.auth import UserResponse
from backend.app.schemas.batch_prioritization import (
    BatchPrioritizationRequest,
    BatchPrioritizationResponse,
)
from backend.app.schemas.prioritization import (
    PrioritizationRequest,
    PrioritizationResponse,
)
from backend.app.services.scoring_service import scoring_service

router = APIRouter(prefix="/prioritize", tags=["Prioritization"])


@router.post(
    "",
    response_model=PrioritizationResponse,
    status_code=status.HTTP_200_OK,
    summary="Compute Multi-Criteria Prioritization Scores",
    description="Computes prioritization scores under Mode 1 (Linear Equal-Weights Baseline: S_linear) and Mode 2 (Nonlinear Interactive Risk Surface: S_nonlinear) across controlled Asset Criticality Tiers (0.25, 0.50, 0.75, 1.00). Restricted to Security Analyst and Administrator roles."
)
def prioritize_vulnerability(
    req: PrioritizationRequest,
    current_user: UserResponse = Depends(require_roles(["analyst", "admin"]))
):
    return scoring_service.prioritize(req)


@router.post(
    "/batch",
    response_model=BatchPrioritizationResponse,
    status_code=status.HTTP_200_OK,
    summary="Execute Batch Vulnerability Triage Queue Scoring",
    description="Processes a batch list of CVE IDs (Max 100 items), auto-populating system vulnerability metadata (CVSS v3.1, EPSS probability, CISA KEV listing), and returns a deterministically ranked vulnerability triage queue with Mode 1 vs Mode 2 scores, score shift indicators, and item-level error status. Restricted to Security Analyst and Administrator roles."
)
def prioritize_vulnerability_batch(
    req: BatchPrioritizationRequest,
    current_user: UserResponse = Depends(require_roles(["analyst", "admin"]))
):
    return scoring_service.prioritize_batch(req)

