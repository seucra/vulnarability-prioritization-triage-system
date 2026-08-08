"""
Research Provenance & System Metadata API Endpoint
Repository: seucra/vulnarability-prioritization-triage-system
"""

from fastapi import APIRouter, status
from backend.app.schemas.provenance import ResearchProvenanceResponse
from backend.app.services.provenance_service import provenance_service

router = APIRouter(prefix="/provenance", tags=["Research Provenance"])


@router.get(
    "",
    response_model=ResearchProvenanceResponse,
    status_code=status.HTTP_200_OK,
    summary="Get System & Research Provenance Metadata",
    description="Returns dataset freeze manifest, record counts, temporal partition boundaries, Phase 3 experiment metrics, EPSS snapshot date, and research limitations."
)
def get_provenance():
    return provenance_service.get_provenance()
