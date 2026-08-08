"""
Custom API Exception Handlers
Repository: seucra/vulnarability-prioritization-triage-system
"""

from fastapi import HTTPException, status


class VulnerabilityNotFoundException(HTTPException):
    def __init__(self, cve_id: str):
        super().__init__(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Vulnerability '{cve_id}' not found in canonical dataset.",
        )


class InvalidFeatureBoundaryException(HTTPException):
    def __init__(self, detail: str):
        super().__init__(
            status_code=status.HTTP_422_UNPROCESSABLE_ENTITY,
            detail=detail,
        )


class ModelNotLoadedException(HTTPException):
    def __init__(self, model_name: str):
        super().__init__(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Research model artifact '{model_name}' is not loaded or missing.",
        )
