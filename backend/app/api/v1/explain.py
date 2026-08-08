"""
SHAP Feature Explanation API Endpoint
Repository: seucra/vulnarability-prioritization-triage-system
"""

from fastapi import APIRouter, Depends, status
from backend.app.api.deps import get_current_user
from backend.app.schemas.auth import UserResponse
from backend.app.schemas.prediction import (
    CVSSPredictionRequest,
    KEVPredictionRequest,
)
from backend.app.schemas.explanation import SHAPExplanationResponse
from backend.app.services.explanation_service import explanation_service

router = APIRouter(prefix="/explain", tags=["Model Explainability"])


@router.post(
    "/cvss",
    response_model=SHAPExplanationResponse,
    status_code=status.HTTP_200_OK,
    summary="Explain CVSS Base Score Prediction (SHAP)",
    description="Computes local SHAP feature attributions on the frozen EXP-A1 XGBoost Regressor for a vulnerability description. Requires authenticated session."
)
def explain_cvss_prediction(
    req: CVSSPredictionRequest,
    current_user: UserResponse = Depends(get_current_user)
):
    return explanation_service.explain_cvss_prediction(
        description_en=req.description_en,
        cwe_ids=req.cwe_ids,
        cpe_count=req.cpe_count,
        cpe_part_a_count=req.cpe_part_a_count,
        cpe_part_o_count=req.cpe_part_o_count,
        cpe_part_h_count=req.cpe_part_h_count,
        vendor_count=req.vendor_count,
        product_count=req.product_count,
        pub_month=req.pub_month
    )


@router.post(
    "/kev",
    response_model=SHAPExplanationResponse,
    status_code=status.HTTP_200_OK,
    summary="Explain Publication-Time KEV Risk Prediction (SHAP)",
    description="Computes local SHAP feature attributions on the frozen EXP-B2 XGBoost Classifier for a publication-time vulnerability description. Requires authenticated session."
)
def explain_kev_prediction(
    req: KEVPredictionRequest,
    current_user: UserResponse = Depends(get_current_user)
):
    return explanation_service.explain_kev_prediction(
        description_en=req.description_en,
        cwe_ids=req.cwe_ids,
        cpe_count=req.cpe_count,
        cpe_part_a_count=req.cpe_part_a_count,
        cpe_part_o_count=req.cpe_part_o_count,
        cpe_part_h_count=req.cpe_part_h_count,
        vendor_count=req.vendor_count,
        product_count=req.product_count,
        pub_month=req.pub_month
    )
