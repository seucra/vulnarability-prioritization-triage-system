"""
Model Inference API Endpoints (EXP-A1 CVSS Base Score & EXP-B2 Publication-Time KEV Risk)
Repository: seucra/vulnarability-prioritization-triage-system
"""

from typing import Optional
from fastapi import APIRouter, Depends, Query, status
from backend.app.api.deps import get_current_user
from backend.app.core.database import db_engine
from backend.app.schemas.auth import UserResponse
from backend.app.schemas.prediction import (
    CVSSPredictionRequest,
    CVSSPredictionResponse,
    KEVPredictionRequest,
    KEVPredictionResponse,
)
from backend.app.services.inference_service import inference_service

router = APIRouter(prefix="/predict", tags=["Model Predictions"])


@router.post(
    "/cvss",
    response_model=CVSSPredictionResponse,
    status_code=status.HTTP_200_OK,
    summary="Estimate Pre-Scoring CVSS v3.1 Base Score (EXP-A1)",
    description="Estimates the CVSS v3.1 base score from initial text description and metadata using the frozen EXP-A1 XGBoost Regressor. Requires authenticated session."
)
def predict_cvss(
    req: CVSSPredictionRequest,
    cve_id: Optional[str] = Query(None, description="Optional CVE ID to include authoritative NVD score for comparison"),
    current_user: UserResponse = Depends(get_current_user)
):
    authoritative_score = None
    if cve_id:
        vuln = db_engine.get_vulnerability_by_id(cve_id)
        if vuln and vuln.get("cvss_v31_base_score") is not None:
            authoritative_score = float(vuln["cvss_v31_base_score"])
            
    return inference_service.predict_cvss(req, authoritative_score=authoritative_score)


@router.post(
    "/kev",
    response_model=KEVPredictionResponse,
    status_code=status.HTTP_200_OK,
    summary="Predict Publication-Time KEV Catalog Inclusion (EXP-B2)",
    description="Predicts the probability of future CISA KEV catalog inclusion at CVE publication time using the frozen EXP-B2 XGBoost Classifier. EPSS snapshot scores and CVSS vector components are strictly excluded and rejected. Requires authenticated session."
)
def predict_kev(
    req: KEVPredictionRequest,
    current_user: UserResponse = Depends(get_current_user)
):
    return inference_service.predict_kev(req)
