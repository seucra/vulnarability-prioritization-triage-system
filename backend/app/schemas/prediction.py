"""
Prediction Request & Response Schemas
Repository: seucra/vulnarability-prioritization-triage-system
"""

from typing import List, Optional
from pydantic import BaseModel, Field, root_validator, model_validator


class CVSSPredictionRequest(BaseModel):
    description_en: str = Field(..., min_length=10, description="Vulnerability natural language description")
    cwe_ids: List[str] = Field(default_factory=list, description="List of associated CWE identifiers (e.g., ['CWE-79'])")
    cpe_count: int = Field(0, ge=0, description="Total CPE configurations")
    cpe_part_a_count: int = Field(0, ge=0, description="Applications CPE count")
    cpe_part_o_count: int = Field(0, ge=0, description="Operating Systems CPE count")
    cpe_part_h_count: int = Field(0, ge=0, description="Hardware CPE count")
    vendor_count: int = Field(0, ge=0, description="Distinct vendor count")
    product_count: int = Field(0, ge=0, description="Distinct product count")
    pub_month: int = Field(1, ge=1, le=12, description="Publication month (1-12)")


class CVSSPredictionResponse(BaseModel):
    predicted_cvss_v31_base_score: float = Field(..., description="Estimated CVSS v3.1 base score [0.0, 10.0]")
    authoritative_cvss_v31_base_score: Optional[float] = Field(None, description="Authoritative NVD CVSS score if CVE ID is specified")
    prediction_label: str = Field("Predicted CVSS v3.1 Base Score", description="Explicit non-authoritative label")
    model_name: str = Field("EXP-A1 XGBoost Regressor", description="Model architecture")
    mae_test_benchmark: float = Field(0.9750, description="Phase 3 Test MAE benchmark")
    disclaimer: str = Field(
        "Estimated pre-scoring value derived strictly from initial description text and metadata. Not an official NVD/CNA analyst score.",
        description="Methodological disclaimer"
    )


class KEVPredictionRequest(BaseModel):
    description_en: str = Field(..., min_length=10, description="Vulnerability description available at publication")
    cwe_ids: List[str] = Field(default_factory=list, description="Publication-time CWE weakenesses")
    cpe_count: int = Field(0, ge=0)
    cpe_part_a_count: int = Field(0, ge=0)
    cpe_part_o_count: int = Field(0, ge=0)
    cpe_part_h_count: int = Field(0, ge=0)
    vendor_count: int = Field(0, ge=0)
    product_count: int = Field(0, ge=0)
    pub_month: int = Field(1, ge=1, le=12)
    
    # Prohibited post-publication features (EPSS & CVSS components)
    epss: Optional[float] = Field(None, description="PROHIBITED FEATURE: EPSS scores are excluded from publication-time prediction")
    epss_score: Optional[float] = Field(None, description="PROHIBITED FEATURE")
    epss_percentile: Optional[float] = Field(None, description="PROHIBITED FEATURE")
    cvss_v31_base_score: Optional[float] = Field(None, description="PROHIBITED FEATURE: CVSS base score is post-publication")
    cvss_vector: Optional[str] = Field(None, description="PROHIBITED FEATURE")

    @model_validator(mode="after")
    def validate_publication_time_boundary(self):
        prohibited = []
        if self.epss is not None:
            prohibited.append("epss")
        if self.epss_score is not None:
            prohibited.append("epss_score")
        if self.epss_percentile is not None:
            prohibited.append("epss_percentile")
        if self.cvss_v31_base_score is not None:
            prohibited.append("cvss_v31_base_score")
        if self.cvss_vector is not None:
            prohibited.append("cvss_vector")
            
        if prohibited:
            raise ValueError(
                f"Strict Publication-Time Feature Boundary Violation! The following post-publication fields are excluded from EXP-B2 prediction: {prohibited}. "
                "EPSS snapshot scores and CVSS vector components are prohibited at publication-time prediction."
            )
        return self


class KEVPredictionResponse(BaseModel):
    predicted_kev_probability: float = Field(..., description="Estimated probability of future CISA KEV catalog inclusion [0.0, 1.0]")
    risk_classification: str = Field(..., description="Risk category: HIGH_RISK (>=0.537), ELEVATED_RISK (>=0.20), LOW_RISK (<0.20)")
    prediction_point: str = Field("CVE Publication / Initial Triage", description="Strict temporal prediction point")
    model_name: str = Field("EXP-B2 XGBoost Classifier", description="Model architecture")
    pr_auc_test_benchmark: float = Field(0.02884, description="Phase 3 Test PR-AUC benchmark")
    uplift_vs_random: str = Field("8.96x precision multiplier over random baseline (0.00322)", description="Relative baseline uplift")
    target_definition: str = Field("Probability of future CISA KEV membership (proxy for exploitation)", description="Target interpretation")
