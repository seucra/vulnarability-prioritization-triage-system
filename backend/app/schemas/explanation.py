"""
SHAP Explanation Schemas
Repository: seucra/vulnarability-prioritization-triage-system
"""

from typing import Dict, List, Optional
from pydantic import BaseModel, Field


class FeatureContribution(BaseModel):
    feature_name: str
    shap_value: float = Field(..., description="SHAP attribution value (contribution to log-odds or score)")
    abs_shap_value: float = Field(..., description="Absolute SHAP contribution magnitude")
    feature_value: Optional[str] = None
    directional_impact: str = Field(..., description="INCREASES_RISK or DECREASES_RISK")


class SHAPExplanationResponse(BaseModel):
    target_model: str = Field(..., description="EXP-A1 Regressor or EXP-B2 Classifier")
    base_value: float = Field(..., description="Explainer expected base value")
    predicted_value: float = Field(..., description="Final model prediction")
    top_feature_contributions: List[FeatureContribution]
    global_top_features: Dict[str, float] = Field(..., description="Phase 3 global SHAP mean absolute importances")
    causal_disclaimer: str = Field(
        "SHAP explains internal tree ensemble feature contributions and model decision boundaries. It does NOT establish physical causal mechanisms.",
        description="Causal disclaimer"
    )
