"""
Prioritization Scoring Service (Linear Baseline vs Nonlinear Decision Surface)
Repository: seucra/vulnarability-prioritization-triage-system
"""

import numpy as np
from backend.app.config import settings
from backend.app.schemas.prioritization import (
    PrioritizationRequest,
    PrioritizationResponse,
    PrioritizationScoreDetail,
)


class ScoringService:
    @staticmethod
    def calculate_linear_score(x1: float, x2: float, x3: float, x4: float) -> float:
        """
        MODE 1 — Transparent Linear Baseline
        S_linear = 0.25*x1 + 0.25*x2 + 0.25*x3 + 0.25*x4
        Explicitly defined as: Project-controlled equal weights baseline.
        """
        w1, w2, w3, w4 = 0.25, 0.25, 0.25, 0.25
        return float(np.clip(w1 * x1 + w2 * x2 + w3 * x3 + w4 * x4, 0.0, 1.0))

    @staticmethod
    def calculate_nonlinear_score(x1: float, x2: float, x3: float, x4: float) -> float:
        """
        MODE 2 — Nonlinear Interactive Decision Surface
        S_nonlinear = x4 * [ 1 - (1 - x1)^(1 + alpha*x3) * (1 - x2)^(1 + beta*x3) ]
        with alpha = 1.0, beta = 1.5
        """
        alpha = settings.C1_ALPHA_KEV_SEVERITY_MULT # 1.0
        beta = settings.C1_BETA_KEV_THREAT_MULT    # 1.5
        
        x1_c = float(np.clip(x1, 0.0, 1.0))
        x2_c = float(np.clip(x2, 0.0, 1.0))
        x3_c = float(np.clip(x3, 0.0, 1.0))
        x4_c = float(np.clip(x4, 0.0, 1.0))
        
        sev_factor = (1.0 - x1_c) ** (1.0 + alpha * x3_c)
        threat_factor = (1.0 - x2_c) ** (1.0 + beta * x3_c)
        
        risk_core = 1.0 - (sev_factor * threat_factor)
        return float(np.clip(x4_c * risk_core, 0.0, 1.0))

    @classmethod
    def prioritize(cls, req: PrioritizationRequest) -> PrioritizationResponse:
        x1 = req.cvss_score / 10.0 # Normalized CVSS [0, 1]
        x2 = req.epss_score        # EPSS [0, 1]
        x3 = 1.0 if req.is_kev else 0.0 # KEV binary flag
        x4 = req.asset_criticality # Asset Criticality Tier weight [0.25 - 1.0]
        
        s_lin = cls.calculate_linear_score(x1, x2, x3, x4)
        s_nonlin = cls.calculate_nonlinear_score(x1, x2, x3, x4)
        
        # Categorize tier label
        if x4 <= 0.30:
            tier_name = "Tier 1 (Low Criticality: 0.25)"
        elif x4 <= 0.60:
            tier_name = "Tier 2 (Medium Criticality: 0.50)"
        elif x4 <= 0.85:
            tier_name = "Tier 3 (High Criticality: 0.75)"
        else:
            tier_name = "Tier 4 (Critical Infrastructure: 1.00)"
            
        inputs_dict = {
            "normalized_cvss_x1": round(x1, 4),
            "epss_probability_x2": round(x2, 4),
            "is_kev_x3": x3,
            "asset_criticality_x4": x4
        }
        
        detail_lin = PrioritizationScoreDetail(
            priority_score=round(s_lin, 4),
            scoring_mode="MODE 1 — Transparent Linear Baseline (Project-Controlled Equal Weights)",
            asset_criticality_tier=tier_name,
            asset_criticality_x4=x4,
            inputs=inputs_dict
        )
        
        detail_nonlin = PrioritizationScoreDetail(
            priority_score=round(s_nonlin, 4),
            scoring_mode="MODE 2 — Nonlinear Interactive Decision Surface (alpha=1.0, beta=1.5)",
            asset_criticality_tier=tier_name,
            asset_criticality_x4=x4,
            inputs=inputs_dict
        )
        
        return PrioritizationResponse(
            cve_id=req.cve_id,
            linear_baseline_mode_1=detail_lin,
            nonlinear_surface_mode_2=detail_nonlin,
        )


scoring_service = ScoringService()
