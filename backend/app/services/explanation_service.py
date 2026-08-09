"""
Explanation Service Layer for SHAP Feature Attribution
Repository: seucra/vulnarability-prioritization-triage-system
"""

import json
from typing import Dict, List, Optional
import numpy as np

import shap
from backend.app.config import settings
from backend.app.core.exceptions import ModelNotLoadedException
from backend.app.schemas.explanation import (
    FeatureContribution,
    SHAPExplanationResponse,
)
from backend.app.services.inference_service import inference_service


class ExplanationService:
    def __init__(self):
        self.shap_summary_path = settings.EXPERIMENTS_DIR / "shap" / "shap_summary.json"
        self.global_shap_data: Dict = {}
        self._load_global_shap()
        
        self.explainer_a1: Optional[shap.TreeExplainer] = None
        self.explainer_b2: Optional[shap.TreeExplainer] = None

    def _load_global_shap(self):
        if self.shap_summary_path.exists():
            with open(self.shap_summary_path, "r") as f:
                self.global_shap_data = json.load(f)

    def _get_explainer_a1(self) -> shap.TreeExplainer:
        if self.explainer_a1 is None and inference_service.model_a1 is not None:
            self.explainer_a1 = shap.TreeExplainer(inference_service.model_a1)
        return self.explainer_a1

    def _get_explainer_b2(self) -> shap.TreeExplainer:
        if self.explainer_b2 is None and inference_service.model_b2 is not None:
            self.explainer_b2 = shap.TreeExplainer(inference_service.model_b2)
        return self.explainer_b2

    def explain_cvss_prediction(
        self,
        description_en: str,
        cwe_ids: List[str],
        cpe_count: int,
        cpe_part_a_count: int,
        cpe_part_o_count: int,
        cpe_part_h_count: int,
        vendor_count: int,
        product_count: int,
        pub_month: int
    ) -> SHAPExplanationResponse:
        if inference_service.model_a1 is None or inference_service.vec_a1 is None:
            raise ModelNotLoadedException("EXP-A1 XGBoost Regressor")

        explainer = self._get_explainer_a1()
        X_vec = inference_service._build_feature_vector(
            description_en, cwe_ids, cpe_count, cpe_part_a_count,
            cpe_part_o_count, cpe_part_h_count, vendor_count, product_count,
            pub_month, inference_service.vec_a1
        )
        
        X_arr = X_vec.toarray()
        shap_vals = explainer.shap_values(X_arr)[0]
        base_val = float(explainer.expected_value)
        pred_val = float(np.clip(base_val + shap_vals.sum(), 0.0, 10.0))
        
        feature_names = inference_service.feats_a1
        top_idx = np.argsort(np.abs(shap_vals))[::-1][:10]
        
        contributions = []
        for idx in top_idx:
            sv = float(shap_vals[idx])
            val_str = str(round(float(X_arr[0, idx]), 3))
            fname = feature_names[idx] if idx < len(feature_names) else f"feature_{idx}"
            contributions.append(
                FeatureContribution(
                    feature_name=fname,
                    shap_value=round(sv, 4),
                    abs_shap_value=round(abs(sv), 4),
                    feature_value=val_str,
                    directional_impact="INCREASES_RISK/SCORE" if sv > 0 else "DECREASES_RISK/SCORE"
                )
            )
            
        global_top = self.global_shap_data.get("exp_a1_top_shap_importance", {})
        
        return SHAPExplanationResponse(
            target_model="EXP-A1 XGBoost Regressor (CVSS Estimation)",
            base_value=round(base_val, 4),
            predicted_value=round(pred_val, 4),
            top_feature_contributions=contributions,
            global_top_features=global_top,
        )

    def explain_kev_prediction(
        self,
        description_en: str,
        cwe_ids: List[str],
        cpe_count: int,
        cpe_part_a_count: int,
        cpe_part_o_count: int,
        cpe_part_h_count: int,
        vendor_count: int,
        product_count: int,
        pub_month: int
    ) -> SHAPExplanationResponse:
        if inference_service.model_b2 is None or inference_service.vec_b2 is None:
            raise ModelNotLoadedException("EXP-B2 XGBoost Classifier")

        explainer = self._get_explainer_b2()
        X_vec = inference_service._build_feature_vector(
            description_en, cwe_ids, cpe_count, cpe_part_a_count,
            cpe_part_o_count, cpe_part_h_count, vendor_count, product_count,
            pub_month, inference_service.vec_b2
        )
        
        X_arr = X_vec.toarray()
        shap_vals = explainer.shap_values(X_arr)[0]
        base_val = float(explainer.expected_value)
        prob = float(inference_service.model_b2.predict_proba(X_vec)[0, 1])
        
        feature_names = inference_service.feats_b2
        top_idx = np.argsort(np.abs(shap_vals))[::-1][:10]
        
        contributions = []
        for idx in top_idx:
            sv = float(shap_vals[idx])
            val_str = str(round(float(X_arr[0, idx]), 3))
            fname = feature_names[idx] if idx < len(feature_names) else f"feature_{idx}"
            contributions.append(
                FeatureContribution(
                    feature_name=fname,
                    shap_value=round(sv, 4),
                    abs_shap_value=round(abs(sv), 4),
                    feature_value=val_str,
                    directional_impact="INCREASES_KEV_PROBABILITY" if sv > 0 else "DECREASES_KEV_PROBABILITY"
                )
            )
            
        global_top = self.global_shap_data.get("exp_b2_top_shap_importance", {})
        
        return SHAPExplanationResponse(
            target_model="EXP-B2 XGBoost Classifier (Publication-Time KEV Prediction)",
            base_value=round(base_val, 4),
            predicted_value=round(prob, 5),
            top_feature_contributions=contributions,
            global_top_features=global_top,
        )


explanation_service = ExplanationService()
