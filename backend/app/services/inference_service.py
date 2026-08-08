"""
Inference Service Layer for Reconstructed Phase 3 Models
Repository: seucra/vulnarability-prioritization-triage-system
"""

import json
from typing import List, Tuple
import joblib
import numpy as np
import pandas as pd
from scipy.sparse import hstack, csr_matrix
import xgboost as xgb

from backend.app.config import settings
from backend.app.core.exceptions import ModelNotLoadedException
from backend.app.schemas.prediction import (
    CVSSPredictionRequest,
    CVSSPredictionResponse,
    KEVPredictionRequest,
    KEVPredictionResponse,
)


class InferenceService:
    def __init__(self):
        self.exp_a1_dir = settings.EXPERIMENTS_DIR / "exp_a1"
        self.exp_b2_dir = settings.EXPERIMENTS_DIR / "exp_b2"
        
        self.model_a1: xgb.XGBRegressor = None
        self.vec_a1 = None
        self.feats_a1: List[str] = []
        
        self.model_b2: xgb.XGBClassifier = None
        self.vec_b2 = None
        self.feats_b2: List[str] = []
        
        self._load_artifacts()

    def _load_artifacts(self):
        print("Loading reconstructed Phase 3 model artifacts into memory...")
        # Load A1
        if (self.exp_a1_dir / "model.xgb").exists():
            self.model_a1 = xgb.XGBRegressor()
            self.model_a1.load_model(str(self.exp_a1_dir / "model.xgb"))
            self.vec_a1 = joblib.load(str(self.exp_a1_dir / "vectorizer.joblib"))
            with open(self.exp_a1_dir / "feature_names.json", "r") as f:
                self.feats_a1 = json.load(f)
            print("EXP-A1 model & vectorizer loaded successfully.")

        # Load B2
        if (self.exp_b2_dir / "model.xgb").exists():
            self.model_b2 = xgb.XGBClassifier()
            self.model_b2.load_model(str(self.exp_b2_dir / "model.xgb"))
            self.vec_b2 = joblib.load(str(self.exp_b2_dir / "vectorizer.joblib"))
            with open(self.exp_b2_dir / "feature_names.json", "r") as f:
                self.feats_b2 = json.load(f)
            print("EXP-B2 model & vectorizer loaded successfully.")

    def _build_feature_vector(
        self,
        description_en: str,
        cwe_ids: List[str],
        cpe_count: int,
        cpe_part_a_count: int,
        cpe_part_o_count: int,
        cpe_part_h_count: int,
        vendor_count: int,
        product_count: int,
        pub_month: int,
        vectorizer
    ) -> csr_matrix:
        # TF-IDF 500 features
        X_text = vectorizer.transform([description_en])
        
        # Numeric features
        has_cwe = 1 if len(cwe_ids) > 0 else 0
        has_cpe = 1 if cpe_count > 0 else 0
        cwe_count = len(cwe_ids)
        semantic_cwe_count = len([c for c in cwe_ids if c.startswith("CWE-")])
        
        # Top 20 CWEs indicator vector matching Phase 3 order
        top_20_cwes = [
            "CWE-79", "CWE-89", "CWE-20", "CWE-200", "CWE-125", "CWE-787", "CWE-416",
            "CWE-352", "CWE-22", "CWE-476", "CWE-78", "CWE-190", "CWE-269", "CWE-862",
            "CWE-94", "CWE-434", "CWE-287", "CWE-798", "CWE-502", "CWE-306"
        ]
        cwe_top20_vec = [1 if c in cwe_ids else 0 for c in top_20_cwes]
        
        num_vec = [
            has_cwe,
            has_cpe,
            cwe_count,
            semantic_cwe_count,
            *cwe_top20_vec,
            cpe_count,
            cpe_part_a_count,
            cpe_part_h_count,
            cpe_part_o_count,
            vendor_count,
            product_count,
            pub_month
        ]
        
        X_num = csr_matrix(np.array(num_vec, dtype=np.float32).reshape(1, -1))
        return hstack([X_text, X_num]).tocsr()

    def predict_cvss(self, req: CVSSPredictionRequest, authoritative_score: float = None) -> CVSSPredictionResponse:
        if not self.model_a1:
            raise ModelNotLoadedException("EXP-A1 XGBoost Regressor")
            
        X_vec = self._build_feature_vector(
            req.description_en,
            req.cwe_ids,
            req.cpe_count,
            req.cpe_part_a_count,
            req.cpe_part_o_count,
            req.cpe_part_h_count,
            req.vendor_count,
            req.product_count,
            req.pub_month,
            self.vec_a1
        )
        
        pred_raw = float(self.model_a1.predict(X_vec)[0])
        pred_bounded = float(np.clip(pred_raw, 0.0, 10.0))
        
        return CVSSPredictionResponse(
            predicted_cvss_v31_base_score=round(pred_bounded, 2),
            authoritative_cvss_v31_base_score=authoritative_score,
            prediction_label="Predicted CVSS v3.1 Base Score",
            model_name="EXP-A1 XGBoost Regressor",
            mae_test_benchmark=0.9750,
        )

    def predict_kev(self, req: KEVPredictionRequest) -> KEVPredictionResponse:
        if not self.model_b2:
            raise ModelNotLoadedException("EXP-B2 XGBoost Classifier")
            
        X_vec = self._build_feature_vector(
            req.description_en,
            req.cwe_ids,
            req.cpe_count,
            req.cpe_part_a_count,
            req.cpe_part_o_count,
            req.cpe_part_h_count,
            req.vendor_count,
            req.product_count,
            req.pub_month,
            self.vec_b2
        )
        
        prob = float(self.model_b2.predict_proba(X_vec)[0, 1])
        
        # Risk classification thresholds established in Phase 3
        if prob >= 0.53738:
            risk_cat = "HIGH_RISK"
        elif prob >= 0.20:
            risk_cat = "ELEVATED_RISK"
        else:
            risk_cat = "LOW_RISK"
            
        return KEVPredictionResponse(
            predicted_kev_probability=round(prob, 5),
            risk_classification=risk_cat,
            prediction_point="CVE Publication / Initial Triage",
            model_name="EXP-B2 XGBoost Classifier",
            pr_auc_test_benchmark=0.02884,
            uplift_vs_random="8.96x precision multiplier over random baseline (0.00322)",
            target_definition="Probability of future CISA KEV catalog inclusion (proxy for exploitation)"
        )


inference_service = InferenceService()
