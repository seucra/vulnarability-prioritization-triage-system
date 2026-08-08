"""
Phase 4 Model Reconstruction and Validation Script
Repository: seucra/vulnarability-prioritization-triage-system

Performs deterministic reconstruction of the final frozen Phase 3 models:
- EXP-A1 (XGBoost Regressor for CVSS v3.1 Base Score Estimation)
- EXP-B2 (XGBoost Classifier for Publication-Time KEV Prediction)

Reuses the exact feature construction code and hyperparameters from Phase 3.
Validates reconstructed model predictions against Phase 3 recorded outputs.

Serializes artifacts:
- data/experiments/phase3/exp_a1/model.xgb
- data/experiments/phase3/exp_a1/vectorizer.joblib
- data/experiments/phase3/exp_a1/feature_names.json
- data/experiments/phase3/exp_b2/model.xgb
- data/experiments/phase3/exp_b2/vectorizer.joblib
- data/experiments/phase3/exp_b2/feature_names.json
"""

import json
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq

# Import exact feature builders and data loaders from Phase 3 scripts
from scripts.experiments.run_exp_a1 import load_data as load_a1_data, build_features as build_a1_features
from scripts.experiments.run_exp_b2 import load_data as load_b2_data, build_features as build_b2_features
import xgboost as xgb

RANDOM_SEED = 42
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EXP_A1_DIR = REPO_ROOT / "data" / "experiments" / "phase3" / "exp_a1"
EXP_B2_DIR = REPO_ROOT / "data" / "experiments" / "phase3" / "exp_b2"


def reconstruct_and_validate_a1():
    print("--- 1. Reconstructing EXP-A1 Model ---")
    df, cwe, cpe = load_a1_data()
    X_all, y_all, years_all, feature_names = build_a1_features(df, cwe, cpe)
    
    # Load Phase 3 metrics metadata
    with open(EXP_A1_DIR / "metrics.json", "r") as f:
        a1_meta = json.load(f)
    best_params = a1_meta["nonlinear_xgboost"]["best_hyperparameters"]
    print(f"EXP-A1 Hyperparameters: {best_params}")
    
    train_val_idx = np.where(years_all <= 2024)[0]
    test_idx = np.where(years_all >= 2025)[0]
    
    # Fit exact XGBoost Regressor on Train + Validation
    model_a1 = xgb.XGBRegressor(
        max_depth=best_params["max_depth"],
        n_estimators=best_params["n_estimators"],
        learning_rate=best_params["learning_rate"],
        random_state=RANDOM_SEED,
        n_jobs=-1,
        tree_method="hist",
    )
    model_a1.fit(X_all[train_val_idx], y_all[train_val_idx])
    
    # Predict on Test partition
    test_preds = model_a1.predict(X_all[test_idx])
    
    # Compare with Phase 3 test predictions
    recorded_test_df = pq.read_table(str(EXP_A1_DIR / "test_predictions.parquet")).to_pandas()
    recorded_preds = recorded_test_df["xgboost_pred"].values
    
    max_diff = float(np.max(np.abs(test_preds - recorded_preds)))
    mean_diff = float(np.mean(np.abs(test_preds - recorded_preds)))
    print(f"EXP-A1 Validation Check: Max diff vs Phase 3 recorded: {max_diff:.8f}, Mean diff: {mean_diff:.8f}")
    assert max_diff < 1e-4, f"EXP-A1 reconstruction failed validation! Max difference: {max_diff}"
    print("EXP-A1 Reconstruction SUCCESSFULLY VALIDATED!")
    
    # Re-extract vectorizer for inference
    from sklearn.feature_extraction.text import TfidfVectorizer
    tfidf = TfidfVectorizer(max_features=500, stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
    tfidf.fit(df["description_en"].fillna(""))
    
    # Serialize artifacts
    model_a1.save_model(str(EXP_A1_DIR / "model.xgb"))
    joblib.dump(tfidf, str(EXP_A1_DIR / "vectorizer.joblib"))
    with open(EXP_A1_DIR / "feature_names.json", "w") as f:
        json.dump(feature_names, f, indent=2)
    print(f"EXP-A1 artifacts serialized to {EXP_A1_DIR}")


def reconstruct_and_validate_b2():
    print("\n--- 2. Reconstructing EXP-B2 Model ---")
    df, cwe, cpe = load_b2_data()
    X_all, y_all, years_all, feature_names = build_b2_features(df, cwe, cpe)
    
    with open(EXP_B2_DIR / "metrics.json", "r") as f:
        b2_meta = json.load(f)
    best_params = b2_meta["nonlinear_xgboost"]["best_hyperparameters"]
    print(f"EXP-B2 Hyperparameters: {best_params}")
    
    train_val_idx = np.where(years_all <= 2024)[0]
    test_idx = np.where(years_all >= 2025)[0]
    
    model_b2 = xgb.XGBClassifier(
        scale_pos_weight=best_params["scale_pos_weight"],
        max_depth=best_params["max_depth"],
        n_estimators=best_params["n_estimators"],
        learning_rate=best_params["learning_rate"],
        random_state=RANDOM_SEED,
        n_jobs=-1,
        tree_method="hist",
        eval_metric="logloss",
    )
    model_b2.fit(X_all[train_val_idx], y_all[train_val_idx])
    
    test_probs = model_b2.predict_proba(X_all[test_idx])[:, 1]
    
    recorded_test_df = pq.read_table(str(EXP_B2_DIR / "test_predictions.parquet")).to_pandas()
    recorded_probs = recorded_test_df["xgboost_prob"].values
    
    max_diff = float(np.max(np.abs(test_probs - recorded_probs)))
    mean_diff = float(np.mean(np.abs(test_probs - recorded_probs)))
    print(f"EXP-B2 Validation Check: Max diff vs Phase 3 recorded: {max_diff:.8f}, Mean diff: {mean_diff:.8f}")
    assert max_diff < 1e-4, f"EXP-B2 reconstruction failed validation! Max difference: {max_diff}"
    print("EXP-B2 Reconstruction SUCCESSFULLY VALIDATED!")
    
    from sklearn.feature_extraction.text import TfidfVectorizer
    tfidf = TfidfVectorizer(max_features=500, stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
    tfidf.fit(df["description_en"].fillna(""))
    
    model_b2.save_model(str(EXP_B2_DIR / "model.xgb"))
    joblib.dump(tfidf, str(EXP_B2_DIR / "vectorizer.joblib"))
    with open(EXP_B2_DIR / "feature_names.json", "w") as f:
        json.dump(feature_names, f, indent=2)
    print(f"EXP-B2 artifacts serialized to {EXP_B2_DIR}")


def main():
    print("Beginning Phase 4 Deterministic Model Reconstruction & Validation...")
    reconstruct_and_validate_a1()
    reconstruct_and_validate_b2()
    print("\nAll Phase 3 models successfully reconstructed, validated, and serialized!")


if __name__ == "__main__":
    main()
