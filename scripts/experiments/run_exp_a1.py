"""
Phase 3 EXP-A1: CVSS v3.1 Base Score Estimation (Corrected Preprocessing Pipeline)
Repository: seucra/vulnarability-prioritization-triage-system

Supervised regression predicting cvss_v31_base_score from publication-time features.
Temporal Split:
- TRAIN: 2002–2022
- VALIDATION: 2023–2024
- TEST: 2025–2026 (Evaluated ONCE after model selection freeze)

Leakage-Safe Preprocessing:
- TF-IDF and CWE feature selection are fit strictly on TRAIN during model selection/tuning.
- Preprocessor is refitted strictly on TRAIN + VALIDATION before final test set inference.
- Test partition is transformed using fitted preprocessor without refitting.

Outputs: metrics.json, test_predictions.parquet, model.xgb, vectorizer.joblib, feature_names.json
"""

import argparse
import json
import time
from pathlib import Path
from typing import Optional

import joblib
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.linear_model import Ridge
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
import xgboost as xgb

from src.features.preprocessing import LeakageSafePreprocessor

RANDOM_SEED = 42
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "data" / "experiments" / "phase3_corrected" / "exp_a1"


def load_data():
    print("Loading Parquet data for EXP-A1...")
    vulns = pq.read_table(str(PROCESSED_DIR / "vulnerabilities.parquet")).to_pandas()
    cwe = pq.read_table(str(PROCESSED_DIR / "cve_cwe.parquet")).to_pandas()
    cpe = pq.read_table(str(PROCESSED_DIR / "cve_cpe.parquet")).to_pandas()

    # Filter to CVEs with non-null cvss_v31_base_score
    df = vulns[vulns["cvss_v31_base_score"].notna()].copy()
    print(f"Total CVEs with CVSS v3.1 base score: {len(df):,}")
    return df, cwe, cpe


def eval_metrics(y_true, y_pred):
    mae = float(mean_absolute_error(y_true, y_pred))
    rmse = float(np.sqrt(mean_squared_error(y_true, y_pred)))
    r2 = float(r2_score(y_true, y_pred))
    return {"mae": round(mae, 4), "rmse": round(rmse, 4), "r2": round(r2, 4)}


def run_exp_a1(output_dir: Optional[Path] = None):
    if output_dir is None:
        output_dir = DEFAULT_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    df, cwe, cpe = load_data()

    # 1. Temporal Partitions
    years_all = df["publication_year"].values
    df_train = df[years_all <= 2022].copy()
    df_val = df[(years_all >= 2023) & (years_all <= 2024)].copy()
    df_test = df[years_all >= 2025].copy()
    df_train_val = df[years_all <= 2024].copy()

    y_train = df_train["cvss_v31_base_score"].values.astype(np.float32)
    y_val = df_val["cvss_v31_base_score"].values.astype(np.float32)
    y_test = df_test["cvss_v31_base_score"].values.astype(np.float32)
    y_train_val = df_train_val["cvss_v31_base_score"].values.astype(np.float32)

    print(
        f"Partition Sizes -> Train: {len(df_train):,}, Val: {len(df_val):,}, "
        f"Test: {len(df_test):,}, Train+Val Refit: {len(df_train_val):,}"
    )

    # 2. Model Selection Phase: Fit preprocessor strictly on TRAIN (<= 2022)
    print("\n--- Fitting LeakageSafePreprocessor on TRAIN partition (<= 2022) ---")
    preprocessor_tune = LeakageSafePreprocessor(include_epss=False, random_state=RANDOM_SEED)
    preprocessor_tune.fit(df_train, cwe)
    X_train = preprocessor_tune.transform(df_train, cwe, cpe)
    X_val = preprocessor_tune.transform(df_val, cwe, cpe)

    print(f"X_train shape: {X_train.shape}, X_val shape: {X_val.shape}")

    # --- Tuning A1-Baseline (Ridge Regression) ---
    print("\n--- Tuning A1-Baseline (Ridge Regression) ---")
    best_ridge_alpha = None
    best_ridge_val_mae = float("inf")

    alpha_candidates = [0.1, 1.0, 10.0, 100.0, 500.0]
    ridge_search_results = {}

    for alpha in alpha_candidates:
        model = Ridge(alpha=alpha, random_state=RANDOM_SEED)
        model.fit(X_train, y_train)
        val_pred = model.predict(X_val)
        val_mae = mean_absolute_error(y_val, val_pred)
        ridge_search_results[str(alpha)] = round(float(val_mae), 4)
        print(f"  Ridge (alpha={alpha}): Val MAE = {val_mae:.4f}")

        if val_mae < best_ridge_val_mae:
            best_ridge_val_mae = val_mae
            best_ridge_alpha = alpha

    print(f"Selected Best Ridge alpha: {best_ridge_alpha} (Val MAE: {best_ridge_val_mae:.4f})")

    # --- Tuning A1-Nonlinear (XGBoost Regressor) ---
    print("\n--- Tuning A1-Nonlinear (XGBoost Regressor) ---")
    param_grid = [
        {"max_depth": 4, "n_estimators": 100, "learning_rate": 0.1},
        {"max_depth": 6, "n_estimators": 150, "learning_rate": 0.08},
        {"max_depth": 8, "n_estimators": 200, "learning_rate": 0.05},
    ]

    best_xgb_params = None
    best_xgb_val_mae = float("inf")
    xgb_search_results = {}

    for params in param_grid:
        param_str = f"depth={params['max_depth']}_n={params['n_estimators']}_lr={params['learning_rate']}"
        t0 = time.time()
        model = xgb.XGBRegressor(
            max_depth=params["max_depth"],
            n_estimators=params["n_estimators"],
            learning_rate=params["learning_rate"],
            random_state=RANDOM_SEED,
            n_jobs=-1,
            tree_method="hist",
        )
        model.fit(X_train, y_train)
        val_pred = model.predict(X_val)
        val_mae = mean_absolute_error(y_val, val_pred)
        elapsed = time.time() - t0
        xgb_search_results[param_str] = round(float(val_mae), 4)
        print(f"  XGBoost ({param_str}): Val MAE = {val_mae:.4f} ({elapsed:.1f}s)")

        if val_mae < best_xgb_val_mae:
            best_xgb_val_mae = val_mae
            best_xgb_params = params

    print(f"Selected Best XGBoost params: {best_xgb_params} (Val MAE: {best_xgb_val_mae:.4f})")

    # 3. Final Test Evaluation Phase: Refit preprocessor on TRAIN + VALIDATION (<= 2024)
    print("\n--- Refitting LeakageSafePreprocessor on TRAIN + VALIDATION (<= 2024) ---")
    preprocessor_final = LeakageSafePreprocessor(include_epss=False, random_state=RANDOM_SEED)
    preprocessor_final.fit(df_train_val, cwe)

    X_train_val = preprocessor_final.transform(df_train_val, cwe, cpe)
    X_train_eval = preprocessor_final.transform(df_train, cwe, cpe)
    X_val_eval = preprocessor_final.transform(df_val, cwe, cpe)
    X_test = preprocessor_final.transform(df_test, cwe, cpe)

    print(f"X_train_val shape: {X_train_val.shape}, X_test shape: {X_test.shape}")

    # Refit Ridge on TRAIN + VALIDATION
    print("\nFitting final Ridge model...")
    final_ridge = Ridge(alpha=best_ridge_alpha, random_state=RANDOM_SEED)
    final_ridge.fit(X_train_val, y_train_val)

    train_pred_r = final_ridge.predict(X_train_eval)
    val_pred_r = final_ridge.predict(X_val_eval)
    test_pred_r = final_ridge.predict(X_test)

    ridge_metrics = {
        "best_hyperparameters": {"alpha": best_ridge_alpha},
        "search_grid_val_mae": ridge_search_results,
        "train": eval_metrics(y_train, train_pred_r),
        "validation": eval_metrics(y_val, val_pred_r),
        "test": eval_metrics(y_test, test_pred_r),
    }

    # Refit XGBoost on TRAIN + VALIDATION
    print("Fitting final XGBoost regressor...")
    final_xgb = xgb.XGBRegressor(
        max_depth=best_xgb_params["max_depth"],
        n_estimators=best_xgb_params["n_estimators"],
        learning_rate=best_xgb_params["learning_rate"],
        random_state=RANDOM_SEED,
        n_jobs=-1,
        tree_method="hist",
    )
    final_xgb.fit(X_train_val, y_train_val)

    train_pred_x = final_xgb.predict(X_train_eval)
    val_pred_x = final_xgb.predict(X_val_eval)
    test_pred_x = final_xgb.predict(X_test)

    xgb_metrics = {
        "best_hyperparameters": best_xgb_params,
        "search_grid_val_mae": xgb_search_results,
        "train": eval_metrics(y_train, train_pred_x),
        "validation": eval_metrics(y_val, val_pred_x),
        "test": eval_metrics(y_test, test_pred_x),
    }

    # Extract feature importances
    importances = final_xgb.feature_importances_
    top_feat_idx = np.argsort(importances)[::-1][:20]
    feature_names = preprocessor_final.feature_names
    top_features = {feature_names[i]: round(float(importances[i]), 5) for i in top_feat_idx}

    results = {
        "experiment": "EXP-A1",
        "target": "cvss_v31_base_score",
        "preprocessing_status": "CORRECTED (Inductive temporal fitting, no test leakage)",
        "dataset_cardinality": {
            "total": len(df),
            "train": len(df_train),
            "validation": len(df_val),
            "test": len(df_test),
            "train_val_refit": len(df_train_val),
        },
        "baseline_ridge": ridge_metrics,
        "nonlinear_xgboost": xgb_metrics,
        "top_20_xgboost_feature_importances": top_features,
    }

    # Save artifacts
    pred_df = pd.DataFrame({
        "cve_id": df_test["cve_id"].values,
        "y_test_actual": y_test,
        "ridge_pred": test_pred_r,
        "xgboost_pred": test_pred_x,
    })
    pred_df.to_parquet(output_dir / "test_predictions.parquet", index=False)

    with open(output_dir / "metrics.json", "w") as f:
        json.dump(results, f, indent=2)

    with open(output_dir / "feature_names.json", "w") as f:
        json.dump(feature_names, f, indent=2)

    joblib.dump(preprocessor_final.tfidf, output_dir / "vectorizer.joblib")
    final_xgb.save_model(output_dir / "model.xgb")

    print(f"\nEXP-A1 complete. Artifacts saved to {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EXP-A1 CVSS Base Score Regression (Corrected Preprocessing)")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to save experimental outputs (defaults to phase3_corrected/exp_a1 to preserve baseline)",
    )
    args = parser.parse_args()
    run_exp_a1(output_dir=args.output_dir)
