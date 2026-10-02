"""
Phase 3 EXP-B1: KEV Prediction With EPSS Snapshot (Retrospective Sensitivity Analysis)
Repository: seucra/vulnarability-prioritization-triage-system

Retrospective Sensitivity Experiment using 2026-07-16 EPSS Snapshot.
EXPLICIT LABEL: RETROSPECTIVE SNAPSHOT EXPERIMENT (Not a valid historical deployment model).

Temporal Split:
- TRAIN: 2002–2022
- VALIDATION: 2023–2024
- TEST: 2025–2026 (Evaluated ONCE after model selection freeze)

Leakage-Safe Preprocessing:
- TF-IDF and CWE feature selection are fit strictly on TRAIN during model selection/tuning.
- Preprocessor is refitted strictly on TRAIN + VALIDATION before final test set inference.
- Test partition is transformed using fitted preprocessor without refitting.
- Retrospective EPSS features (epss, epss_percentile) are retained for sensitivity quantification.

Outputs: metrics.json, test_predictions.parquet
"""

import argparse
import json
import time
from pathlib import Path
from typing import Optional

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    roc_auc_score,
    precision_recall_curve,
    f1_score,
)
import xgboost as xgb

from src.features.preprocessing import LeakageSafePreprocessor

RANDOM_SEED = 42
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
DEFAULT_OUTPUT_DIR = REPO_ROOT / "data" / "experiments" / "phase3_corrected" / "exp_b1"


def load_data():
    print("Loading Parquet data for EXP-B1...")
    vulns = pq.read_table(str(PROCESSED_DIR / "vulnerabilities.parquet")).to_pandas()
    cwe = pq.read_table(str(PROCESSED_DIR / "cve_cwe.parquet")).to_pandas()
    cpe = pq.read_table(str(PROCESSED_DIR / "cve_cpe.parquet")).to_pandas()
    epss = pq.read_table(str(PROCESSED_DIR / "epss.parquet")).to_pandas()
    kev = pq.read_table(str(PROCESSED_DIR / "kev.parquet")).to_pandas()

    kev_set = set(kev["cve_id"])
    vulns["is_kev"] = vulns["cve_id"].isin(kev_set).astype(int)

    # Merge EPSS scores
    vulns = pd.merge(
        vulns,
        epss[["cve_id", "epss", "percentile"]],
        on="cve_id",
        how="left",
    )
    # Fill missing EPSS with 0 score / percentile
    vulns["epss"] = vulns["epss"].fillna(0.0)
    vulns["percentile"] = vulns["percentile"].fillna(0.0)

    print(f"Total Canonical CVEs: {len(vulns):,}, KEV Positive: {vulns['is_kev'].sum():,}")
    return vulns, cwe, cpe


def eval_b1_metrics(y_true, y_prob):
    prauc = float(average_precision_score(y_true, y_prob))
    rocauc = float(roc_auc_score(y_true, y_prob))

    # Top-500 metrics
    top_500_idx = np.argsort(y_prob)[::-1][:500]
    p_at_500 = float(y_true[top_500_idx].sum() / 500.0)
    r_at_500 = float(y_true[top_500_idx].sum() / max(1, y_true.sum()))

    # Optimal F1 threshold
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_prob)
    f1_scores = np.where(
        (precisions + recalls) > 0,
        2 * (precisions * recalls) / (precisions + recalls),
        0.0,
    )
    best_f1_idx = np.argmax(f1_scores)
    max_f1 = float(f1_scores[best_f1_idx])
    opt_thresh = float(thresholds[best_f1_idx]) if best_f1_idx < len(thresholds) else 0.5

    return {
        "pr_auc": round(prauc, 5),
        "roc_auc": round(rocauc, 5),
        "precision_at_500": round(p_at_500, 4),
        "recall_at_500": round(r_at_500, 5),
        "max_f1": round(max_f1, 5),
        "optimal_f1_threshold": round(opt_thresh, 5),
    }


def run_exp_b1(output_dir: Optional[Path] = None):
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

    y_train = df_train["is_kev"].values.astype(int)
    y_val = df_val["is_kev"].values.astype(int)
    y_test = df_test["is_kev"].values.astype(int)
    y_train_val = df_train_val["is_kev"].values.astype(int)

    print(
        f"Partition Sizes -> Train: {len(df_train):,} ({y_train.sum()} KEV), "
        f"Val: {len(df_val):,} ({y_val.sum()} KEV), "
        f"Test: {len(df_test):,} ({y_test.sum()} KEV), "
        f"Train+Val Refit: {len(df_train_val):,} ({y_train_val.sum()} KEV)"
    )

    # 2. Model Selection Phase: Fit preprocessor strictly on TRAIN (<= 2022) with EPSS included
    print("\n--- Fitting LeakageSafePreprocessor on TRAIN partition (<= 2022) [Retrospective EPSS included] ---")
    preprocessor_tune = LeakageSafePreprocessor(include_epss=True, random_state=RANDOM_SEED)
    preprocessor_tune.fit(df_train, cwe)
    X_train = preprocessor_tune.transform(df_train, cwe, cpe)
    X_val = preprocessor_tune.transform(df_val, cwe, cpe)

    print(f"X_train shape: {X_train.shape}, X_val shape: {X_val.shape}")

    # --- Tuning B1-Baseline (Logistic Regression) ---
    print("\n--- Tuning B1-Baseline (Logistic Regression) ---")
    c_candidates = [0.01, 0.1, 1.0, 10.0]
    log_search_results = {}
    best_log_c = None
    best_log_val_prauc = -1.0

    for c_val in c_candidates:
        model = LogisticRegression(
            C=c_val,
            class_weight="balanced",
            max_iter=1000,
            random_state=RANDOM_SEED,
            n_jobs=-1,
        )
        model.fit(X_train, y_train)
        val_prob = model.predict_proba(X_val)[:, 1]
        val_prauc = average_precision_score(y_val, val_prob)
        log_search_results[str(c_val)] = round(float(val_prauc), 5)
        print(f"  LogReg (C={c_val}): Val PR-AUC = {val_prauc:.5f}")

        if val_prauc > best_log_val_prauc:
            best_log_val_prauc = val_prauc
            best_log_c = c_val

    print(f"Selected Best LogReg C: {best_log_c} (Val PR-AUC: {best_log_val_prauc:.5f})")

    # --- Tuning B1-Nonlinear (XGBoost Classifier) ---
    print("\n--- Tuning B1-Nonlinear (XGBoost Classifier) ---")
    param_grid = [
        {"scale_pos_weight": 20, "max_depth": 4, "n_estimators": 100, "learning_rate": 0.1},
        {"scale_pos_weight": 50, "max_depth": 6, "n_estimators": 150, "learning_rate": 0.08},
        {"scale_pos_weight": 100, "max_depth": 6, "n_estimators": 200, "learning_rate": 0.05},
    ]

    best_xgb_params = None
    best_xgb_val_prauc = -1.0
    xgb_search_results = {}

    for params in param_grid:
        param_str = (
            f"spw={params['scale_pos_weight']}_depth={params['max_depth']}_"
            f"n={params['n_estimators']}_lr={params['learning_rate']}"
        )
        t0 = time.time()
        model = xgb.XGBClassifier(
            scale_pos_weight=params["scale_pos_weight"],
            max_depth=params["max_depth"],
            n_estimators=params["n_estimators"],
            learning_rate=params["learning_rate"],
            random_state=RANDOM_SEED,
            n_jobs=-1,
            tree_method="hist",
            eval_metric="logloss",
        )
        model.fit(X_train, y_train)
        val_prob = model.predict_proba(X_val)[:, 1]
        val_prauc = average_precision_score(y_val, val_prob)
        elapsed = time.time() - t0
        xgb_search_results[param_str] = round(float(val_prauc), 5)
        print(f"  XGBoost ({param_str}): Val PR-AUC = {val_prauc:.5f} ({elapsed:.1f}s)")

        if val_prauc > best_xgb_val_prauc:
            best_xgb_val_prauc = val_prauc
            best_xgb_params = params

    print(f"Selected Best XGBoost params: {best_xgb_params} (Val PR-AUC: {best_xgb_val_prauc:.5f})")

    # 3. Final Test Evaluation Phase: Refit preprocessor on TRAIN + VALIDATION (<= 2024)
    print("\n--- Refitting LeakageSafePreprocessor on TRAIN + VALIDATION (<= 2024) ---")
    preprocessor_final = LeakageSafePreprocessor(include_epss=True, random_state=RANDOM_SEED)
    preprocessor_final.fit(df_train_val, cwe)

    X_train_val = preprocessor_final.transform(df_train_val, cwe, cpe)
    X_train_eval = preprocessor_final.transform(df_train, cwe, cpe)
    X_val_eval = preprocessor_final.transform(df_val, cwe, cpe)
    X_test = preprocessor_final.transform(df_test, cwe, cpe)

    print(f"X_train_val shape: {X_train_val.shape}, X_test shape: {X_test.shape}")

    # Refit Logistic Regression on TRAIN + VALIDATION
    print("\nFitting final Logistic Regression model...")
    final_log = LogisticRegression(
        C=best_log_c,
        class_weight="balanced",
        max_iter=1000,
        random_state=RANDOM_SEED,
        n_jobs=-1,
    )
    final_log.fit(X_train_val, y_train_val)

    train_prob_l = final_log.predict_proba(X_train_eval)[:, 1]
    val_prob_l = final_log.predict_proba(X_val_eval)[:, 1]
    test_prob_l = final_log.predict_proba(X_test)[:, 1]

    log_metrics = {
        "best_hyperparameters": {"C": best_log_c},
        "search_grid_val_prauc": log_search_results,
        "train": eval_b1_metrics(y_train, train_prob_l),
        "validation": eval_b1_metrics(y_val, val_prob_l),
        "test": eval_b1_metrics(y_test, test_prob_l),
    }

    # Refit XGBoost on TRAIN + VALIDATION
    print("Fitting final XGBoost classifier...")
    final_xgb = xgb.XGBClassifier(
        scale_pos_weight=best_xgb_params["scale_pos_weight"],
        max_depth=best_xgb_params["max_depth"],
        n_estimators=best_xgb_params["n_estimators"],
        learning_rate=best_xgb_params["learning_rate"],
        random_state=RANDOM_SEED,
        n_jobs=-1,
        tree_method="hist",
        eval_metric="logloss",
    )
    final_xgb.fit(X_train_val, y_train_val)

    train_prob_x = final_xgb.predict_proba(X_train_eval)[:, 1]
    val_prob_x = final_xgb.predict_proba(X_val_eval)[:, 1]
    test_prob_x = final_xgb.predict_proba(X_test)[:, 1]

    xgb_metrics = {
        "best_hyperparameters": best_xgb_params,
        "search_grid_val_prauc": xgb_search_results,
        "train": eval_b1_metrics(y_train, train_prob_x),
        "validation": eval_b1_metrics(y_val, val_prob_x),
        "test": eval_b1_metrics(y_test, test_prob_x),
    }

    # Feature Importances
    importances = final_xgb.feature_importances_
    top_feat_idx = np.argsort(importances)[::-1][:20]
    feature_names = preprocessor_final.feature_names
    top_features = {feature_names[i]: round(float(importances[i]), 5) for i in top_feat_idx}

    results = {
        "experiment": "EXP-B1",
        "experiment_designation": "RETROSPECTIVE SNAPSHOT EXPERIMENT (Sensitivity Analysis Only)",
        "prediction_point": "Retrospective Analysis with EPSS 2026-07-16 Snapshot",
        "epss_snapshot_provenance": "2026-07-16T12:03:48Z (Model v2026.06.15)",
        "methodological_status": "EXPLICIT NEGATIVE CONTROL (Demonstrates look-ahead telemetry inflation)",
        "preprocessing_status": "CORRECTED (Inductive temporal fitting, retrospective EPSS features retained)",
        "dataset_cardinality": {
            "total": len(df),
            "train": len(df_train),
            "validation": len(df_val),
            "test": len(df_test),
        },
        "baseline_logistic_regression": log_metrics,
        "nonlinear_xgboost": xgb_metrics,
        "top_20_xgboost_feature_importances": top_features,
    }

    # Save artifacts
    pred_df = pd.DataFrame({
        "cve_id": df_test["cve_id"].values,
        "y_test_actual": y_test,
        "logistic_prob": test_prob_l,
        "xgboost_prob": test_prob_x,
    })
    pred_df.to_parquet(output_dir / "test_predictions.parquet", index=False)

    with open(output_dir / "metrics.json", "w") as f:
        json.dump(results, f, indent=2)

    print(f"\nEXP-B1 complete. Artifacts saved to {output_dir}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="EXP-B1 Retrospective EPSS Sensitivity (Corrected Preprocessing)")
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Directory to save experimental outputs (defaults to phase3_corrected/exp_b1 to preserve baseline)",
    )
    args = parser.parse_args()
    run_exp_b1(output_dir=args.output_dir)
