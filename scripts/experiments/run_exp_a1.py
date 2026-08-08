"""
Phase 3 EXP-A1: CVSS v3.1 Base Score Estimation
Repository: wdl-vuln-prioritization

Supervised regression predicting cvss_v31_base_score from publication-time features.
Temporal Split:
- TRAIN: 2002–2022
- VALIDATION: 2023–2024
- TEST: 2025–2026 (Evaluated ONCE after model selection freeze)

Models:
- A1-Baseline: Ridge Regression
- A1-Nonlinear: XGBoost Regressor

Outputs: data/experiments/phase3/exp_a1/metrics.json
"""

import json
import os
import time
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import Ridge
from sklearn.metrics import mean_absolute_error, mean_squared_error, r2_score
import xgboost as xgb

RANDOM_SEED = 42
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
OUTPUT_DIR = REPO_ROOT / "data" / "experiments" / "phase3" / "exp_a1"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_data():
    print("Loading Parquet data for EXP-A1...")
    vulns = pq.read_table(str(PROCESSED_DIR / "vulnerabilities.parquet")).to_pandas()
    cwe = pq.read_table(str(PROCESSED_DIR / "cve_cwe.parquet")).to_pandas()
    cpe = pq.read_table(str(PROCESSED_DIR / "cve_cpe.parquet")).to_pandas()

    # Filter to CVEs with non-null cvss_v31_base_score
    df = vulns[vulns["cvss_v31_base_score"].notna()].copy()
    print(f"Total CVEs with CVSS v3.1 base score: {len(df):,}")
    return df, cwe, cpe


def build_features(df, cwe, cpe):
    print("Building features for EXP-A1...")
    
    # 1. Text Features (TF-IDF on description_en)
    tfidf = TfidfVectorizer(
        max_features=500,
        stop_words="english",
        ngram_range=(1, 2),
        sublinear_tf=True,
    )
    desc_text = df["description_en"].fillna("")
    X_text = tfidf.fit_transform(desc_text)
    
    # 2. CWE Features
    cwe_counts = cwe.groupby("cve_id").size().rename("cwe_count")
    semantic_cwe_counts = cwe[cwe["is_semantic_cwe"]].groupby("cve_id").size().rename("semantic_cwe_count")
    
    top_20_cwes = cwe[cwe["is_semantic_cwe"]]["cwe_id"].value_counts().head(20).index.tolist()
    cwe_top20_df = cwe[cwe["cwe_id"].isin(top_20_cwes)].groupby(["cve_id", "cwe_id"]).size().unstack(fill_value=0)
    cwe_top20_df = (cwe_top20_df > 0).astype(int)
    
    # 3. CPE Features
    cpe_counts = cpe.groupby("cve_id").size().rename("cpe_count")
    cpe_parts = cpe.groupby(["cve_id", "part"]).size().unstack(fill_value=0)
    cpe_parts.columns = [f"cpe_part_{col}" for col in cpe_parts.columns]
    
    vendor_counts = cpe.groupby("cve_id")["vendor"].nunique().rename("vendor_count")
    product_counts = cpe.groupby("cve_id")["product"].nunique().rename("product_count")
    
    # Merge tabular features into df
    feat_df = pd.DataFrame(index=df["cve_id"])
    feat_df["has_cwe"] = df["has_cwe"].astype(int).values
    feat_df["has_cpe_configuration"] = df["has_cpe_configuration"].astype(int).values
    
    feat_df = feat_df.join(cwe_counts, how="left").fillna({"cwe_count": 0})
    feat_df = feat_df.join(semantic_cwe_counts, how="left").fillna({"semantic_cwe_count": 0})
    feat_df = feat_df.join(cwe_top20_df, how="left").fillna(0)
    
    feat_df = feat_df.join(cpe_counts, how="left").fillna({"cpe_count": 0})
    feat_df = feat_df.join(cpe_parts, how="left").fillna(0)
    feat_df = feat_df.join(vendor_counts, how="left").fillna({"vendor_count": 0})
    feat_df = feat_df.join(product_counts, how="left").fillna({"product_count": 0})
    
    # Publication month
    pub_dt = pd.to_datetime(df["published"], errors="coerce")
    feat_df["pub_month"] = pub_dt.dt.month.fillna(1).values
    
    X_num = csr_matrix(feat_df.values.astype(np.float32))
    
    # Combine TF-IDF and tabular features
    X_all = hstack([X_text, X_num]).tocsr()
    y_all = df["cvss_v31_base_score"].values.astype(np.float32)
    years_all = df["publication_year"].values
    
    feature_names = [f"tfidf_{w}" for w in tfidf.get_feature_names_out()] + list(feat_df.columns)
    print(f"Combined feature matrix shape: {X_all.shape}")
    
    return X_all, y_all, years_all, feature_names


def eval_metrics(y_true, y_pred):
    mae = float(mean_absolute_error(y_true, y_pred))
    rmse = float(np.sqrt(mean_squared_error(y_true, y_pred)))
    r2 = float(r2_score(y_true, y_pred))
    return {"mae": round(mae, 4), "rmse": round(rmse, 4), "r2": round(r2, 4)}


def run_exp_a1():
    df, cwe, cpe = load_data()
    X_all, y_all, years_all, feature_names = build_features(df, cwe, cpe)
    
    # Temporal Partitions
    train_idx = np.where(years_all <= 2022)[0]
    val_idx = np.where((years_all >= 2023) & (years_all <= 2024))[0]
    test_idx = np.where(years_all >= 2025)[0]
    train_val_idx = np.where(years_all <= 2024)[0]
    
    print(f"Partition Sizes -> Train: {len(train_idx):,}, Val: {len(val_idx):,}, Test: {len(test_idx):,}")
    
    X_train, y_train = X_all[train_idx], y_all[train_idx]
    X_val, y_val = X_all[val_idx], y_all[val_idx]
    X_test, y_test = X_all[test_idx], y_all[test_idx]
    X_train_val, y_train_val = X_all[train_val_idx], y_all[train_val_idx]
    
    # --- 1. A1-Baseline (Ridge Regression) ---
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
    
    # Refit Ridge on TRAIN + VALIDATION
    final_ridge = Ridge(alpha=best_ridge_alpha, random_state=RANDOM_SEED)
    final_ridge.fit(X_train_val, y_train_val)
    
    train_pred_r = final_ridge.predict(X_train)
    val_pred_r = final_ridge.predict(X_val)
    test_pred_r = final_ridge.predict(X_test)
    
    ridge_metrics = {
        "best_hyperparameters": {"alpha": best_ridge_alpha},
        "search_grid_val_mae": ridge_search_results,
        "train": eval_metrics(y_train, train_pred_r),
        "validation": eval_metrics(y_val, val_pred_r),
        "test": eval_metrics(y_test, test_pred_r),
    }
    
    # --- 2. A1-Nonlinear (XGBoost Regressor) ---
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
    
    # Refit XGBoost on TRAIN + VALIDATION
    final_xgb = xgb.XGBRegressor(
        max_depth=best_xgb_params["max_depth"],
        n_estimators=best_xgb_params["n_estimators"],
        learning_rate=best_xgb_params["learning_rate"],
        random_state=RANDOM_SEED,
        n_jobs=-1,
        tree_method="hist",
    )
    final_xgb.fit(X_train_val, y_train_val)
    
    train_pred_x = final_xgb.predict(X_train)
    val_pred_x = final_xgb.predict(X_val)
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
    top_features = {feature_names[i]: round(float(importances[i]), 5) for i in top_feat_idx}
    
    results = {
        "experiment": "EXP-A1",
        "target": "cvss_v31_base_score",
        "dataset_cardinality": {
            "total": len(df),
            "train": len(train_idx),
            "validation": len(val_idx),
            "test": len(test_idx),
            "train_val_refit": len(train_val_idx),
        },
        "baseline_ridge": ridge_metrics,
        "nonlinear_xgboost": xgb_metrics,
        "top_20_xgboost_feature_importances": top_features,
    }
    
    # Save predictions for plotting
    pred_df = pd.DataFrame({
        "cve_id": df.iloc[test_idx]["cve_id"].values,
        "y_test_actual": y_test,
        "ridge_pred": test_pred_r,
        "xgboost_pred": test_pred_x,
    })
    pred_df.to_parquet(OUTPUT_DIR / "test_predictions.parquet", index=False)
    
    with open(OUTPUT_DIR / "metrics.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print(f"\nEXP-A1 complete. Metrics saved to {OUTPUT_DIR / 'metrics.json'}")


if __name__ == "__main__":
    run_exp_a1()
