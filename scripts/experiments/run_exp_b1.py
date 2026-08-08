"""
Phase 3 EXP-B1: KEV Prediction With EPSS Snapshot (Retrospective Sensitivity)
Repository: wdl-vuln-prioritization

Retrospective Sensitivity Experiment using 2026-07-16 EPSS Snapshot.
EXPLICIT LABEL: RETROSPECTIVE SNAPSHOT EXPERIMENT (Not a valid historical deployment model).

Temporal Split:
- TRAIN: 2002–2022
- VALIDATION: 2023–2024
- TEST: 2025–2026 (Evaluated ONCE after model selection freeze)

Models:
- B1-Baseline: Logistic Regression (class_weight='balanced')
- B1-Nonlinear: XGBoost Classifier (scale_pos_weight tuned)

Outputs: data/experiments/phase3/exp_b1/metrics.json
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
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    average_precision_score,
    roc_auc_score,
    precision_recall_curve,
    f1_score,
)
import xgboost as xgb

RANDOM_SEED = 42
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
OUTPUT_DIR = REPO_ROOT / "data" / "experiments" / "phase3" / "exp_b1"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


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
        how="left"
    )
    # Fill missing EPSS with 0 score / percentile
    vulns["epss"] = vulns["epss"].fillna(0.0)
    vulns["percentile"] = vulns["percentile"].fillna(0.0)
    
    print(f"Total Canonical CVEs: {len(vulns):,}, KEV Positive: {vulns['is_kev'].sum():,}")
    return vulns, cwe, cpe


def build_features(df, cwe, cpe):
    print("Building features (including EPSS snapshot) for EXP-B1...")
    
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
    
    # Retrospective EPSS features
    feat_df["epss"] = df["epss"].values
    feat_df["epss_percentile"] = df["percentile"].values
    
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
    y_all = df["is_kev"].values.astype(int)
    years_all = df["publication_year"].values
    
    feature_names = [f"tfidf_{w}" for w in tfidf.get_feature_names_out()] + list(feat_df.columns)
    print(f"Combined feature matrix shape: {X_all.shape}")
    
    return X_all, y_all, years_all, feature_names


def eval_b1_metrics(y_true, y_prob, k_val=500):
    pr_auc = float(average_precision_score(y_true, y_prob))
    roc_auc = float(roc_auc_score(y_true, y_prob))
    
    top_k_idx = np.argsort(y_prob)[::-1][:k_val]
    top_k_true = y_true[top_k_idx]
    
    prec_at_k = float(top_k_true.sum() / k_val)
    rec_at_k = float(top_k_true.sum() / y_true.sum()) if y_true.sum() > 0 else 0.0
    
    precisions, recalls, thresholds = precision_recall_curve(y_true, y_prob)
    f1_scores = 2 * (precisions * recalls) / (precisions + recalls + 1e-10)
    best_idx = np.argmax(f1_scores)
    best_f1 = float(f1_scores[best_idx])
    best_thresh = float(thresholds[best_idx]) if best_idx < len(thresholds) else 0.5
    
    return {
        "pr_auc": round(pr_auc, 5),
        "roc_auc": round(roc_auc, 5),
        f"precision_at_{k_val}": round(prec_at_k, 5),
        f"recall_at_{k_val}": round(rec_at_k, 5),
        "max_f1": round(best_f1, 5),
        "optimal_f1_threshold": round(best_thresh, 5),
    }


def run_exp_b1():
    df, cwe, cpe = load_data()
    X_all, y_all, years_all, feature_names = build_features(df, cwe, cpe)
    
    # Temporal Partitions
    train_idx = np.where(years_all <= 2022)[0]
    val_idx = np.where((years_all >= 2023) & (years_all <= 2024))[0]
    test_idx = np.where(years_all >= 2025)[0]
    train_val_idx = np.where(years_all <= 2024)[0]
    
    X_train, y_train = X_all[train_idx], y_all[train_idx]
    X_val, y_val = X_all[val_idx], y_all[val_idx]
    X_test, y_test = X_all[test_idx], y_all[test_idx]
    X_train_val, y_train_val = X_all[train_val_idx], y_all[train_val_idx]
    
    # --- 1. B1-Baseline (Logistic Regression) ---
    print("\n--- Tuning B1-Baseline (Logistic Regression with EPSS Snapshot) ---")
    c_candidates = [0.01, 0.1, 1.0, 10.0]
    best_log_c = None
    best_log_val_prauc = -1.0
    log_search_results = {}
    
    for c in c_candidates:
        model = LogisticRegression(C=c, class_weight="balanced", random_state=RANDOM_SEED, max_iter=1000)
        model.fit(X_train, y_train)
        val_prob = model.predict_proba(X_val)[:, 1]
        val_prauc = average_precision_score(y_val, val_prob)
        log_search_results[str(c)] = round(float(val_prauc), 5)
        print(f"  Logistic Regression (C={c}): Val PR-AUC = {val_prauc:.5f}")
        
        if val_prauc > best_log_val_prauc:
            best_log_val_prauc = val_prauc
            best_log_c = c
            
    print(f"Selected Best Logistic Regression C: {best_log_c} (Val PR-AUC: {best_log_val_prauc:.5f})")
    
    final_log = LogisticRegression(C=best_log_c, class_weight="balanced", random_state=RANDOM_SEED, max_iter=1000)
    final_log.fit(X_train_val, y_train_val)
    
    train_prob_l = final_log.predict_proba(X_train)[:, 1]
    val_prob_l = final_log.predict_proba(X_val)[:, 1]
    test_prob_l = final_log.predict_proba(X_test)[:, 1]
    
    log_metrics = {
        "best_hyperparameters": {"C": best_log_c},
        "search_grid_val_prauc": log_search_results,
        "train": eval_b1_metrics(y_train, train_prob_l),
        "validation": eval_b1_metrics(y_val, val_prob_l),
        "test": eval_b1_metrics(y_test, test_prob_l),
    }
    
    # --- 2. B1-Nonlinear (XGBoost Classifier) ---
    print("\n--- Tuning B1-Nonlinear (XGBoost Classifier with EPSS Snapshot) ---")
    param_grid = [
        {"scale_pos_weight": 20, "max_depth": 4, "n_estimators": 100, "learning_rate": 0.1},
        {"scale_pos_weight": 50, "max_depth": 6, "n_estimators": 150, "learning_rate": 0.08},
        {"scale_pos_weight": 100, "max_depth": 6, "n_estimators": 200, "learning_rate": 0.05},
    ]
    
    best_xgb_params = None
    best_xgb_val_prauc = -1.0
    xgb_search_results = {}
    
    for params in param_grid:
        param_str = f"spw={params['scale_pos_weight']}_depth={params['max_depth']}_n={params['n_estimators']}_lr={params['learning_rate']}"
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
    
    train_prob_x = final_xgb.predict_proba(X_train)[:, 1]
    val_prob_x = final_xgb.predict_proba(X_val)[:, 1]
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
    top_features = {feature_names[i]: round(float(importances[i]), 5) for i in top_feat_idx}
    
    # Read EXP-B2 test PR-AUC to compute leakage delta
    b2_metrics_file = REPO_ROOT / "data" / "experiments" / "phase3" / "exp_b2" / "metrics.json"
    delta_prauc_xgb = None
    delta_prauc_log = None
    if b2_metrics_file.exists():
        with open(b2_metrics_file, "r") as f:
            b2_res = json.load(f)
        b2_test_prauc_xgb = b2_res["nonlinear_xgboost"]["test"]["pr_auc"]
        b2_test_prauc_log = b2_res["baseline_logistic_regression"]["test"]["pr_auc"]
        delta_prauc_xgb = round(xgb_metrics["test"]["pr_auc"] - b2_test_prauc_xgb, 5)
        delta_prauc_log = round(log_metrics["test"]["pr_auc"] - b2_test_prauc_log, 5)
    
    results = {
        "experiment": "EXP-B1",
        "experiment_designation": "RETROSPECTIVE SNAPSHOT EXPERIMENT (Sensitivity Analysis Only)",
        "target": "is_kev",
        "prediction_point": "Retrospective Analysis with EPSS 2026-07-16 Snapshot",
        "dataset_cardinality": {
            "total": len(df),
            "train": len(train_idx),
            "validation": len(val_idx),
            "test": len(test_idx),
        },
        "baseline_logistic_regression": log_metrics,
        "nonlinear_xgboost": xgb_metrics,
        "snapshot_leakage_delta_test": {
            "logistic_regression_delta_pr_auc": delta_prauc_log,
            "xgboost_delta_pr_auc": delta_prauc_xgb,
            "interpretation": "Quantifies performance boost on test partition attributable to 2026 EPSS snapshot features.",
        },
        "top_20_xgboost_feature_importances": top_features,
    }
    
    pred_df = pd.DataFrame({
        "cve_id": df.iloc[test_idx]["cve_id"].values,
        "y_test_actual": y_test,
        "logistic_prob": test_prob_l,
        "xgboost_prob": test_prob_x,
    })
    pred_df.to_parquet(OUTPUT_DIR / "test_predictions.parquet", index=False)
    
    with open(OUTPUT_DIR / "metrics.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print(f"\nEXP-B1 complete. Metrics saved to {OUTPUT_DIR / 'metrics.json'}")


if __name__ == "__main__":
    run_exp_b1()
