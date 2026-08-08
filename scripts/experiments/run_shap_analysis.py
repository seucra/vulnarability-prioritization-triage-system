"""
Phase 3 SHAP Post-Hoc Explainability Script
Repository: wdl-vuln-prioritization

Performs post-hoc SHAP analysis strictly AFTER final model freezing:
- EXP-A1 (XGBoost Regressor for CVSS v3.1 Score)
- EXP-B2 (XGBoost Classifier for Publication-Time KEV Prediction)

Outputs: data/experiments/phase3/shap/shap_summary.json
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from scipy.sparse import hstack, csr_matrix
from sklearn.feature_extraction.text import TfidfVectorizer
import shap
import xgboost as xgb

RANDOM_SEED = 42
REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
OUTPUT_DIR = REPO_ROOT / "data" / "experiments" / "phase3" / "shap"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def run_a1_shap():
    print("\n--- Running SHAP Analysis for EXP-A1 (CVSS v3.1 Regressor) ---")
    a1_dir = REPO_ROOT / "data" / "experiments" / "phase3" / "exp_a1"
    with open(a1_dir / "metrics.json", "r") as f:
        a1_meta = json.load(f)
    best_params = a1_meta["nonlinear_xgboost"]["best_hyperparameters"]
    
    vulns = pq.read_table(str(PROCESSED_DIR / "vulnerabilities.parquet")).to_pandas()
    cwe = pq.read_table(str(PROCESSED_DIR / "cve_cwe.parquet")).to_pandas()
    cpe = pq.read_table(str(PROCESSED_DIR / "cve_cpe.parquet")).to_pandas()
    
    df = vulns[vulns["cvss_v31_base_score"].notna()].copy()
    
    # Rebuild feature matrix
    tfidf = TfidfVectorizer(max_features=500, stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
    X_text = tfidf.fit_transform(df["description_en"].fillna(""))
    
    cwe_counts = cwe.groupby("cve_id").size().rename("cwe_count")
    semantic_cwe_counts = cwe[cwe["is_semantic_cwe"]].groupby("cve_id").size().rename("semantic_cwe_count")
    top_20_cwes = cwe[cwe["is_semantic_cwe"]]["cwe_id"].value_counts().head(20).index.tolist()
    cwe_top20_df = cwe[cwe["cwe_id"].isin(top_20_cwes)].groupby(["cve_id", "cwe_id"]).size().unstack(fill_value=0)
    cwe_top20_df = (cwe_top20_df > 0).astype(int)
    
    cpe_counts = cpe.groupby("cve_id").size().rename("cpe_count")
    cpe_parts = cpe.groupby(["cve_id", "part"]).size().unstack(fill_value=0)
    cpe_parts.columns = [f"cpe_part_{col}" for col in cpe_parts.columns]
    vendor_counts = cpe.groupby("cve_id")["vendor"].nunique().rename("vendor_count")
    product_counts = cpe.groupby("cve_id")["product"].nunique().rename("product_count")
    
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
    pub_dt = pd.to_datetime(df["published"], errors="coerce")
    feat_df["pub_month"] = pub_dt.dt.month.fillna(1).values
    
    X_num = csr_matrix(feat_df.values.astype(np.float32))
    X_all = hstack([X_text, X_num]).tocsr()
    y_all = df["cvss_v31_base_score"].values.astype(np.float32)
    years_all = df["publication_year"].values
    
    feature_names = [f"tfidf_{w}" for w in tfidf.get_feature_names_out()] + list(feat_df.columns)
    
    train_val_idx = np.where(years_all <= 2024)[0]
    test_idx = np.where(years_all >= 2025)[0]
    
    # Fit final frozen model
    model = xgb.XGBRegressor(
        max_depth=best_params["max_depth"],
        n_estimators=best_params["n_estimators"],
        learning_rate=best_params["learning_rate"],
        random_state=RANDOM_SEED,
        n_jobs=-1,
        tree_method="hist",
    )
    model.fit(X_all[train_val_idx], y_all[train_val_idx])
    
    # Compute SHAP values on test sample
    test_sample_idx = test_idx[:2000] # Representative sample for fast exact TreeExplainer
    X_sample = X_all[test_sample_idx].toarray()
    
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample)
    
    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    top_shap_idx = np.argsort(mean_abs_shap)[::-1][:15]
    
    a1_shap_dict = {feature_names[i]: round(float(mean_abs_shap[i]), 5) for i in top_shap_idx}
    print("A1 Top 5 SHAP Features:", list(a1_shap_dict.items())[:5])
    return a1_shap_dict


def run_b2_shap():
    print("\n--- Running SHAP Analysis for EXP-B2 (KEV Classifier) ---")
    b2_dir = REPO_ROOT / "data" / "experiments" / "phase3" / "exp_b2"
    with open(b2_dir / "metrics.json", "r") as f:
        b2_meta = json.load(f)
    best_params = b2_meta["nonlinear_xgboost"]["best_hyperparameters"]
    
    vulns = pq.read_table(str(PROCESSED_DIR / "vulnerabilities.parquet")).to_pandas()
    cwe = pq.read_table(str(PROCESSED_DIR / "cve_cwe.parquet")).to_pandas()
    cpe = pq.read_table(str(PROCESSED_DIR / "cve_cpe.parquet")).to_pandas()
    kev = pq.read_table(str(PROCESSED_DIR / "kev.parquet")).to_pandas()
    
    kev_set = set(kev["cve_id"])
    vulns["is_kev"] = vulns["cve_id"].isin(kev_set).astype(int)
    
    # Rebuild feature matrix
    tfidf = TfidfVectorizer(max_features=500, stop_words="english", ngram_range=(1, 2), sublinear_tf=True)
    X_text = tfidf.fit_transform(vulns["description_en"].fillna(""))
    
    cwe_counts = cwe.groupby("cve_id").size().rename("cwe_count")
    semantic_cwe_counts = cwe[cwe["is_semantic_cwe"]].groupby("cve_id").size().rename("semantic_cwe_count")
    top_20_cwes = cwe[cwe["is_semantic_cwe"]]["cwe_id"].value_counts().head(20).index.tolist()
    cwe_top20_df = cwe[cwe["cwe_id"].isin(top_20_cwes)].groupby(["cve_id", "cwe_id"]).size().unstack(fill_value=0)
    cwe_top20_df = (cwe_top20_df > 0).astype(int)
    
    cpe_counts = cpe.groupby("cve_id").size().rename("cpe_count")
    cpe_parts = cpe.groupby(["cve_id", "part"]).size().unstack(fill_value=0)
    cpe_parts.columns = [f"cpe_part_{col}" for col in cpe_parts.columns]
    vendor_counts = cpe.groupby("cve_id")["vendor"].nunique().rename("vendor_count")
    product_counts = cpe.groupby("cve_id")["product"].nunique().rename("product_count")
    
    feat_df = pd.DataFrame(index=vulns["cve_id"])
    feat_df["has_cwe"] = vulns["has_cwe"].astype(int).values
    feat_df["has_cpe_configuration"] = vulns["has_cpe_configuration"].astype(int).values
    feat_df = feat_df.join(cwe_counts, how="left").fillna({"cwe_count": 0})
    feat_df = feat_df.join(semantic_cwe_counts, how="left").fillna({"semantic_cwe_count": 0})
    feat_df = feat_df.join(cwe_top20_df, how="left").fillna(0)
    feat_df = feat_df.join(cpe_counts, how="left").fillna({"cpe_count": 0})
    feat_df = feat_df.join(cpe_parts, how="left").fillna(0)
    feat_df = feat_df.join(vendor_counts, how="left").fillna({"vendor_count": 0})
    feat_df = feat_df.join(product_counts, how="left").fillna({"product_count": 0})
    pub_dt = pd.to_datetime(vulns["published"], errors="coerce")
    feat_df["pub_month"] = pub_dt.dt.month.fillna(1).values
    
    X_num = csr_matrix(feat_df.values.astype(np.float32))
    X_all = hstack([X_text, X_num]).tocsr()
    y_all = vulns["is_kev"].values.astype(int)
    years_all = vulns["publication_year"].values
    
    feature_names = [f"tfidf_{w}" for w in tfidf.get_feature_names_out()] + list(feat_df.columns)
    
    train_val_idx = np.where(years_all <= 2024)[0]
    test_idx = np.where(years_all >= 2025)[0]
    
    # Fit final frozen model
    model = xgb.XGBClassifier(
        scale_pos_weight=best_params["scale_pos_weight"],
        max_depth=best_params["max_depth"],
        n_estimators=best_params["n_estimators"],
        learning_rate=best_params["learning_rate"],
        random_state=RANDOM_SEED,
        n_jobs=-1,
        tree_method="hist",
        eval_metric="logloss",
    )
    model.fit(X_all[train_val_idx], y_all[train_val_idx])
    
    test_sample_idx = test_idx[:2000]
    X_sample = X_all[test_sample_idx].toarray()
    
    explainer = shap.TreeExplainer(model)
    shap_values = explainer.shap_values(X_sample)
    
    mean_abs_shap = np.abs(shap_values).mean(axis=0)
    top_shap_idx = np.argsort(mean_abs_shap)[::-1][:15]
    
    b2_shap_dict = {feature_names[i]: round(float(mean_abs_shap[i]), 5) for i in top_shap_idx}
    print("B2 Top 5 SHAP Features:", list(b2_shap_dict.items())[:5])
    return b2_shap_dict


def main():
    a1_shap = run_a1_shap()
    b2_shap = run_b2_shap()
    
    results = {
        "analysis": "Post-Hoc SHAP Explainability",
        "scope": "Evaluated on frozen final fitted models (EXP-A1 Regressor & EXP-B2 Classifier) on Test partition samples.",
        "exp_a1_top_shap_importance": a1_shap,
        "exp_b2_top_shap_importance": b2_shap,
        "causal_disclaimer": "SHAP explains model behavior and relative feature influence within the trained decision tree ensembles; it does not establish causal mechanisms.",
    }
    
    with open(OUTPUT_DIR / "shap_summary.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print(f"\nSHAP analysis complete. Output saved to {OUTPUT_DIR / 'shap_summary.json'}")


if __name__ == "__main__":
    main()
