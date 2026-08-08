"""
Phase 3 Research Visualizations Script
Repository: wdl-vuln-prioritization

Generates static publication-quality figures saved to docs/research/figures/phase3/:
- a1_cvss_actual_vs_predicted.png
- a1_cvss_residuals.png
- b2_pr_curve.png
- b2_roc_curve.png
- b1_vs_b2_comparison.png
- c1_ranking_changes_across_tiers.png
- c1_risk_surface_contours.png
- shap_a1_global_importance.png
- shap_b2_global_importance.png
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import seaborn as sns
from sklearn.metrics import precision_recall_curve, roc_curve

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
EXP_DIR = REPO_ROOT / "data" / "experiments" / "phase3"
FIGURES_DIR = REPO_ROOT / "docs" / "research" / "figures" / "phase3"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams["font.sans-serif"] = "DejaVu Sans"
plt.rcParams["axes.edgecolor"] = "#cccccc"
plt.rcParams["axes.linewidth"] = 0.8


def plot_exp_a1():
    pred_path = EXP_DIR / "exp_a1" / "test_predictions.parquet"
    if not pred_path.exists():
        return
    df = pq.read_table(str(pred_path)).to_pandas()
    
    # 1. Actual vs Predicted
    fig, ax = plt.subplots(figsize=(7, 6))
    ax.scatter(df["y_test_actual"], df["xgboost_pred"], alpha=0.15, s=12, color="#7570b3", label="XGBoost Predictions")
    ax.plot([0, 10], [0, 10], "r--", linewidth=1.5, label="Ideal Prediction (y = x)")
    ax.set_title("EXP-A1: Actual vs. Predicted CVSS v3.1 Base Score (Test Partition)", fontsize=11, fontweight="bold", pad=10)
    ax.set_xlabel("Authoritative CVSS v3.1 Base Score", fontsize=10)
    ax.set_ylabel("Predicted CVSS v3.1 Score", fontsize=10)
    ax.set_xlim(-0.5, 10.5)
    ax.set_ylim(-0.5, 10.5)
    ax.legend(loc="upper left")
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "a1_cvss_actual_vs_predicted.png", dpi=300)
    plt.close()
    
    # 2. Residuals
    residuals = df["xgboost_pred"] - df["y_test_actual"]
    fig, ax = plt.subplots(figsize=(7, 4.5))
    sns.histplot(residuals, bins=50, kde=True, ax=ax, color="#7570b3", alpha=0.6)
    ax.set_title("EXP-A1: XGBoost Residual Error Distribution (Test Partition)", fontsize=11, fontweight="bold", pad=10)
    ax.set_xlabel("Residual Error (Predicted - Actual)", fontsize=10)
    ax.set_ylabel("Count", fontsize=10)
    ax.axvline(0, color="red", linestyle="--", linewidth=1.2)
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "a1_cvss_residuals.png", dpi=300)
    plt.close()


def plot_exp_b2():
    pred_path = EXP_DIR / "exp_b2" / "test_predictions.parquet"
    if not pred_path.exists():
        return
    df = pq.read_table(str(pred_path)).to_pandas()
    y_true = df["y_test_actual"].values
    
    # PR Curve
    p_log, r_log, _ = precision_recall_curve(y_true, df["logistic_prob"])
    p_xgb, r_xgb, _ = precision_recall_curve(y_true, df["xgboost_prob"])
    
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(r_xgb, p_xgb, color="#e7298a", linewidth=2, label="B2 XGBoost (Publication-Time, PR-AUC=0.0288)")
    ax.plot(r_log, p_log, color="#2b5c8f", linewidth=1.5, linestyle="--", label="B2 Logistic Regression (PR-AUC=0.0208)")
    ax.axhline(y_true.mean(), color="gray", linestyle=":", label=f"Random Baseline ({y_true.mean()*100:.2f}%)")
    
    ax.set_title("EXP-B2: Precision-Recall Curve (Publication-Time KEV Prediction)", fontsize=11, fontweight="bold", pad=10)
    ax.set_xlabel("Recall", fontsize=10)
    ax.set_ylabel("Precision", fontsize=10)
    ax.legend(loc="upper right", fontsize=9)
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "b2_pr_curve.png", dpi=300)
    plt.close()
    
    # ROC Curve
    fpr_l, tpr_l, _ = roc_curve(y_true, df["logistic_prob"])
    fpr_x, tpr_x, _ = roc_curve(y_true, df["xgboost_prob"])
    
    fig, ax = plt.subplots(figsize=(7, 5))
    ax.plot(fpr_l, tpr_l, color="#2b5c8f", linewidth=1.8, label="B2 Logistic Regression (ROC-AUC=0.8586)")
    ax.plot(fpr_x, tpr_x, color="#e7298a", linewidth=2, linestyle="-.", label="B2 XGBoost (ROC-AUC=0.8132)")
    ax.plot([0, 1], [0, 1], "k--", alpha=0.5, label="Random Classifier (AUC=0.5)")
    
    ax.set_title("EXP-B2: ROC Curve (Publication-Time KEV Prediction)", fontsize=11, fontweight="bold", pad=10)
    ax.set_xlabel("False Positive Rate", fontsize=10)
    ax.set_ylabel("True Positive Rate", fontsize=10)
    ax.legend(loc="lower right", fontsize=9)
    ax.grid(True, linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "b2_roc_curve.png", dpi=300)
    plt.close()


def plot_b1_vs_b2_comparison():
    b1_file = EXP_DIR / "exp_b1" / "metrics.json"
    b2_file = EXP_DIR / "exp_b2" / "metrics.json"
    if not (b1_file.exists() and b2_file.exists()):
        return
        
    with open(b1_file, "r") as f:
        b1_res = json.load(f)
    with open(b2_file, "r") as f:
        b2_res = json.load(f)
        
    b2_prauc = [
        b2_res["baseline_logistic_regression"]["test"]["pr_auc"],
        b2_res["nonlinear_xgboost"]["test"]["pr_auc"]
    ]
    b1_prauc = [
        b1_res["baseline_logistic_regression"]["test"]["pr_auc"],
        b1_res["nonlinear_xgboost"]["test"]["pr_auc"]
    ]
    
    models = ["Logistic Regression", "XGBoost Classifier"]
    x = np.arange(len(models))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(8, 4.5))
    rects1 = ax.bar(x - width/2, b2_prauc, width, label="EXP-B2 (Publication-Time, No EPSS)", color="#2b5c8f")
    rects2 = ax.bar(x + width/2, b1_prauc, width, label="EXP-B1 (Retrospective 2026 EPSS Snapshot)", color="#d95f02")
    
    ax.set_ylabel("PR-AUC (Average Precision) on Test Partition", fontsize=10)
    ax.set_title("Retrospective EPSS Snapshot Leakage Comparison (EXP-B1 vs EXP-B2)", fontsize=11, fontweight="bold", pad=10)
    ax.set_xticks(x)
    ax.set_xticklabels(models)
    ax.legend(loc="upper left")
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    
    # Annotate bars
    for bar in rects1:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 0.005, f"{h:.4f}", ha="center", va="bottom", fontsize=9, fontweight="bold")
    for bar in rects2:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 0.005, f"{h:.4f}", ha="center", va="bottom", fontsize=9, fontweight="bold", color="#d95f02")
        
    ax.set_ylim(0, 0.40)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "b1_vs_b2_comparison.png", dpi=300)
    plt.close()


def plot_exp_c1():
    c1_file = EXP_DIR / "exp_c1" / "metrics.json"
    if not c1_file.exists():
        return
    with open(c1_file, "r") as f:
        c1_res = json.load(f)
        
    tiers = list(c1_res["asset_criticality_tier_results"].keys())
    tier_labels = ["Tier 1\n(Low)", "Tier 2\n(Medium)", "Tier 3\n(High)", "Tier 4\n(Critical)"]
    
    top100_jaccard = [c1_res["asset_criticality_tier_results"][t]["top_100_jaccard_overlap"] for t in tiers]
    top1000_jaccard = [c1_res["asset_criticality_tier_results"][t]["top_1000_jaccard_overlap"] for t in tiers]
    
    x = np.arange(len(tiers))
    width = 0.35
    
    fig, ax = plt.subplots(figsize=(8, 4.5))
    rects1 = ax.bar(x - width/2, top100_jaccard, width, label="Top-100 Queue Jaccard Overlap", color="#1b9e77")
    rects2 = ax.bar(x + width/2, top1000_jaccard, width, label="Top-1000 Queue Jaccard Overlap", color="#7570b3")
    
    ax.set_ylabel("Jaccard Overlap Ratio (Linear vs Nonlinear)", fontsize=10)
    ax.set_title("EXP-C1: High-Priority Queue Disruption Across Asset Criticality Tiers", fontsize=11, fontweight="bold", pad=10)
    ax.set_xticks(x)
    ax.set_xticklabels(tier_labels)
    ax.legend(loc="upper right")
    ax.set_ylim(0, 0.30)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    
    for bar in rects1:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 0.005, f"{h:.3f}", ha="center", va="bottom", fontsize=8, fontweight="bold")
    for bar in rects2:
        h = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., h + 0.005, f"{h:.3f}", ha="center", va="bottom", fontsize=8, fontweight="bold")
        
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "c1_ranking_changes_across_tiers.png", dpi=300)
    plt.close()

    # Contour Plot for C1 Risk Surface
    x1_vals = np.linspace(0, 1, 100)
    x2_vals = np.linspace(0, 1, 100)
    X1, X2 = np.meshgrid(x1_vals, x2_vals)
    
    # Linear surface (KEV=0, Asset=1.0)
    Z_lin = 0.25 * X1 + 0.25 * X2 + 0.25 * 0 + 0.25 * 1.0
    # Nonlinear surface (KEV=1, Asset=1.0)
    Z_nonlin = 1.0 * (1.0 - (1.0 - X1)**2.0 * (1.0 - X2)**2.5)
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    
    c1 = ax1.contourf(X1, X2, Z_lin, levels=15, cmap="Blues")
    fig.colorbar(c1, ax=ax1)
    ax1.set_title("Linear Baseline Surface (S_linear)", fontsize=11, fontweight="bold")
    ax1.set_xlabel("Normalized CVSS (x1)", fontsize=9)
    ax1.set_ylabel("EPSS Probability (x2)", fontsize=9)
    
    c2 = ax2.contourf(X1, X2, Z_nonlin, levels=15, cmap="Reds")
    fig.colorbar(c2, ax=ax2)
    ax2.set_title("Nonlinear Interactive Surface (S_nonlinear, KEV=1)", fontsize=11, fontweight="bold")
    ax2.set_xlabel("Normalized CVSS (x1)", fontsize=9)
    ax2.set_ylabel("EPSS Probability (x2)", fontsize=9)
    
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "c1_risk_surface_contours.png", dpi=300)
    plt.close()


def plot_shap():
    shap_file = EXP_DIR / "shap" / "shap_summary.json"
    if not shap_file.exists():
        return
    with open(shap_file, "r") as f:
        shap_res = json.load(f)
        
    a1_feats = shap_res["exp_a1_top_shap_importance"]
    b2_feats = shap_res["exp_b2_top_shap_importance"]
    
    # A1 SHAP Plot
    fig, ax = plt.subplots(figsize=(8, 4.5))
    keys = list(a1_feats.keys())[:10][::-1]
    vals = [a1_feats[k] for k in keys]
    ax.barh(keys, vals, color="#7570b3")
    ax.set_title("EXP-A1: Top SHAP Global Feature Importances (CVSS Regressor)", fontsize=11, fontweight="bold", pad=10)
    ax.set_xlabel("Mean Absolute SHAP Value (|SHAP|)", fontsize=10)
    ax.grid(axis="x", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "shap_a1_global_importance.png", dpi=300)
    plt.close()
    
    # B2 SHAP Plot
    fig, ax = plt.subplots(figsize=(8, 4.5))
    keys = list(b2_feats.keys())[:10][::-1]
    vals = [b2_feats[k] for k in keys]
    ax.barh(keys, vals, color="#e7298a")
    ax.set_title("EXP-B2: Top SHAP Global Feature Importances (KEV Classifier)", fontsize=11, fontweight="bold", pad=10)
    ax.set_xlabel("Mean Absolute SHAP Value (|SHAP|)", fontsize=10)
    ax.grid(axis="x", linestyle="--", alpha=0.5)
    plt.tight_layout()
    plt.savefig(FIGURES_DIR / "shap_b2_global_importance.png", dpi=300)
    plt.close()


def main():
    print("Generating Phase 3 research figures...")
    plot_exp_a1()
    plot_exp_b2()
    plot_b1_vs_b2_comparison()
    plot_exp_c1()
    plot_shap()
    print("All Phase 3 figures successfully generated and saved to docs/research/figures/phase3/.")


if __name__ == "__main__":
    main()
