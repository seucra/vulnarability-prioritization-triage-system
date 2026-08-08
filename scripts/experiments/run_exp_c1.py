"""
Phase 3 EXP-C1: Linear Baseline vs. Nonlinear Decision-Support Simulation
Repository: wdl-vuln-prioritization

Multi-criteria decision-support simulation across controlled Asset Criticality Tiers (Tier 1–4).
Not supervised learning.

Reference Linear Baseline:
  S_linear = w1 * x1 + w2 * x2 + w3 * x3 + w4 * x4
  where x1 = CVSS/10, x2 = EPSS, x3 = KEV, x4 = Asset_criticality
  Project-controlled baseline weights: w = (0.25, 0.25, 0.25, 0.25)

Nonlinear Interactive Decision Surface:
  S_nonlinear = x4 * [ 1 - (1 - x1)^(1 + alpha * x3) * (1 - x2)^(1 + beta * x3) ]
  with alpha = 1.0, beta = 1.5

Outputs: data/experiments/phase3/exp_c1/metrics.json
"""

import json
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from scipy.stats import spearmanr, kendalltau

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
OUTPUT_DIR = REPO_ROOT / "data" / "experiments" / "phase3" / "exp_c1"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_data():
    print("Loading Parquet data for EXP-C1 simulation...")
    vulns = pq.read_table(str(PROCESSED_DIR / "vulnerabilities.parquet")).to_pandas()
    epss = pq.read_table(str(PROCESSED_DIR / "epss.parquet")).to_pandas()
    kev = pq.read_table(str(PROCESSED_DIR / "kev.parquet")).to_pandas()

    kev_set = set(kev["cve_id"])
    vulns["is_kev"] = vulns["cve_id"].isin(kev_set).astype(int)
    
    # Merge EPSS
    df = pd.merge(
        vulns[vulns["cvss_v31_base_score"].notna()],
        epss[["cve_id", "epss"]],
        on="cve_id",
        how="left"
    )
    df["epss"] = df["epss"].fillna(0.0)
    
    print(f"Total Intersected Population (CVSS v3.1 + EPSS + KEV): {len(df):,}")
    return df


def calculate_linear_score(x1, x2, x3, x4, w=(0.25, 0.25, 0.25, 0.25)):
    w1, w2, w3, w4 = w
    return w1 * x1 + w2 * x2 + w3 * x3 + w4 * x4


def calculate_nonlinear_score(x1, x2, x3, x4, alpha=1.0, beta=1.5):
    # Multiplicative interaction surface scaling threat likelihood and severity when KEV is active
    # Clip bounds to avoid numerical errors
    x1_c = np.clip(x1, 0.0, 1.0)
    x2_c = np.clip(x2, 0.0, 1.0)
    
    sev_factor = (1.0 - x1_c) ** (1.0 + alpha * x3)
    threat_factor = (1.0 - x2_c) ** (1.0 + beta * x3)
    
    risk_core = 1.0 - (sev_factor * threat_factor)
    return x4 * risk_core


def run_exp_c1():
    df = load_data()
    
    x1 = (df["cvss_v31_base_score"] / 10.0).values
    x2 = df["epss"].values
    x3 = df["is_kev"].values
    cve_ids = df["cve_id"].values
    
    asset_tiers = {
        "Tier 1 (Low Criticality)": 0.25,
        "Tier 2 (Medium Criticality)": 0.50,
        "Tier 3 (High Criticality)": 0.75,
        "Tier 4 (Critical Infrastructure)": 1.00,
    }
    
    tier_results = {}
    rank_export_dict = {"cve_id": cve_ids, "is_kev": x3, "cvss_v31": df["cvss_v31_base_score"].values, "epss": x2}
    
    for tier_name, x4_val in asset_tiers.items():
        print(f"\nEvaluating simulation scenario: {tier_name} (Asset Value = {x4_val})...")
        
        # Calculate scores
        s_lin = calculate_linear_score(x1, x2, x3, x4_val, w=(0.25, 0.25, 0.25, 0.25))
        s_nonlin = calculate_nonlinear_score(x1, x2, x3, x4_val, alpha=1.0, beta=1.5)
        
        # Store for export
        tier_key = tier_name.split()[0].lower()
        rank_export_dict[f"score_lin_{tier_key}"] = s_lin
        rank_export_dict[f"score_nonlin_{tier_key}"] = s_nonlin
        
        # Rank orders (1 = highest score)
        rank_lin = np.argsort(np.argsort(-s_lin)) + 1
        rank_nonlin = np.argsort(np.argsort(-s_nonlin)) + 1
        
        # Rank correlations
        rho, _ = spearmanr(s_lin, s_nonlin)
        tau, _ = kendalltau(s_lin[:5000], s_nonlin[:5000]) # Sample for Kendall speed
        
        # Top-K overlap
        top100_lin = set(np.argsort(-s_lin)[:100])
        top100_nonlin = set(np.argsort(-s_nonlin)[:100])
        top100_jaccard = len(top100_lin.intersection(top100_nonlin)) / len(top100_lin.union(top100_nonlin))
        
        top1000_lin = set(np.argsort(-s_lin)[:1000])
        top1000_nonlin = set(np.argsort(-s_nonlin)[:1000])
        top1000_jaccard = len(top1000_lin.intersection(top1000_nonlin)) / len(top1000_lin.union(top1000_nonlin))
        
        # KEV Capture in Top-100 & Top-1000
        kev_top100_lin = int(x3[list(top100_lin)].sum())
        kev_top100_nonlin = int(x3[list(top100_nonlin)].sum())
        
        kev_top1000_lin = int(x3[list(top1000_lin)].sum())
        kev_top1000_nonlin = int(x3[list(top1000_nonlin)].sum())
        
        tier_results[tier_name] = {
            "asset_criticality_x4": x4_val,
            "spearman_rank_correlation_rho": round(float(rho), 4),
            "kendall_tau": round(float(tau), 4),
            "top_100_jaccard_overlap": round(float(top100_jaccard), 4),
            "top_1000_jaccard_overlap": round(float(top1000_jaccard), 4),
            "kev_captured_in_top_100": {
                "linear_baseline": kev_top100_lin,
                "nonlinear_surface": kev_top100_nonlin,
                "delta": kev_top100_nonlin - kev_top100_lin
            },
            "kev_captured_in_top_1000": {
                "linear_baseline": kev_top1000_lin,
                "nonlinear_surface": kev_top1000_nonlin,
                "delta": kev_top1000_nonlin - kev_top1000_lin
            }
        }
        
    # Sensitivity analysis: Variant weights (0.30, 0.30, 0.20, 0.20)
    s_lin_variant = calculate_linear_score(x1, x2, x3, 1.0, w=(0.30, 0.30, 0.20, 0.20))
    s_lin_default = calculate_linear_score(x1, x2, x3, 1.0, w=(0.25, 0.25, 0.25, 0.25))
    rho_weights, _ = spearmanr(s_lin_default, s_lin_variant)
    
    results = {
        "experiment": "EXP-C1",
        "experiment_nature": "Controlled Factorial Decision-Support Simulation (Not Supervised Learning)",
        "intersected_population_count": len(df),
        "reference_linear_weights_baseline": {"w_cvss": 0.25, "w_epss": 0.25, "w_kev": 0.25, "w_asset": 0.25},
        "variant_weights_sensitivity_rho": round(float(rho_weights), 4),
        "nonlinear_surface_parameters": {"alpha_kev_severity_mult": 1.0, "beta_kev_threat_mult": 1.5},
        "asset_criticality_tier_results": tier_results,
    }
    
    rank_export_df = pd.DataFrame(rank_export_dict)
    rank_export_df.to_parquet(OUTPUT_DIR / "simulation_rankings.parquet", index=False)
    
    with open(OUTPUT_DIR / "metrics.json", "w") as f:
        json.dump(results, f, indent=2)
        
    print(f"\nEXP-C1 complete. Metrics saved to {OUTPUT_DIR / 'metrics.json'}")


if __name__ == "__main__":
    run_exp_c1()
