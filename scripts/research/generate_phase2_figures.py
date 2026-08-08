"""
Phase 2 Research Visualizations Script
Repository: wdl-vuln-prioritization

Generates clean research figures saved to docs/research/figures/phase2/:
- cvss_distributions.png
- temporal_availability_by_year.png
- epss_distribution_and_percentiles.png
- kev_publication_to_added_delay.png
- kev_class_imbalance.png
"""

import json
from pathlib import Path

import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import seaborn as sns

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
FIGURES_DIR = REPO_ROOT / "docs" / "research" / "figures" / "phase2"
FIGURES_DIR.mkdir(parents=True, exist_ok=True)

# Set global publication plot style
plt.style.use("seaborn-v0_8-whitegrid" if "seaborn-v0_8-whitegrid" in plt.style.available else "default")
plt.rcParams["font.sans-serif"] = "DejaVu Sans"
plt.rcParams["axes.edgecolor"] = "#cccccc"
plt.rcParams["axes.linewidth"] = 0.8


def plot_cvss_distributions(vulns):
    fig, ax = plt.subplots(figsize=(9, 5))
    
    cvss_data = []
    labels = []
    
    for col, name in [
        ("cvss_v2_base_score", "CVSS v2.0"),
        ("cvss_v30_base_score", "CVSS v3.0"),
        ("cvss_v31_base_score", "CVSS v3.1"),
        ("cvss_v40_base_score", "CVSS v4.0"),
    ]:
        vals = vulns[col].dropna()
        if len(vals) > 0:
            cvss_data.append(vals)
            labels.append(f"{name}\n(n={len(vals):,})")
            
    palette = ["#2b5c8f", "#d95f02", "#7570b3", "#1b9e77"]
    
    bp = ax.boxplot(
        cvss_data,
        tick_labels=labels,
        patch_artist=True,
        medianprops=dict(color="black", linewidth=1.5),
        flierprops=dict(marker=".", markersize=2, alpha=0.3),
    )
    
    for patch, color in zip(bp["boxes"], palette):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
        
    ax.set_title("CVSS Base Score Distributions Across Versions", fontsize=13, fontweight="bold", pad=12)
    ax.set_ylabel("Base Score (0.0 – 10.0)", fontsize=11)
    ax.set_ylim(-0.5, 10.5)
    ax.grid(axis="y", linestyle="--", alpha=0.7)
    
    plt.tight_layout()
    out_path = FIGURES_DIR / "cvss_distributions.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved figure: {out_path}")


def plot_temporal_availability(vulns, epss, kev):
    years = sorted(vulns["publication_year"].unique())
    # Filter years >= 2000 for cleaner visualization
    years_sub = [y for y in years if y >= 2000]
    
    epss_set = set(epss["cve_id"])
    kev_set = set(kev["cve_id"])
    
    total_cves = []
    v2_cves = []
    v31_cves = []
    epss_cves = []
    kev_cves = []
    
    for y in years_sub:
        sub = vulns[vulns["publication_year"] == y]
        total_cves.append(len(sub))
        v2_cves.append(sub["cvss_v2_base_score"].notna().sum())
        v31_cves.append(sub["cvss_v31_base_score"].notna().sum())
        
        cve_ids = set(sub["cve_id"])
        epss_cves.append(len(cve_ids.intersection(epss_set)))
        kev_cves.append(len(cve_ids.intersection(kev_set)))
        
    fig, ax1 = plt.subplots(figsize=(11, 5.5))
    
    ax1.plot(years_sub, total_cves, color="#333333", linewidth=2.5, label="Total Published CVEs", linestyle="-")
    ax1.plot(years_sub, v2_cves, color="#2b5c8f", linewidth=1.8, label="CVSS v2 Available", linestyle="--")
    ax1.plot(years_sub, v31_cves, color="#7570b3", linewidth=1.8, label="CVSS v3.1 Available", linestyle="-.")
    ax1.plot(years_sub, epss_cves, color="#1b9e77", linewidth=1.8, label="EPSS Snapshot Coverage", linestyle=":")
    
    ax1.set_xlabel("CVE Publication Year", fontsize=11)
    ax1.set_ylabel("Number of CVEs", fontsize=11)
    ax1.set_title("Vulnerability Volume & Feature Availability Over Time (2000–2026)", fontsize=13, fontweight="bold", pad=12)
    ax1.legend(loc="upper left", frameon=True)
    ax1.grid(True, linestyle="--", alpha=0.5)
    
    # Secondary axis for KEV
    ax2 = ax1.twinx()
    ax2.bar(years_sub, kev_cves, alpha=0.35, color="#e7298a", width=0.6, label="KEV Catalog Additions")
    ax2.set_ylabel("CISA KEV Vulnerabilities", fontsize=11, color="#e7298a")
    ax2.tick_params(axis="y", labelcolor="#e7298a")
    ax2.grid(False)
    
    plt.tight_layout()
    out_path = FIGURES_DIR / "temporal_availability_by_year.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved figure: {out_path}")


def plot_epss_distribution(epss):
    scores = epss["epss"]
    
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    
    # Linear & Log Score Density
    sns.histplot(scores, bins=50, kde=True, ax=ax1, color="#1b9e77", stat="density", alpha=0.6)
    ax1.set_title("EPSS Probability Density Score Distribution", fontsize=12, fontweight="bold")
    ax1.set_xlabel("EPSS Score [0.0 - 1.0]", fontsize=10)
    ax1.set_ylabel("Density", fontsize=10)
    ax1.grid(True, linestyle="--", alpha=0.5)
    
    # Percentile curve
    sorted_scores = np.sort(scores)
    percentiles = np.linspace(0, 100, len(sorted_scores))
    ax2.plot(percentiles, sorted_scores, color="#d95f02", linewidth=2)
    ax2.set_title("EPSS Score vs. Percentile Curve", fontsize=12, fontweight="bold")
    ax2.set_xlabel("EPSS Percentile (0 – 100%)", fontsize=10)
    ax2.set_ylabel("EPSS Probability Score", fontsize=10)
    ax2.grid(True, linestyle="--", alpha=0.5)
    ax2.set_yscale("log")
    
    plt.tight_layout()
    out_path = FIGURES_DIR / "epss_distribution_and_percentiles.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved figure: {out_path}")


def plot_kev_delay(vulns, kev):
    merged = pd.merge(
        kev,
        vulns[["cve_id", "published"]],
        on="cve_id",
        how="inner"
    )
    
    merged["pub_dt"] = pd.to_datetime(merged["published"], errors="coerce").dt.tz_localize(None)
    merged["kev_dt"] = pd.to_datetime(merged["date_added"], errors="coerce")
    merged["delay_years"] = (merged["kev_dt"] - merged["pub_dt"]).dt.total_seconds() / (365.25 * 24 * 3600)
    
    delay_years = merged["delay_years"].dropna()
    
    fig, ax = plt.subplots(figsize=(8, 4.5))
    
    sns.histplot(delay_years, bins=40, ax=ax, color="#e7298a", kde=True, alpha=0.6)
    ax.set_title("Delay Between NVD Publication and CISA KEV Catalog Addition", fontsize=12, fontweight="bold", pad=12)
    ax.set_xlabel("Time Elapsed (Years)", fontsize=10)
    ax.set_ylabel("Number of KEV Vulnerabilities", fontsize=10)
    ax.axvline(0, color="black", linestyle="--", linewidth=1, label="Publication Date (0 yrs)")
    ax.axvline(delay_years.median(), color="#7570b3", linestyle="-.", linewidth=1.5, label=f"Median ({delay_years.median():.2f} yrs)")
    ax.legend(loc="upper right")
    ax.grid(True, linestyle="--", alpha=0.5)
    
    plt.tight_layout()
    out_path = FIGURES_DIR / "kev_publication_to_added_delay.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved figure: {out_path}")


def plot_kev_imbalance(vulns, kev):
    total = len(vulns)
    kev_count = len(kev)
    non_kev = total - kev_count
    
    fig, ax = plt.subplots(figsize=(6, 4.5))
    
    bars = ax.bar(["Non-KEV\n(Unobserved)", "CISA KEV\n(Known Exploited)"], [non_kev, kev_count], color=["#2b5c8f", "#e7298a"], width=0.5)
    ax.set_yscale("log")
    ax.set_ylabel("CVE Count (Log Scale)", fontsize=11)
    ax.set_title("CISA KEV Binary Class Imbalance in Canonical Dataset", fontsize=12, fontweight="bold", pad=12)
    
    # Annotate bars
    ax.text(0, non_kev * 1.2, f"{non_kev:,}\n(99.55%)", ha="center", va="bottom", fontsize=10, fontweight="bold")
    ax.text(1, kev_count * 1.2, f"{kev_count:,}\n(0.45%)", ha="center", va="bottom", fontsize=10, fontweight="bold", color="#e7298a")
    
    ax.set_ylim(100, total * 3)
    ax.grid(axis="y", linestyle="--", alpha=0.5)
    
    plt.tight_layout()
    out_path = FIGURES_DIR / "kev_class_imbalance.png"
    plt.savefig(out_path, dpi=300)
    plt.close()
    print(f"Saved figure: {out_path}")


def main():
    print("Loading Parquet data for figures generation...")
    vulns = pq.read_table(str(PROCESSED_DIR / "vulnerabilities.parquet")).to_pandas()
    epss = pq.read_table(str(PROCESSED_DIR / "epss.parquet")).to_pandas()
    kev = pq.read_table(str(PROCESSED_DIR / "kev.parquet")).to_pandas()
    
    plot_cvss_distributions(vulns)
    plot_temporal_availability(vulns, epss, kev)
    plot_epss_distribution(epss)
    plot_kev_delay(vulns, kev)
    plot_kev_imbalance(vulns, kev)
    print("All Phase 2 figures successfully generated.")


if __name__ == "__main__":
    main()
