"""
Phase 2 Dataset Characterization Script
Repository: wdl-vuln-prioritization

Performs read-only descriptive analysis of canonical frozen Parquet tables:
- data/processed/vulnerabilities.parquet
- data/processed/cve_cwe.parquet
- data/processed/cve_cpe.parquet
- data/processed/epss.parquet
- data/processed/kev.parquet
- data/processed/vendor_statements.parquet

Exports metrics to data/experiments/phase2_metrics.json for report generation.
"""

import json
import os
from pathlib import Path

import numpy as np
import pandas as pd
import pyarrow.parquet as pq

REPO_ROOT = Path(__file__).resolve().parent.parent.parent
PROCESSED_DIR = REPO_ROOT / "data" / "processed"
OUTPUT_DIR = REPO_ROOT / "data" / "experiments"
OUTPUT_DIR.mkdir(parents=True, exist_ok=True)


def load_datasets():
    print("Loading frozen Parquet datasets...")
    vulns = pq.read_table(str(PROCESSED_DIR / "vulnerabilities.parquet")).to_pandas()
    cwe = pq.read_table(str(PROCESSED_DIR / "cve_cwe.parquet")).to_pandas()
    cpe = pq.read_table(str(PROCESSED_DIR / "cve_cpe.parquet")).to_pandas()
    epss = pq.read_table(str(PROCESSED_DIR / "epss.parquet")).to_pandas()
    kev = pq.read_table(str(PROCESSED_DIR / "kev.parquet")).to_pandas()
    vendor = pq.read_table(str(PROCESSED_DIR / "vendor_statements.parquet")).to_pandas()
    print("Datasets successfully loaded into memory.")
    return vulns, cwe, cpe, epss, kev, vendor


def analyze_cvss(vulns):
    print("\n--- Analyzing CVSS Metrics ---")
    metrics = {}
    versions = ["cvss_v2", "cvss_v30", "cvss_v31", "cvss_v40"]
    
    for v in versions:
        score_col = f"{v}_base_score"
        sev_col = f"{v}_severity"
        
        scores = vulns[score_col].dropna()
        count = int(len(scores))
        missing = int(len(vulns) - count)
        pct_covered = float(count / len(vulns) * 100)
        
        stats = {}
        if count > 0:
            stats = {
                "count": count,
                "missing": missing,
                "coverage_pct": round(pct_covered, 2),
                "min": float(scores.min()),
                "max": float(scores.max()),
                "mean": round(float(scores.mean()), 3),
                "median": round(float(scores.median()), 3),
                "std": round(float(scores.std()), 3),
                "p25": round(float(scores.quantile(0.25)), 3),
                "p75": round(float(scores.quantile(0.75)), 3),
            }
            
            if sev_col in vulns.columns:
                sev_counts = vulns[sev_col].value_counts(dropna=False).to_dict()
                stats["severities"] = {str(k): int(v) for k, v in sev_counts.items()}
        else:
            stats = {"count": 0, "missing": missing, "coverage_pct": 0.0}
            
        metrics[v] = stats

    # Vector breakdown for CVSS v3.1
    v31_vectors = vulns["cvss_v31_vector"].dropna()
    component_counts = {}
    if len(v31_vectors) > 0:
        # Example vector: CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
        parsed_components = []
        for vec in v31_vectors:
            parts = vec.split("/")
            comp_dict = {}
            for p in parts:
                if ":" in p:
                    k, val = p.split(":", 1)
                    comp_dict[k] = val
            parsed_components.append(comp_dict)
            
        comp_df = pd.DataFrame(parsed_components)
        for col in ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]:
            if col in comp_df.columns:
                counts = comp_df[col].value_counts().to_dict()
                component_counts[col] = {str(k): int(v) for k, v in counts.items()}
                
    metrics["cvss_v31_components"] = component_counts
    return metrics


def analyze_descriptions(vulns):
    print("\n--- Analyzing Vulnerability Descriptions ---")
    desc = vulns["description_en"].fillna("")
    
    char_lens = desc.apply(len)
    word_counts = desc.apply(lambda text: len(text.split()))
    
    empty_desc = int((char_lens == 0).sum())
    near_empty_desc = int((char_lens < 10).sum())
    near_empty_words = int((word_counts < 5).sum())
    
    duplicate_counts = desc.value_counts()
    unique_desc_count = int(len(duplicate_counts))
    duplicated_text_count = int((duplicate_counts > 1).sum())
    duplicated_records_count = int(len(vulns) - unique_desc_count)
    
    top_duplicates = duplicate_counts[duplicate_counts > 1].head(5).to_dict()
    
    return {
        "total_records": int(len(vulns)),
        "unique_descriptions": unique_desc_count,
        "duplicated_text_types": duplicated_text_count,
        "duplicated_total_records": duplicated_records_count,
        "empty_descriptions": empty_desc,
        "near_empty_char_lt_10": near_empty_desc,
        "near_empty_words_lt_5": near_empty_words,
        "char_length": {
            "min": int(char_lens.min()),
            "max": int(char_lens.max()),
            "mean": round(float(char_lens.mean()), 2),
            "median": round(float(char_lens.median()), 2),
            "p25": round(float(char_lens.quantile(0.25)), 2),
            "p75": round(float(char_lens.quantile(0.75)), 2),
            "p95": round(float(char_lens.quantile(0.95)), 2),
            "p99": round(float(char_lens.quantile(0.99)), 2),
        },
        "word_count": {
            "min": int(word_counts.min()),
            "max": int(word_counts.max()),
            "mean": round(float(word_counts.mean()), 2),
            "median": round(float(word_counts.median()), 2),
            "p25": round(float(word_counts.quantile(0.25)), 2),
            "p75": round(float(word_counts.quantile(0.75)), 2),
            "p95": round(float(word_counts.quantile(0.95)), 2),
            "p99": round(float(word_counts.quantile(0.99)), 2),
        },
        "top_duplicate_examples": {str(k)[:50] + "...": int(v) for k, v in top_duplicates.items()}
    }


def analyze_cwe(vulns, cwe):
    print("\n--- Analyzing CWE Taxonomy ---")
    total_cwe_records = int(len(cwe))
    unique_cwes = int(cwe["cwe_id"].nunique())
    unique_cves_in_cwe = int(cwe["cve_id"].nunique())
    
    # Semantic vs non-semantic
    semantic_count = int(cwe["is_semantic_cwe"].sum())
    non_semantic_count = int((~cwe["is_semantic_cwe"]).sum())
    
    nvd_noinfo = int((cwe["cwe_id"] == "NVD-CWE-noinfo").sum())
    nvd_other = int((cwe["cwe_id"] == "NVD-CWE-Other").sum())
    
    # CWE mappings per CVE
    cwe_per_cve = cwe.groupby("cve_id").size()
    cve_has_cwe_set = set(cwe["cve_id"])
    cve_no_cwe_count = int(len(vulns) - len(cve_has_cwe_set))
    
    single_cwe_count = int((cwe_per_cve == 1).sum())
    multi_cwe_count = int((cwe_per_cve > 1).sum())
    
    cwe_dist = {
        "0_cwes": cve_no_cwe_count,
        "1_cwe": single_cwe_count,
        "multi_cwes": multi_cwe_count,
        "max_cwes_per_cve": int(cwe_per_cve.max()) if len(cwe_per_cve) > 0 else 0,
    }
    
    top_cwes = cwe["cwe_id"].value_counts().head(10).to_dict()
    
    return {
        "total_cwe_mappings": total_cwe_records,
        "unique_cwe_ids": unique_cwes,
        "unique_cves_with_cwe": unique_cves_in_cwe,
        "cve_coverage_pct": round(unique_cves_in_cwe / len(vulns) * 100, 2),
        "semantic_cwe_mappings": semantic_count,
        "non_semantic_mappings": non_semantic_count,
        "nvd_cwe_noinfo_count": nvd_noinfo,
        "nvd_cwe_other_count": nvd_other,
        "cwe_per_cve_distribution": cwe_dist,
        "top_10_cwes": {str(k): int(v) for k, v in top_cwes.items()}
    }


def analyze_cpe(vulns, cpe):
    print("\n--- Analyzing CPE Applicability ---")
    total_cpe_rows = int(len(cpe))
    unique_cves_in_cpe = int(cpe["cve_id"].nunique())
    cves_without_cpe = int(len(vulns) - unique_cves_in_cpe)
    
    cpe_per_cve = cpe.groupby("cve_id").size()
    
    counts_binned = {
        "0_cpe": cves_without_cpe,
        "1_cpe": int((cpe_per_cve == 1).sum()),
        "2_to_5_cpe": int(((cpe_per_cve >= 2) & (cpe_per_cve <= 5)).sum()),
        "6_to_20_cpe": int(((cpe_per_cve >= 6) & (cpe_per_cve <= 20)).sum()),
        "21_plus_cpe": int((cpe_per_cve >= 21).sum()),
    }
    
    unique_vendors = int(cpe["vendor"].dropna().nunique())
    unique_products = int(cpe["product"].dropna().nunique())
    
    part_dist = cpe["part"].value_counts(dropna=False).to_dict()
    top_vendors = cpe["vendor"].value_counts().head(10).to_dict()
    top_products = cpe["product"].value_counts().head(10).to_dict()
    
    return {
        "total_cpe_mappings": total_cpe_rows,
        "unique_cves_with_cpe": unique_cves_in_cpe,
        "cpe_coverage_pct": round(unique_cves_in_cpe / len(vulns) * 100, 2),
        "cves_without_cpe": cves_without_cpe,
        "cpe_per_cve_distribution": counts_binned,
        "cpe_per_cve_stats": {
            "min": int(cpe_per_cve.min()) if len(cpe_per_cve) > 0 else 0,
            "max": int(cpe_per_cve.max()) if len(cpe_per_cve) > 0 else 0,
            "mean": round(float(cpe_per_cve.mean()), 2) if len(cpe_per_cve) > 0 else 0.0,
            "median": round(float(cpe_per_cve.median()), 2) if len(cpe_per_cve) > 0 else 0.0,
            "p90": round(float(cpe_per_cve.quantile(0.90)), 2) if len(cpe_per_cve) > 0 else 0.0,
            "p99": round(float(cpe_per_cve.quantile(0.99)), 2) if len(cpe_per_cve) > 0 else 0.0,
        },
        "unique_vendors": unique_vendors,
        "unique_products": unique_products,
        "part_distribution": {str(k): int(v) for k, v in part_dist.items()},
        "top_10_vendors": {str(k): int(v) for k, v in top_vendors.items()},
        "top_10_products": {str(k): int(v) for k, v in top_products.items()},
    }


def analyze_epss(vulns, epss):
    print("\n--- Analyzing EPSS Dataset ---")
    total_epss = int(len(epss))
    unique_epss_cves = int(epss["cve_id"].nunique())
    
    vuln_cve_set = set(vulns["cve_id"])
    epss_cve_set = set(epss["cve_id"])
    
    overlap = len(vuln_cve_set.intersection(epss_cve_set))
    epss_not_in_nvd = len(epss_cve_set - vuln_cve_set)
    nvd_without_epss = len(vuln_cve_set - epss_cve_set)
    
    scores = epss["epss"]
    pcts = epss["percentile"]
    
    # Correlation
    corr = float(scores.corr(pcts))
    
    return {
        "total_epss_rows": total_epss,
        "unique_epss_cves": unique_epss_cves,
        "nvd_overlap_count": overlap,
        "nvd_overlap_pct": round(overlap / len(vulns) * 100, 2),
        "epss_cves_absent_from_nvd": epss_not_in_nvd,
        "nvd_cves_missing_epss": nvd_without_epss,
        "score_date": str(epss["score_date"].iloc[0]),
        "model_version": str(epss["model_version"].iloc[0]),
        "score_stats": {
            "min": float(scores.min()),
            "max": float(scores.max()),
            "mean": round(float(scores.mean()), 5),
            "median": round(float(scores.median()), 5),
            "std": round(float(scores.std()), 5),
            "p10": round(float(scores.quantile(0.10)), 5),
            "p25": round(float(scores.quantile(0.25)), 5),
            "p50": round(float(scores.quantile(0.50)), 5),
            "p75": round(float(scores.quantile(0.75)), 5),
            "p90": round(float(scores.quantile(0.90)), 5),
            "p95": round(float(scores.quantile(0.95)), 5),
            "p99": round(float(scores.quantile(0.99)), 5),
            "p99_9": round(float(scores.quantile(0.999)), 5),
        },
        "percentile_stats": {
            "min": float(pcts.min()),
            "max": float(pcts.max()),
            "mean": round(float(pcts.mean()), 5),
            "median": round(float(pcts.median()), 5),
            "p25": round(float(pcts.quantile(0.25)), 5),
            "p75": round(float(pcts.quantile(0.75)), 5),
        },
        "score_percentile_correlation": round(corr, 4),
    }


def analyze_kev(vulns, kev):
    print("\n--- Analyzing CISA KEV Dataset ---")
    total_kev = int(len(kev))
    unique_kev_cves = int(kev["cve_id"].nunique())
    
    membership_rate = round(total_kev / len(vulns) * 100, 4)
    
    ransomware_dist = kev["known_ransomware_campaign_use"].value_counts().to_dict()
    
    # Join with vulnerabilities for publication date comparison
    merged = pd.merge(
        kev,
        vulns[["cve_id", "published", "publication_year"]],
        on="cve_id",
        how="inner"
    )
    
    # Calculate days between publication and KEV date_added
    merged["pub_dt"] = pd.to_datetime(merged["published"], errors="coerce").dt.tz_localize(None)
    merged["kev_dt"] = pd.to_datetime(merged["date_added"], errors="coerce")
    
    merged["delay_days"] = (merged["kev_dt"] - merged["pub_dt"]).dt.total_seconds() / (24 * 3600)
    
    delay_valid = merged["delay_days"].dropna()
    
    negative_delay = int((delay_valid < 0).sum())
    within_30d = int(((delay_valid >= 0) & (delay_valid <= 30)).sum())
    within_90d = int(((delay_valid >= 0) & (delay_valid <= 90)).sum())
    within_365d = int(((delay_valid >= 0) & (delay_valid <= 365)).sum())
    over_1yr = int((delay_valid > 365).sum())
    
    year_added_dist = pd.to_datetime(kev["date_added"]).dt.year.value_counts().sort_index().to_dict()
    pub_year_kev_dist = merged["publication_year"].value_counts().sort_index().to_dict()
    
    return {
        "total_kev_catalog_rows": total_kev,
        "unique_kev_cves": unique_kev_cves,
        "nvd_membership_rate_pct": membership_rate,
        "nvd_membership_fraction": f"{total_kev} / {len(vulns)}",
        "ransomware_campaign_use": {str(k): int(v) for k, v in ransomware_dist.items()},
        "kev_date_added_year_distribution": {str(k): int(v) for k, v in year_added_dist.items()},
        "kev_by_cve_publication_year": {str(k): int(v) for k, v in pub_year_kev_dist.items()},
        "publication_to_kev_added_timing_days": {
            "min": round(float(delay_valid.min()), 1),
            "max": round(float(delay_valid.max()), 1),
            "mean": round(float(delay_valid.mean()), 1),
            "median": round(float(delay_valid.median()), 1),
            "p25": round(float(delay_valid.quantile(0.25)), 1),
            "p75": round(float(delay_valid.quantile(0.75)), 1),
            "added_before_nvd_publication_count": negative_delay,
            "within_30_days_count": within_30d,
            "within_90_days_count": within_90d,
            "within_365_days_count": within_365d,
            "over_365_days_count": over_1yr,
        }
    }


def analyze_temporal_structure(vulns, epss, kev):
    print("\n--- Analyzing Temporal Structure & Year Distributions ---")
    years = sorted(vulns["publication_year"].unique())
    
    vuln_epss_set = set(epss["cve_id"])
    vuln_kev_set = set(kev["cve_id"])
    
    yearly_breakdown = {}
    for y in years:
        sub = vulns[vulns["publication_year"] == y]
        cve_count = int(len(sub))
        
        cve_ids = set(sub["cve_id"])
        
        v2_count = int(sub["cvss_v2_base_score"].notna().sum())
        v30_count = int(sub["cvss_v30_base_score"].notna().sum())
        v31_count = int(sub["cvss_v31_base_score"].notna().sum())
        v40_count = int(sub["cvss_v40_base_score"].notna().sum())
        
        epss_count = int(len(cve_ids.intersection(vuln_epss_set)))
        kev_count = int(len(cve_ids.intersection(vuln_kev_set)))
        
        yearly_breakdown[int(y)] = {
            "total_cves": cve_count,
            "cvss_v2": v2_count,
            "cvss_v30": v30_count,
            "cvss_v31": v31_count,
            "cvss_v40": v40_count,
            "epss_coverage": epss_count,
            "kev_count": kev_count,
        }
        
    return yearly_breakdown


def main():
    vulns, cwe, cpe, epss, kev, vendor = load_datasets()
    
    results = {
        "cvss": analyze_cvss(vulns),
        "descriptions": analyze_descriptions(vulns),
        "cwe": analyze_cwe(vulns, cwe),
        "cpe": analyze_cpe(vulns, cpe),
        "epss": analyze_epss(vulns, epss),
        "kev": analyze_kev(vulns, kev),
        "temporal_yearly_breakdown": analyze_temporal_structure(vulns, epss, kev)
    }
    
    out_file = OUTPUT_DIR / "phase2_metrics.json"
    with open(out_file, "w") as f:
        json.dump(results, f, indent=2)
        
    print(f"\nCharacterization complete. Metrics saved to {out_file}")


if __name__ == "__main__":
    main()
