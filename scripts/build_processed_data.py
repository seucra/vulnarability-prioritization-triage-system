#!/usr/bin/env python3
"""
Orchestrator Script for Phase 1 Canonical ETL Pipeline.
Repository: wdl-vuln-prioritization

Reads raw data from data/raw/ and constructs canonical, loss-minimizing Parquet datasets in data/processed/.
Performs dataset-level join audits, missingness analysis, and temporal coverage checks.
"""

import sys
import logging
import time
from pathlib import Path

import pyarrow as pa
import pyarrow.parquet as pq
import pandas as pd

# Add src to sys.path
repo_root = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(repo_root / "src"))

from ingestion.nvd import process_nvd_feeds
from ingestion.cpe import process_cpe_configurations
from ingestion.epss import process_epss
from ingestion.kev import process_kev
from ingestion.vendor import process_vendor_statements
from ingestion.schemas import (
    VULNERABILITIES_SCHEMA,
    CVE_CWE_SCHEMA,
    CVE_CPE_SCHEMA,
    EPSS_SCHEMA,
    KEV_SCHEMA,
    VENDOR_STATEMENTS_SCHEMA,
)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)
logger = logging.getLogger("ETL_Orchestrator")


def main():
    start_time = time.time()

    raw_dir = repo_root / "data" / "raw"
    processed_dir = repo_root / "data" / "processed"
    processed_dir.mkdir(parents=True, exist_ok=True)

    logger.info("=" * 80)
    print("PHASE 1: CANONICAL ETL AND RESEARCH DATASET CONSTRUCTION")
    logger.info(f"Repository Root: {repo_root}")
    logger.info(f"Raw Data Dir   : {raw_dir}")
    logger.info(f"Processed Dir  : {processed_dir}")
    logger.info("=" * 80)

    # 1. Ingest NVD Feeds (Vulnerabilities & CWE)
    logger.info("\n--- STEP 1: Processing NVD CVE Yearly Feeds ---")
    df_vulns, df_cwe = process_nvd_feeds(raw_dir / "nvd")

    # 2. Ingest CPE Configurations
    logger.info("\n--- STEP 2: Processing CPE Platform Configurations ---")
    df_cpe = process_cpe_configurations(raw_dir / "nvd")

    # 3. Ingest EPSS Snapshot
    logger.info("\n--- STEP 3: Processing EPSS Snapshot ---")
    df_epss = process_epss(raw_dir / "epss" / "epss_scores-2026-07-16.csv.gz")

    # 4. Ingest CISA KEV Catalog
    logger.info("\n--- STEP 4: Processing CISA KEV Catalog ---")
    df_kev = process_kev(raw_dir / "kev" / "known_exploited_vulnerabilities.csv")

    # 5. Ingest Vendor Statements
    logger.info("\n--- STEP 5: Processing Vendor Statements ---")
    df_vendor = process_vendor_statements(raw_dir / "vendor" / "vendorstatements.xml.gz")

    # 6. Write Parquet Datasets
    logger.info("\n--- STEP 6: Writing Parquet Datasets with PyArrow Schemas ---")

    tables = [
        ("vulnerabilities.parquet", df_vulns, VULNERABILITIES_SCHEMA),
        ("cve_cwe.parquet", df_cwe, CVE_CWE_SCHEMA),
        ("cve_cpe.parquet", df_cpe, CVE_CPE_SCHEMA),
        ("epss.parquet", df_epss, EPSS_SCHEMA),
        ("kev.parquet", df_kev, KEV_SCHEMA),
        ("vendor_statements.parquet", df_vendor, VENDOR_STATEMENTS_SCHEMA),
    ]

    for filename, df, schema in tables:
        out_path = processed_dir / filename
        table = pa.Table.from_pandas(df, schema=schema, preserve_index=False)
        pq.write_table(table, out_path, compression="snappy")
        sz = out_path.stat().st_size
        logger.info(f"Wrote {filename:<25} | Rows: {len(df):>10,} | Disk Size: {sz / (1024*1024):>6.2f} MB")

    # 7. Dataset-Level Join Audit
    logger.info("\n--- STEP 7: Dataset-Level Join Audit ---")
    nvd_cves = set(df_vulns["cve_id"])
    epss_cves = set(df_epss["cve_id"])
    kev_cves = set(df_kev["cve_id"])

    nvd_cap_epss = nvd_cves.intersection(epss_cves)
    nvd_cap_kev = nvd_cves.intersection(kev_cves)
    nvd_cap_epss_cap_kev = nvd_cves.intersection(epss_cves).intersection(kev_cves)

    epss_absent_nvd = epss_cves - nvd_cves
    kev_absent_nvd = kev_cves - nvd_cves
    kev_absent_epss = kev_cves - epss_cves

    print("\nIntersection Summary:")
    print(f"  NVD ∩ EPSS         : {len(nvd_cap_epss):>10,} ({len(nvd_cap_epss)/len(nvd_cves)*100:.2f}% of NVD)")
    print(f"  NVD ∩ KEV          : {len(nvd_cap_kev):>10,} ({len(nvd_cap_kev)/len(nvd_cves)*100:.2f}% of NVD)")
    print(f"  NVD ∩ EPSS ∩ KEV   : {len(nvd_cap_epss_cap_kev):>10,} ({len(nvd_cap_epss_cap_kev)/len(nvd_cves)*100:.2f}% of NVD)")

    print("\nAbsence Summary:")
    print(f"  EPSS CVEs absent from canonical NVD : {len(epss_absent_nvd):>10,}")
    print(f"  KEV CVEs absent from canonical NVD  : {len(kev_absent_nvd):>10,}")
    print(f"  KEV CVEs absent from EPSS snapshot  : {len(kev_absent_epss):>10,}")

    # 8. Missingness Audit
    logger.info("\n--- STEP 8: Vulnerabilities Missingness Audit ---")
    total_nvd = len(df_vulns)
    missing_fields = [
        ("description_en", df_vulns["description_en"].isna().sum()),
        ("CVSS v2", df_vulns["cvss_v2_base_score"].isna().sum()),
        ("CVSS v3.0", df_vulns["cvss_v30_base_score"].isna().sum()),
        ("CVSS v3.1", df_vulns["cvss_v31_base_score"].isna().sum()),
        ("CVSS v4.0", df_vulns["cvss_v40_base_score"].isna().sum()),
        ("CWE (has_cwe=False)", (~df_vulns["has_cwe"]).sum()),
        ("CPE Config (has_cpe=False)", (~df_vulns["has_cpe_configuration"]).sum()),
    ]

    print(f"Total Canonical Vulnerabilities: {total_nvd:,}")
    for name, cnt in missing_fields:
        pct = (cnt / total_nvd) * 100
        print(f"  Missing {name:<25}: {cnt:>10,} / {total_nvd:,} ({pct:>6.2f}%)")

    # 9. Temporal Audit by Publication Year
    logger.info("\n--- STEP 9: Temporal Audit by Publication Year ---")
    yearly_grp = df_vulns.groupby("publication_year")

    temp_audit = []
    for yr, group in yearly_grp:
        g_cves = set(group["cve_id"])
        c_tot = len(group)
        c_v2 = group["has_cvss_v2"].sum()
        c_v30 = group["has_cvss_v30"].sum()
        c_v31 = group["has_cvss_v31"].sum()
        c_epss = len(g_cves.intersection(epss_cves))
        c_kev = len(g_cves.intersection(kev_cves))
        temp_audit.append({
            "Year": yr,
            "CVE Count": c_tot,
            "CVSS v2": c_v2,
            "CVSS v3.0": c_v30,
            "CVSS v3.1": c_v31,
            "EPSS Count": c_epss,
            "KEV Count": c_kev,
        })

    df_temp = pd.DataFrame(temp_audit)
    print("\n" + df_temp.to_string(index=False))

    elapsed = time.time() - start_time
    logger.info("\n" + "=" * 80)
    logger.info(f"CANONICAL ETL COMPLETED SUCCESSFULLY in {elapsed:.2f} seconds.")
    logger.info("=" * 80)


if __name__ == "__main__":
    main()
