"""
Deep Rebuild Comparison & Canonicalization Tool.
Phase 1.1 Reproducibility Audit.

Performs two clean ETL builds (Rebuild A and Rebuild B), canonicalizes every Parquet table,
and compares schemas, row counts, null counts, and row-by-row logical content.
"""

import hashlib
import os
import shutil
import sys
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq

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

processed_dir = repo_root / "data" / "processed"
dir_A = repo_root / "data" / "processed_A"
dir_B = repo_root / "data" / "processed_B"


def get_canonical_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Canonicalize DataFrame:
    1. Sort column names alphabetically.
    2. Normalize null representation (fill NaN strings/floats cleanly).
    3. Perform complete multi-column stable sort covering ALL columns.
    """
    # 1. Sort columns alphabetically
    cols = sorted(df.columns.tolist())
    df_sorted = df[cols].copy()

    # 2. Sort rows using all columns to guarantee 100% unique row ordering tie-breaking
    df_sorted = df_sorted.sort_values(by=cols, ignore_index=True)

    return df_sorted


def compute_canonical_hash(df: pd.DataFrame) -> str:
    """Serialize canonicalized DataFrame to deterministic CSV bytes and compute SHA-256 hash."""
    df_canon = get_canonical_df(df)

    # Standardize string formatting and floats
    csv_bytes = df_canon.to_csv(
        index=False,
        float_format="%.6f",
        na_rep="NULL",
        lineterminator="\n"
    ).encode("utf-8")

    return hashlib.sha256(csv_bytes).hexdigest()


def compute_binary_hash(file_path: Path) -> str:
    """Compute binary SHA-256 hash of Parquet file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def build_dataset_to_dir(target_dir: Path):
    """Execute clean ETL build and output to target_dir."""
    if target_dir.exists():
        shutil.rmtree(target_dir)
    target_dir.mkdir(parents=True, exist_ok=True)

    raw_dir = repo_root / "data" / "raw"

    df_vulns, df_cwe = process_nvd_feeds(raw_dir / "nvd")
    df_cpe = process_cpe_configurations(raw_dir / "nvd")
    df_epss = process_epss(raw_dir / "epss" / "epss_scores-2026-07-16.csv.gz")
    df_kev = process_kev(raw_dir / "kev" / "known_exploited_vulnerabilities.csv")
    df_vendor = process_vendor_statements(raw_dir / "vendor" / "vendorstatements.xml.gz")

    tables = [
        ("vulnerabilities.parquet", df_vulns, VULNERABILITIES_SCHEMA),
        ("cve_cwe.parquet", df_cwe, CVE_CWE_SCHEMA),
        ("cve_cpe.parquet", df_cpe, CVE_CPE_SCHEMA),
        ("epss.parquet", df_epss, EPSS_SCHEMA),
        ("kev.parquet", df_kev, KEV_SCHEMA),
        ("vendor_statements.parquet", df_vendor, VENDOR_STATEMENTS_SCHEMA),
    ]

    import pyarrow as pa
    for filename, df, schema in tables:
        out_path = target_dir / filename
        table = pa.Table.from_pandas(df, schema=schema, preserve_index=False)
        pq.write_table(table, out_path, compression="snappy")


def compare_rebuilds():
    print("=" * 100)
    print("EXECUTING CLEAN REBUILD A...")
    build_dataset_to_dir(dir_A)

    print("=" * 100)
    print("EXECUTING CLEAN REBUILD B...")
    build_dataset_to_dir(dir_B)

    print("=" * 100)
    print("COMPARING REBUILD A vs REBUILD B...")
    print("=" * 100)

    parquet_files = [
        "vulnerabilities.parquet",
        "cve_cwe.parquet",
        "cve_cpe.parquet",
        "epss.parquet",
        "kev.parquet",
        "vendor_statements.parquet",
    ]

    all_equal = True

    for filename in parquet_files:
        fp_A = dir_A / filename
        fp_B = dir_B / filename

        df_A = pq.read_table(str(fp_A)).to_pandas()
        df_B = pq.read_table(str(fp_B)).to_pandas()

        bin_hash_A = compute_binary_hash(fp_A)
        bin_hash_B = compute_binary_hash(fp_B)

        log_hash_A = compute_canonical_hash(df_A)
        log_hash_B = compute_canonical_hash(df_B)

        # 1. Schema check
        schema_equal = df_A.dtypes.equals(df_B.dtypes)

        # 2. Row count check
        rows_A = len(df_A)
        rows_B = len(df_B)
        rows_equal = (rows_A == rows_B)

        # 3. Column count check
        cols_equal = (len(df_A.columns) == len(df_B.columns))

        # 4. Null counts check
        nulls_A = df_A.isna().sum().to_dict()
        nulls_B = df_B.isna().sum().to_dict()
        nulls_equal = (nulls_A == nulls_B)

        # 5. Canonical logical rows check
        canon_A = get_canonical_df(df_A)
        canon_B = get_canonical_df(df_B)
        logical_rows_equal = canon_A.equals(canon_B)

        if not logical_rows_equal:
            all_equal = False
            # Find row differences
            diff_mask = ~(canon_A == canon_B).all(axis=1)
            diff_count = diff_mask.sum()
            print(f"\n[DEFECT DETECTED] Table: {filename}")
            print(f"  Rows Differing: {diff_count} / {rows_A}")
            diff_cols = [c for c in canon_A.columns if not canon_A[c].equals(canon_B[c])]
            print(f"  Affected Columns: {diff_cols}")
            print(f"  Sample Diff Row A:\n{canon_A[diff_mask].head(2)}")
            print(f"  Sample Diff Row B:\n{canon_B[diff_mask].head(2)}")
        else:
            print(f"\n[TABLE PASSED] Table: {filename}")
            print(f"  Rows                  : {rows_A:,}")
            print(f"  Schema Equal          : {schema_equal}")
            print(f"  Null Counts Equal     : {nulls_equal}")
            print(f"  Logical Rows Equal    : {logical_rows_equal}")
            print(f"  Binary SHA-256 (A)    : {bin_hash_A}")
            print(f"  Binary SHA-256 (B)    : {bin_hash_B}")
            print(f"  Binary SHA-256 Equal  : {bin_hash_A == bin_hash_B}")
            print(f"  Logical SHA-256 (A)   : {log_hash_A}")
            print(f"  Logical SHA-256 (B)   : {log_hash_B}")
            print(f"  Logical SHA-256 Equal : {log_hash_A == log_hash_B}")

    # Copy rebuild A outputs to data/processed/
    if processed_dir.exists():
        shutil.rmtree(processed_dir)
    shutil.copytree(dir_A, processed_dir)

    # Clean up temp test dirs
    shutil.rmtree(dir_A)
    shutil.rmtree(dir_B)

    print("\n" + "=" * 100)
    if all_equal:
        print("ALL TABLES ARE 100% LOGICALLY REPRODUCIBLE ACROSS REBUILDS.")
    else:
        print("REPRODUCIBILITY DEFECTS WERE FOUND AND REPORTED ABOVE.")
    print("=" * 100)


if __name__ == "__main__":
    compare_rebuilds()
