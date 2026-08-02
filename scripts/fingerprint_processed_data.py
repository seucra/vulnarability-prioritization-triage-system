"""
Fingerprint Utility for Processed Datasets.
Calculates file sizes, SHA-256 binary hashes, and deterministic logical content fingerprints.
"""

import hashlib
import sys
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq

repo_root = Path(__file__).resolve().parent.parent
processed_dir = repo_root / "data" / "processed"


def get_canonical_df(df: pd.DataFrame) -> pd.DataFrame:
    """
    Canonicalize DataFrame for deterministic hashing:
    1. Sort column names alphabetically.
    2. Sort rows using ALL columns as stable tie-breaker.
    """
    cols = sorted(df.columns.tolist())
    df_sorted = df[cols].copy()
    df_sorted = df_sorted.sort_values(by=cols, ignore_index=True)
    return df_sorted


def calculate_logical_fingerprint(file_path: Path) -> str:
    """Compute deterministic SHA-256 hash of canonicalized DataFrame values."""
    df = pq.read_table(str(file_path)).to_pandas()
    df_canon = get_canonical_df(df)
    csv_bytes = df_canon.to_csv(
        index=False,
        float_format="%.6f",
        na_rep="NULL",
        lineterminator="\n"
    ).encode("utf-8")
    return hashlib.sha256(csv_bytes).hexdigest()


def calculate_binary_hash(file_path: Path) -> str:
    """Compute binary SHA-256 hash of file."""
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return sha256.hexdigest()


def main():
    print("=" * 140)
    print(f"{'File Name':<27} | {'Rows':>9} | {'Cols':>4} | {'Size (MB)':>9} | {'Binary SHA-256 Hash':<64} | {'Logical Content SHA-256 Hash'}")
    print("=" * 140)

    for fp in sorted(processed_dir.glob("*.parquet")):
        table = pq.read_table(str(fp))
        rows = table.num_rows
        cols = table.num_columns
        size_mb = fp.stat().st_size / (1024 * 1024)
        bin_hash = calculate_binary_hash(fp)
        log_hash = calculate_logical_fingerprint(fp)
        print(f"{fp.name:<27} | {rows:>9,} | {cols:>4} | {size_mb:>9.2f} | {bin_hash} | {log_hash}")

    print("=" * 140)


if __name__ == "__main__":
    main()
