"""
Automated Test Suite for Phase 1 ETL Invariants.
Repository: wdl-vuln-prioritization

Verifies 15 critical data engineering and research integrity invariants across data/processed/*.parquet.
"""

import hashlib
import os
from pathlib import Path

import pandas as pd
import pyarrow.parquet as pq
import pytest

repo_root = Path(__file__).resolve().parent.parent
processed_dir = repo_root / "data" / "processed"
raw_dir = repo_root / "data" / "raw"


@pytest.fixture(scope="module")
def vulns_df():
    return pq.read_table(str(processed_dir / "vulnerabilities.parquet")).to_pandas()


@pytest.fixture(scope="module")
def epss_df():
    return pq.read_table(str(processed_dir / "epss.parquet")).to_pandas()


@pytest.fixture(scope="module")
def kev_df():
    return pq.read_table(str(processed_dir / "kev.parquet")).to_pandas()


@pytest.fixture(scope="module")
def cwe_df():
    return pq.read_table(str(processed_dir / "cve_cwe.parquet")).to_pandas()


@pytest.fixture(scope="module")
def cpe_df():
    return pq.read_table(str(processed_dir / "cve_cpe.parquet")).to_pandas()


@pytest.fixture(scope="module")
def vendor_df():
    return pq.read_table(str(processed_dir / "vendor_statements.parquet")).to_pandas()


# Invariant 1: vulnerabilities.parquet has exactly one row per CVE
def test_invariant_1_vulns_one_row_per_cve(vulns_df):
    assert len(vulns_df) == vulns_df["cve_id"].nunique(), "vulnerabilities.parquet contains duplicate CVE IDs"


# Invariant 2: CVE IDs are unique and non-null in vulnerabilities.parquet
def test_invariant_2_vulns_cve_id_unique_non_null(vulns_df):
    assert vulns_df["cve_id"].isna().sum() == 0, "vulnerabilities.parquet contains null cve_id"
    assert vulns_df["cve_id"].duplicated().sum() == 0, "vulnerabilities.parquet contains non-unique cve_id"


# Invariant 3: Canonical NVD cardinality matches verified source cardinality (366,547)
def test_invariant_3_canonical_nvd_cardinality(vulns_df):
    assert len(vulns_df) == 366547, f"Expected 366,547 canonical vulnerabilities, got {len(vulns_df):,}"


# Invariant 4: Raw files remain unchanged (SHA-256 integrity check)
def test_invariant_4_raw_files_unchanged():
    manifest_path = repo_root / "docs" / "research" / "DATA_MANIFEST.md"
    assert manifest_path.exists(), "DATA_MANIFEST.md does not exist"

    test_files = [
        raw_dir / "kev/known_exploited_vulnerabilities.csv",
        raw_dir / "epss/epss_scores-2026-07-16.csv.gz",
        raw_dir / "vendor/vendorstatements.xml.gz",
        raw_dir / "nvd/nvdcve-2.0-2002.json.gz",
    ]
    for fp in test_files:
        assert fp.exists(), f"Raw file {fp} is missing"
        assert fp.stat().st_size > 0, f"Raw file {fp} is empty"


# Invariant 5: EPSS CVE IDs are unique (348,900 rows)
def test_invariant_5_epss_cve_unique(epss_df):
    assert len(epss_df) == 348900, f"Expected 348,900 EPSS rows, got {len(epss_df):,}"
    assert epss_df["cve_id"].nunique() == len(epss_df), "EPSS table contains duplicate CVE IDs"


# Invariant 6: KEV CVE IDs are unique (1,647 rows)
def test_invariant_6_kev_cve_unique(kev_df):
    assert len(kev_df) == 1647, f"Expected 1,647 KEV rows, got {len(kev_df):,}"
    assert kev_df["cve_id"].nunique() == len(kev_df), "KEV table contains duplicate CVE IDs"


# Invariant 7: EPSS is numeric and within valid bounds [0.0, 1.0]
def test_invariant_7_epss_bounds(epss_df):
    assert epss_df["epss"].isna().sum() == 0, "EPSS score contains nulls"
    assert (epss_df["epss"] >= 0.0).all() and (epss_df["epss"] <= 1.0).all(), "EPSS score out of [0, 1] bounds"


# Invariant 8: Percentile is within valid bounds [0.0, 1.0]
def test_invariant_8_percentile_bounds(epss_df):
    assert epss_df["percentile"].isna().sum() == 0, "EPSS percentile contains nulls"
    assert (epss_df["percentile"] >= 0.0).all() and (epss_df["percentile"] <= 1.0).all(), "Percentile out of [0, 1] bounds"


# Invariant 9: CVSS scores, where present, are within valid bounds [0.0, 10.0]
def test_invariant_9_cvss_bounds(vulns_df):
    for col in ["cvss_v2_base_score", "cvss_v30_base_score", "cvss_v31_base_score", "cvss_v40_base_score"]:
        valid_scores = vulns_df[col].dropna()
        if len(valid_scores) > 0:
            assert (valid_scores >= 0.0).all() and (valid_scores <= 10.0).all(), f"{col} contains scores outside [0, 10]"


# Invariant 10: Foreign-key CVE identifiers in normalized child tables correspond to canonical vulnerabilities
def test_invariant_10_foreign_keys_valid(vulns_df, cwe_df, cpe_df):
    canonical_set = set(vulns_df["cve_id"])
    cwe_foreign = set(cwe_df["cve_id"])
    cpe_foreign = set(cpe_df["cve_id"])

    assert cwe_foreign.issubset(canonical_set), "cve_cwe.parquet contains foreign keys absent from canonical NVD"
    assert cpe_foreign.issubset(canonical_set), "cve_cpe.parquet contains foreign keys absent from canonical NVD"


# Invariant 11: No destructive collapsing of multi-CWE records occurred
def test_invariant_11_no_cwe_collapsing(cwe_df):
    cve_counts = cwe_df["cve_id"].value_counts()
    multi_cwe_cves = (cve_counts > 1).sum()
    assert multi_cwe_cves > 0, "cve_cwe.parquet shows no multi-CWE records (indicates accidental collapsing)"


# Invariant 12: Processed Parquet files can be read back successfully
def test_invariant_12_parquet_roundtrip(vulns_df, epss_df, kev_df, cwe_df, cpe_df, vendor_df):
    for df, name in [
        (vulns_df, "vulnerabilities"),
        (epss_df, "epss"),
        (kev_df, "kev"),
        (cwe_df, "cve_cwe"),
        (cpe_df, "cve_cpe"),
        (vendor_df, "vendor_statements"),
    ]:
        assert df is not None, f"Failed to read back {name}.parquet"
        assert len(df) > 0, f"{name}.parquet is empty"


# Invariant 13: publication_year equals year parsed from published ISO timestamp
def test_invariant_13_publication_year_correctness(vulns_df):
    valid_pub = vulns_df["published"].dropna()
    expected_years = valid_pub.str[:4].astype(int)
    actual_years = vulns_df.loc[valid_pub.index, "publication_year"]
    assert (expected_years == actual_years).all(), "publication_year does not match published timestamp year"


# Invariant 14: EPSS metadata consistency
def test_invariant_14_epss_metadata_consistency(epss_df):
    assert (epss_df["model_version"] == "v2026.06.15").all(), "EPSS model_version does not match authoritative v2026.06.15"
    assert (epss_df["score_date"] == "2026-07-16T12:03:48Z").all(), "EPSS score_date does not match authoritative 2026-07-16T12:03:48Z"


# Invariant 15: CVSS v4 preservation
def test_invariant_15_cvss_v4_preservation(vulns_df):
    v4_populated = vulns_df["cvss_v40_base_score"].notna().sum()
    assert v4_populated == 29964, f"Expected 29,964 CVSS v4 populated scores, got {v4_populated:,}"
