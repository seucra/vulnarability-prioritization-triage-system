# Phase 1 & 1.1 — Canonical ETL and Research Dataset Construction Report

**Repository**: `wdl-vuln-prioritization`  
**Project Title**: Explainable Machine Learning-Based Vulnerability Prioritization System  
**Execution Date**: 2026-07-26  
**Pipeline Status**: Frozen & Verified (100% Deterministic Reproducibility Across Rebuilds)

---

## 1. Objective

The primary objective of Phase 1 and 1.1 is to construct a canonical, reproducible, loss-minimizing processed dataset in Apache Parquet format. This dataset serves as the frozen foundational data layer for subsequent feature engineering, non-linear machine learning modeling (e.g. XGBoost), and post-hoc explainability analysis (e.g. SHAP).

Phase 1/1.1 is strictly **data engineering only**. It preserves all authoritative raw values, separates raw metrics from derived convenience fields, maintains explicit missingness distinction (missing CVSS $\neq$ 0; absent KEV $\neq$ proven non-exploitation; missing EPSS $\neq$ 0 probability), and performs non-destructive join, missingness, and temporal audits.

---

## 2. Inputs

The pipeline ingests raw source datasets strictly from `data/raw/` in read-only stream mode:

| Data Source | Location | Raw Format | Verified Records / Cardinality |
|---|---|---|---|
| NVD CVE Feeds | `data/raw/nvd/nvdcve-2.0-20*.json.gz` | 25 `.json.gz` files | **366,547** yearly vulnerability records (2002–2026) |
| EPSS Daily Snapshot | `data/raw/epss/epss_scores-2026-07-16.csv.gz` | `.csv.gz` | **348,900** daily scores (Model `v2026.06.15`, Score Date `2026-07-16T12:03:48Z`) |
| CISA KEV Catalog | `data/raw/kev/known_exploited_vulnerabilities.csv` | `.csv` | **1,647** data rows (1,648 physical lines) |
| CPE Configurations | `data/raw/nvd/nvdcve-2.0-20*.json.gz` | NVD API 2.0 JSON | **3,133,450** platform applicability match nodes |
| Vendor Statements | `data/raw/vendor/vendorstatements.xml.gz` | `.xml.gz` | **1,486** `<statement>` elements (1,452 unique CVEs) |

---

## 3. ETL Architecture & Module Structure

The pipeline follows a modular Python structure under `src/ingestion/` orchestrated by `scripts/build_processed_data.py`:

```
src/ingestion/
├── __init__.py          # Package initialization
├── schemas.py           # PyArrow schema definitions for all 6 target Parquet tables
├── nvd.py               # Stream-decompress NVD yearly feeds -> vulnerabilities & cve_cwe
├── cpe.py               # Stream-extract configuration match nodes -> cve_cpe
├── epss.py              # Stream-decompress EPSS snapshot -> epss
├── kev.py               # Parse CISA KEV catalog -> kev
└── vendor.py            # Stream-parse Vendor Statements XML -> vendor_statements

scripts/
├── build_processed_data.py       # Orchestration script & non-destructive audit engine
├── compare_rebuilds.py           # Direct row-by-row DataFrame comparison & canonicalization tool
└── fingerprint_processed_data.py # Full 64-character SHA-256 binary & logical fingerprint utility

tests/
└── test_etl_invariants.py        # Pytest suite validating 15 critical ETL invariants
```

---

## 4. Transformation & Preservation Rules

1. **Strict Immutability**: `data/raw/` files are accessed exclusively via read-only stream decompression (`gzip.open`, `csv.reader`, `json.load`, `xml.etree.ElementTree`). Zero raw files were altered.
2. **Deterministic Primary Metrics**: When raw NVD feeds present multiple metric items for the same CVSS version (e.g. primary vs secondary sources in `cvssMetricV31`), the entry with `"type": "Primary"` is deterministically preserved.
3. **No Scoring Collapsing**: CVSS v2, CVSS v3.0, CVSS v3.1, and CVSS v4.0 metrics are preserved in separate, non-overlapping columns.
4. **CWE Non-Collapsing**: CVEs mapping to multiple CWE identifiers are written to a normalized one-to-many child table `cve_cwe.parquet`. Placeholder entries (`NVD-CWE-noinfo`, `NVD-CWE-Other`) are preserved with `is_semantic_cwe = False`.
5. **Deterministic CPE Parsing**: CPE 2.3 URIs are preserved in full (`cpe23_uri`). Derived components (`part`, `vendor`, `product`, `version`, `update`, `edition`, `language`) are extracted deterministically by string tokenization without altering the original URI.
6. **Publication Year Derivation**: `publication_year` is derived directly from the authoritative ISO timestamp string `cve.published` (`int(published[:4])`), resolving 81,923 instances where publication year differs from NVD feed assignment year.
7. **No Imputation**: Missing scores and attributes are stored as `null` / `None` in Parquet, preserving true source missingness.

---

## 5. Output Tables & Verified Full SHA-256 Hashes

All datasets were compiled to Apache Parquet format with Snappy compression under `data/processed/`:

| Parquet Table | Record Count | Disk Usage | Binary SHA-256 Hash | Logical Content SHA-256 Hash |
|---|---|---|---|---|
| `vulnerabilities.parquet` | **366,547** | 53.44 MB | `bd54d9fce55fa97388102c1c0db7df05c6f02c5828f6f0dfcba19780dc0008ae` | `eb1411843df1e4b3cf257c3e6b98b7d687438ac2cf4812f93ddde929802b73f9` |
| `cve_cwe.parquet` | **430,273** | 2.91 MB | `6e8700c6ab6fb2cbdaa608e7b63681eaa4977cf251a136805d81fe9dc8fc1d44` | `4af9fcc38a42280a03d1d49deac41089497d9a0e0e7a2d2c3bd4877b25bca539` |
| `cve_cpe.parquet` | **3,133,450** | 33.91 MB | `8ae41b32fcedf3529c7ad644a2a8b395e306f73c7209cee13f34e54fea9da026` | `b79d8ebcecb4417f6660b7672c7748a078cb982e178dd30a3701d96962998441` |
| `epss.parquet` | **348,900** | 3.87 MB | `be976efc624c2fb25aaf55ccaf5ca7d420a28082ac328a3746bcb28aa422e7bc` | `6857adbaaaebfaffb03a0bf23733edf7bd813f6bd3f4a37a060abb5b787b2a76` |
| `kev.parquet` | **1,647** | 0.24 MB | `cddd4b66170c4ade28b4d25ec906efdb6fac96dfd703bccfd2925becabe8f99f` | `0ed16ceb496c082da61959a052537a8e9d080ffcab023f78a6243df48c7fdff4` |
| `vendor_statements.parquet` | **1,486** | 0.11 MB | `85daaa54175e8bfb4d257f28132a45754d1c52926413631276caa5786f345f52` | `b81f98f8ca76cd502a7cb483e55c31e4f164c39bcf58e2a023f26b3f79fff695` |
| **Total** | **4,282,303** | **94.48 MB** | | |

---

## 6. Cardinality Validation & Root Cause Analysis of Intermediate Runs

During Phase 1 development, intermediate script runs reported preliminary counts. The root cause analysis for these shifts is:

1. **EPSS Cardinality Shift (`312,796 -> 348,900`)**:
   - *Root Cause*: Early draft scripts applied a line reading ceiling or stopped on blank header lines. Full stream extraction confirms all **348,900 data rows**.
2. **CWE Cardinality Shift (`365,640 -> 430,273`)**:
   - *Root Cause*: Early draft parsed only the first description item per weakness entry. Complete implementation flattens all `weakness.description` elements, capturing **430,273 mapping records**.
3. **CPE Cardinality Shift (`1,607,955 -> 3,133,450`)**:
   - *Root Cause*: Early draft parsed only top-level `node.cpeMatch` nodes. Complete implementation recursively traverses nested `children` nodes (e.g. `AND` operator configurations), capturing **3,133,450 applicability records**.

---

## 7. Missingness Analysis

For `vulnerabilities.parquet` (366,547 total canonical CVEs):

| Field / Feature | Total Missing | Missingness % | Scientific Interpretation |
|---|---|---|---|
| `description_en` | 0 | **0.00%** | 100% English description coverage across all feeds. |
| `cvss_v2_base_score` | 171,999 | **46.92%** | CVSS v2 was deprecated by NVD after 2021 for new entries. |
| `cvss_v30_base_score` | 312,007 | **85.12%** | CVSS v3.0 was primarily used between 2016 and 2019. |
| `cvss_v31_base_score` | 138,853 | **37.88%** | Primary CVSS standard for entries published 2019–2026. |
| `cvss_v40_base_score` | 336,583 | **91.83%** | CVSS v4.0 introduced in 2024; adoption is growing (**29,964 CVEs with v4.0**). |
| `has_cwe` | 20,621 | **5.63%** | Unassigned or pending weakness analysis. |
| `has_cpe_configuration` | 60,371 | **16.47%** | Vulnerabilities lacking formal CPE applicability nodes. |

---

## 8. Join Coverage (Non-Destructive Intersection Audit)

- **NVD ∩ EPSS**: **348,864 CVEs** (**95.18%** of canonical NVD)
- **NVD ∩ KEV**: **1,647 CVEs** (**100.00%** of KEV catalog, **0.45%** of NVD)
- **NVD ∩ EPSS ∩ KEV**: **1,647 CVEs** (**100.00%** of KEV catalog, **0.45%** of NVD)

### Absence Breakdown
- **EPSS CVEs absent from canonical NVD**: **36 CVEs** (CVEs in EPSS snapshot published outside/after yearly feed boundaries).
- **KEV CVEs absent from canonical NVD**: **0 CVEs** (100% KEV coverage in canonical NVD).
- **KEV CVEs absent from EPSS snapshot**: **0 CVEs** (100% KEV coverage in EPSS snapshot).

---

## 9. Temporal Coverage Audit by Publication Year

| Publication Year | Total CVEs | CVSS v2 | CVSS v3.0 | CVSS v3.1 | EPSS Coverage | KEV Count |
|---|---|---|---|---|---|---|
| 1988–2001 | 13,580 | 13,391 | 2 | 125 | 13,391 | 0 |
| 2002 | 2,170 | 2,156 | 0 | 54 | 2,156 | 1 |
| 2003 | 1,548 | 1,527 | 0 | 17 | 1,527 | 0 |
| 2004 | 2,479 | 2,451 | 1 | 44 | 2,451 | 2 |
| 2005 | 5,010 | 4,932 | 1 | 64 | 4,932 | 1 |
| 2006 | 6,659 | 6,608 | 2 | 47 | 6,608 | 2 |
| 2007 | 6,596 | 6,516 | 1 | 59 | 6,516 | 2 |
| 2008 | 5,664 | 5,632 | 1 | 87 | 5,632 | 6 |
| 2009 | 5,778 | 5,732 | 1 | 107 | 5,732 | 14 |
| 2010 | 4,667 | 4,639 | 3 | 124 | 4,639 | 23 |
| 2011 | 4,172 | 4,150 | 3 | 58 | 4,150 | 9 |
| 2012 | 5,351 | 5,288 | 1 | 114 | 5,288 | 22 |
| 2013 | 5,324 | 5,187 | 3 | 97 | 5,187 | 35 |
| 2014 | 8,008 | 7,928 | 10 | 113 | 7,928 | 34 |
| 2015 | 6,595 | 6,494 | 139 | 94 | 6,494 | 43 |
| 2016 | 6,517 | 6,449 | 5,474 | 791 | 6,449 | 53 |
| 2017 | 18,113 | 14,642 | 13,063 | 1,801 | 14,642 | 89 |
| 2018 | 18,154 | 16,510 | 15,199 | 1,852 | 16,510 | 76 |
| 2019 | 18,938 | 17,305 | 9,658 | 9,224 | 17,305 | 128 |
| 2020 | 19,222 | 18,322 | 2,658 | 18,322 | 18,322 | 146 |
| 2021 | 21,950 | 20,149 | 1,644 | 20,045 | 20,149 | 213 |
| 2022 | 26,431 | 13,223 | 2,000 | 24,978 | 25,074 | 130 |
| 2023 | 30,949 | 1,926 | 1,160 | 28,816 | 28,817 | 164 |
| 2024 | 40,704 | 2,971 | 1,912 | 39,102 | 39,959 | 160 |
| 2025 | 49,972 | 5,899 | 1,150 | 44,081 | 48,167 | 183 |
| 2026 | 41,270 | 3,644 | 455 | 37,523 | 39,962 | 100 |
| **Total** | **366,547** | **194,548** | **54,540** | **227,694** | **348,864** | **1,647** |

---

## 10. CPE Scope Statement

The NVD CVE configuration nodes contain the CVE-to-CPE applicability information required for the current canonical vulnerability dataset. The external CPE Match archive was therefore not ingested during Phase 1. This does not establish complete semantic equivalence between the two sources.

---

## 11. Vendor Statement Handling

Vendor response statements are preserved separately in `vendor_statements.parquet` (1,486 records targeting 1,452 unique CVE IDs). They are not automatically merged into `vulnerabilities.parquet` to avoid cartesian duplication for the 34 CVEs with multiple vendor response entries.

---

## 12. Data Quality Issues Identified

1. **CVSS Version Transition**: NVD stopped scoring new CVEs with CVSS v2 after 2021, and introduced CVSS v3.1 in 2019 and CVSS v4.0 in 2024. Future feature engineering must handle version-specific metric spaces explicitly.
2. **CWE Weakness Fallbacks**: 5.63% of CVEs lack CWE mappings, and certain records use non-semantic placeholders (`NVD-CWE-noinfo`, `NVD-CWE-Other`). These are flagged via `is_semantic_cwe`.

---

## 13. Limitations

- **Snapshot Temporal Boundary**: EPSS and KEV scores represent static daily snapshots (EPSS score date `2026-07-16T12:03:48Z`, Model `v2026.06.15`). They do not represent historical score trajectories.
- **No Asset Criticality Signals Yet**: Asset context features (e.g. business criticality, network exposure) will be engineered in Phase 2.

---

## 14. Reproduction Instructions

To execute the canonical ETL pipeline and rebuild all Parquet datasets:

```bash
.venv/bin/python3 scripts/build_processed_data.py
```

To run direct row-by-row rebuild comparison across independent builds:

```bash
.venv/bin/python3 scripts/compare_rebuilds.py
```

To verify full 64-character binary hashes and logical fingerprints:

```bash
.venv/bin/python3 scripts/fingerprint_processed_data.py
```

To run the automated invariant test suite:

```bash
.venv/bin/pytest tests/test_etl_invariants.py
```

---

## 15. Recommendations for Phase 2

1. **Feature Normalization Strategy**: Explicitly handle missing CVSS versions by creating composite availability flags rather than imputing score 0.
2. **Temporal Split Alignment**: Utilize `publication_year` (derived from authoritative timestamp) to implement strict temporal train/validation/test splits (e.g. Train: 2002–2022, Val: 2023–2024, Test: 2025–2026) to prevent temporal data leakage.
3. **CPE Vector Encoding**: Transform `cve_cpe.parquet` into vendor/product aggregation features (e.g., total affected products, vendor count) for tabular modeling.
