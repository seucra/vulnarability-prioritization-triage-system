# Phase 1 & 1.1 — Walkthrough & Verification Summary

**Repository**: `wdl-vuln-prioritization`  
**Status**: Phase 1.1 Complete (ETL Reproducibility, Consistency and Dataset Freeze)

---

## 1. Processed Datasets Constructed (`data/processed/`)

All canonical datasets were extracted directly from the read-only raw feeds and compiled into Apache Parquet format with PyArrow schema validation and Snappy compression:

| Parquet Dataset | Record Count / Rows | Disk Size | Target Schema & Description |
|---|---|---|---|
| `vulnerabilities.parquet` | **366,547** | 53.44 MB | Canonical NVD CVE table (one row per unique CVE ID across 25 yearly feeds 2002–2026). Preserves CVSS v2, v3.0, v3.1, v4.0 metrics separately. |
| `cve_cwe.parquet` | **430,273** | 2.91 MB | Normalized one-to-many weakness taxonomy mapping table. Preserves semantic vs placeholder CWE status (`is_semantic_cwe`). |
| `cve_cpe.parquet` | **3,133,450** | 33.91 MB | Normalized one-to-many platform applicability match table. Preserves CPE 2.3 URIs, version bounds, and parsed CPE components. |
| `epss.parquet` | **348,900** | 3.87 MB | Daily EPSS snapshot scores and percentiles (Snapshot Date: `2026-07-16T12:03:48Z`, Model: `v2026.06.15`). |
| `kev.parquet` | **1,647** | 0.24 MB | CISA Known Exploited Vulnerabilities catalog (1,647 unique CVE IDs, 100% field completeness). |
| `vendor_statements.parquet` | **1,486** | 0.11 MB | NVD official vendor vulnerability response statements (1,486 elements targeting 1,452 unique CVE IDs). |
| **Total** | **4,282,303** | **94.48 MB** | |

---

## 2. Non-Destructive Join Audit Results

- **NVD ∩ EPSS**: **348,864 CVEs** (95.18% of canonical NVD)
- **NVD ∩ KEV**: **1,647 CVEs** (100.00% of KEV catalog, 0.45% of NVD)
- **NVD ∩ EPSS ∩ KEV**: **1,647 CVEs** (100.00% of KEV catalog, 0.45% of NVD)
- **EPSS CVEs absent from canonical NVD**: **36 CVEs**
- **KEV CVEs absent from canonical NVD**: **0 CVEs**
- **KEV CVEs absent from EPSS snapshot**: **0 CVEs**

---

## 3. Phase 1.1 Reproducibility Audit (Rebuild #1 vs Rebuild #2)

Across two completely independent clean rebuilds (`rm -f data/processed/*.parquet && .venv/bin/python3 scripts/build_processed_data.py`), logical content fingerprints matched 100% deterministically:

| Parquet File | Rows | Rebuild #1 SHA-256 (Prefix) | Rebuild #2 SHA-256 (Prefix) | Rebuild #1 Fingerprint (Prefix) | Rebuild #2 Fingerprint (Prefix) | Logical Equivalence |
|---|---|---|---|---|---|---|
| `vulnerabilities.parquet` | 366,547 | `bd54d9fce55fa973` | `bd54d9fce55fa973` | `ce61fd6a3cf878f1` | `ce61fd6a3cf878f1` | **100% Identical** |
| `cve_cwe.parquet` | 430,273 | `6e8700c6ab6fb2cb` | `6e8700c6ab6fb2cb` | `4af9fcc38a42280a` | `4af9fcc38a42280a` | **100% Identical** |
| `cve_cpe.parquet` | 3,133,450 | `8ae41b32fcedf352` | `8ae41b32fcedf352` | `98f256472ed530c1` | `98f256472ed530c1` | **100% Identical** |
| `epss.parquet` | 348,900 | `be976efc624c2fb2` | `be976efc624c2fb2` | `6857adbaaaebfaff` | `6857adbaaaebfaff` | **100% Identical** |
| `kev.parquet` | 1,647 | `cddd4b66170c4ade` | `cddd4b66170c4ade` | `0ed16ceb496c082d` | `0ed16ceb496c082d` | **100% Identical** |
| `vendor_statements.parquet` | 1,486 | `85daaa54175e8bfb` | `85daaa54175e8bfb` | `2fda087a590a1f11` | `2fda087a590a1f11` | **100% Identical** |

---

## 4. Automated Test Suite Verification

All 15 critical ETL data engineering and research integrity invariants passed in Pytest:

```bash
.venv/bin/pytest tests/test_etl_invariants.py
```

Result: `15 passed in 10.69s` (100% success rate).

---

## 5. Reproduction Command

To reproduce the canonical ETL build from raw source data:

```bash
.venv/bin/python3 scripts/build_processed_data.py
```
