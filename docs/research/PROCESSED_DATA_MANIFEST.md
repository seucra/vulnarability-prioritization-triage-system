# Processed Data Freeze Manifest (Phase 1.1 Verified Dataset Freeze)

**Repository**: `wdl-vuln-prioritization`  
**Phase**: Phase 1.1 — ETL Reproducibility, Consistency and Dataset Freeze  
**Freeze Date**: 2026-07-26  
**ETL Status**: Frozen & Verified (100% Deterministic Reproducibility Across Clean Builds)

---

## 1. Provenance & Execution Environment

- **Execution Command**: `.venv/bin/python3 scripts/build_processed_data.py`
- **Comparison & Verification Tool**: `scripts/compare_rebuilds.py`
- **Validation Command**: `.venv/bin/pytest tests/test_etl_invariants.py`
- **Python Version**: `3.14.6`
- **Pandas Version**: `3.0.5`
- **PyArrow Version**: `25.0.0`
- **Git Branch**: `main` (clean working directory; raw and processed datasets Git-ignored)
- **Raw Data Snapshot Identity**: 32 raw files in `data/raw/` (cryptographically verified in `docs/research/DATA_MANIFEST.md`)

---

## 2. Processed Parquet Datasets (Verified Hashes & Fingerprints)

| File Name | Row Count | Column Count | Byte Size | Binary SHA-256 Hash | Logical Content SHA-256 Hash |
|---|---|---|---|---|---|
| `vulnerabilities.parquet` | **366,547** | 24 | 56,040,589 | `bd54d9fce55fa97388102c1c0db7df05c6f02c5828f6f0dfcba19780dc0008ae` | `eb1411843df1e4b3cf257c3e6b98b7d687438ac2cf4812f93ddde929802b73f9` |
| `cve_cwe.parquet` | **430,273** | 5 | 3,050,045 | `6e8700c6ab6fb2cbdaa608e7b63681eaa4977cf251a136805d81fe9dc8fc1d44` | `4af9fcc38a42280a03d1d49deac41089497d9a0e0e7a2d2c3bd4877b25bca539` |
| `cve_cpe.parquet` | **3,133,450** | 15 | 35,558,218 | `8ae41b32fcedf3529c7ad644a2a8b395e306f73c7209cee13f34e54fea9da026` | `b79d8ebcecb4417f6660b7672c7748a078cb982e178dd30a3701d96962998441` |
| `epss.parquet` | **348,900** | 5 | 4,058,614 | `be976efc624c2fb25aaf55ccaf5ca7d420a28082ac328a3746bcb28aa422e7bc` | `6857adbaaaebfaffb03a0bf23733edf7bd813f6bd3f4a37a060abb5b787b2a76` |
| `kev.parquet` | **1,647** | 11 | 256,263 | `cddd4b66170c4ade28b4d25ec906efdb6fac96dfd703bccfd2925becabe8f99f` | `0ed16ceb496c082da61959a052537a8e9d080ffcab023f78a6243df48c7fdff4` |
| `vendor_statements.parquet` | **1,486** | 5 | 114,691 | `85daaa54175e8bfb4d257f28132a45754d1c52926413631276caa5786f345f52` | `b81f98f8ca76cd502a7cb483e55c31e4f164c39bcf58e2a023f26b3f79fff695` |
| **Total** | **4,282,303** | | **99.08 MB** | | |

---

## 3. Authoritative EPSS Snapshot Metadata

- **Score Date**: `2026-07-16T12:03:48Z` (Snapshot Date: `2026-07-16`)
- **Model Version**: `v2026.06.15`
- **Source**: `data/raw/epss/epss_scores-2026-07-16.csv.gz` (Line 1 metadata header)

---

## 4. CVSS v4 Metric Verification

- **Total CVEs with `cvssMetricV40`**: **29,964**
- **Total CVSS v4 Metric Records**: **30,064**
- **Earliest Published Date with CVSS v4**: `2005-05-03T04:00:00.000`

---

## 5. CPE Scope Statement

The NVD CVE configuration nodes contain the CVE-to-CPE applicability information required for the current canonical vulnerability dataset. The external CPE Match archive was therefore not ingested during Phase 1. This does not establish complete semantic equivalence between the two sources.
