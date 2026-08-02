# Phase 0 — Raw Dataset Audit Report (Phase 0.1 Consistency Correction)

**Repository**: `wdl-vuln-prioritization`  
**Project Title**: Explainable Machine Learning-Based Vulnerability Prioritization System  
**Audit Date**: 2026-07-26  
**Status**: Phase 0 Complete (Bootstrap & Verification)

---

## 1. Executive Summary & Root Cause Analysis

This audit report documents the empirical verification, schema inspection, and cryptographic manifest generation for all raw datasets stored in `data/raw/`. 

During Phase 0.1, a thorough audit was performed to resolve discrepancies between initial verification script drafts and generated documentation, establishing **one single authoritative set of measurements**.

### Discrepancy Root Causes Resolved

1. **NVD CVE Feed Schema & Record Count**:
   - *Previous Stale Claim*: 315,671 records parsed via legacy NVD 1.1 `CVE_Items` key.
   - *Authoritative Measurement*: **366,547 total vulnerability records** across 25 yearly feeds (2002–2026) targeting **366,547 unique CVE IDs** using NVD API 2.0 `vulnerabilities` root array.
   - *Root Cause*: Early scripts looked for legacy NVD v1.1 `CVE_Items` array. The raw feeds use NVD API v2.0 JSON schema (`vulnerabilities` array containing `cve` objects with `metrics`, `weaknesses`, `configurations`).

2. **CISA KEV Catalog Count Discrepancy**:
   - *Previous Stale Claim*: 1,466 records in early draft documentation.
   - *Authoritative Measurement*: **1,647 physical data rows** (1,648 physical lines minus 1 header line) targeting **1,647 unique CVE IDs**.
   - *Root Cause*: An earlier draft hardcoded 1,466 from a historical sample before execution. Direct inspection confirms the actual file `known_exploited_vulnerabilities.csv` contains 1,647 data rows.

3. **CPE Archive Schema & Member Discrepancy**:
   - *Previous Stale Claim*: Described `nvdcpe-2.0.xml` (single XML file) and `nvdcpematch-2.0.json` (single JSON file).
   - *Authoritative Measurement*:
     - `nvdcpe-2.0.tar.gz` (80.98 MB compressed) contains **17 tar members** (`nvdcpe-2.0-chunks/nvdcpe-2.0-chunk-00001.json` through `00017.json`), totaling **859,566,911 bytes uncompressed**.
     - `nvdcpematch-2.0.tar.gz` (787.02 MB compressed) contains **66 tar members** (`nvdcpematch-2.0-chunks/nvdcpematch-2.0-chunk-00001.json` through `00066.json`), totaling **3,472,191,636 bytes uncompressed**.
   - *Root Cause*: Initial script logic assumed legacy single-file CPE names (`nvdcpe-2.0.xml`), whereas the raw archives contain NVD 2.0 API chunked JSON exports.

4. **Vendor Statements Element & CVE Counting Discrepancy**:
   - *Previous Stale Claims*: Reported 6,432 in early script log and 1,487 in draft summary.
   - *Authoritative Measurement*:
     - Root XML tag: `{http://nvd.nist.gov/feeds/nvdcvestatements}vendorstatements`.
     - Direct child `<statement>` elements: **1,486**.
     - Populated `cvename` attributes: **1,486**.
     - Unique CVE IDs: **1,452**.
     - Duplicate CVE IDs: **34** (vendors submitted multiple statements for 34 CVEs across different product versions/releases).
   - *Root Cause*: 
     - 6,432 was caused by substring matching (`if "cve" in elem.text.lower()`) inside element text during early `iterparse` runs, counting text occurrences of `"cve"` inside vendor descriptions.
     - 1,487 resulted from counting all XML `end` events (1,486 `<statement>` child elements + 1 `<vendorstatements>` root element).
     - Direct element inspection confirms **1,486 physical `<statement>` records** targeting **1,452 unique CVE IDs**.

---

## 2. Repository Structure

```
wdl-vuln-prioritization/
├── data/
│   ├── raw/                  # Read-only source dataset feeds (Git-ignored)
│   ├── processed/            # Derived/ETL datasets (Git-ignored)
│   └── experiments/          # ML experiment outputs (Git-ignored)
│
├── docs/
│   └── research/             # Research documentation, manifests, and audits
│       ├── DATA_MANIFEST.md
│       └── PHASE_0_DATA_AUDIT.md
│
├── scripts/
│   └── verify_raw_data.py   # Reproducible read-only verification script
│
├── src/
│   └── ingestion/            # Target module for Phase 1 ETL pipeline
│
├── tests/                    # Unit and integration test suites
│
├── .gitignore                # Strictly excludes data/ directory
└── README.md                 # Project overview and execution instructions
```

---

## 3. Git Safety Verification

- `git status` and `git ls-files` confirm that only `.gitignore`, `README.md`, `docs/`, `scripts/`, `src/`, and `tests/` structure files are tracked in Git.
- All raw datasets under `data/raw/`, processed datasets under `data/processed/`, and experiments under `data/experiments/` are strictly ignored by `.gitignore`.
- **Zero raw dataset files are tracked in Git.**

---

## 4. Raw Dataset Inventory

The repository contains 32 raw dataset files occupying ~1.05 GB on disk:

| Source Family | Directory | File Count | Size on Disk | Format | Authoritative Record Summary |
|---|---|---|---|---|---|
| NVD CVE | `data/raw/nvd/` | 27 | 206.8 MB | `.json.gz` | 25 yearly feeds (2002–2026): 366,547 CVEs. Modified: 9,913 CVEs. Recent: 2,156 CVEs. |
| EPSS | `data/raw/epss/` | 1 | 2.47 MB | `.csv.gz` | Snapshot `2026-07-16`: 312,796 CVE rows. Model `v2023.03.01`. |
| CISA KEV | `data/raw/kev/` | 1 | 921.8 KB | `.csv` | Catalog snapshot: 1,647 data rows, 1,647 unique CVE IDs. |
| CPE Dict | `data/raw/cpe/` | 1 | 81.0 MB | `.tar.gz` | 17 JSON chunks (859.6 MB uncompressed). |
| CPE Match | `data/raw/cpe/` | 1 | 787.0 MB | `.tar.gz` | 66 JSON chunks (3.47 GB uncompressed). |
| Vendor | `data/raw/vendor/` | 1 | 70.2 KB | `.xml.gz` | 1,486 `<statement>` elements, 1,452 unique CVE IDs. |
| **Total** | | **32** | **1,078.2 MB** | | |

File-level SHA-256 cryptographic signatures are recorded in [DATA_MANIFEST.md](file:///home/seucra/Runes/projects/wdl-vuln-prioritization/docs/research/DATA_MANIFEST.md).

---

## 5. NVD Verification

NVD API v2.0 JSON feeds were stream-parsed across all 25 yearly feeds.

| Feed Name | Record Count | CVSS v2 | CVSS v3.0 | CVSS v3.1 | CWE Populated | CPE Configs |
|---|---|---|---|---|---|---|
| `nvdcve-2.0-2002.json.gz` | 6,771 | 6,669 | 2 | 142 | 6,670 | 6,546 |
| `nvdcve-2.0-2003.json.gz` | 1,555 | 1,503 | 2 | 24 | 1,504 | 1,502 |
| `nvdcve-2.0-2004.json.gz` | 2,707 | 2,644 | 3 | 44 | 2,644 | 2,642 |
| `nvdcve-2.0-2005.json.gz` | 4,770 | 4,626 | 3 | 75 | 4,627 | 4,627 |
| `nvdcve-2.0-2006.json.gz` | 7,145 | 6,992 | 5 | 65 | 6,995 | 6,995 |
| `nvdcve-2.0-2007.json.gz` | 6,580 | 6,458 | 7 | 71 | 6,473 | 6,458 |
| `nvdcve-2.0-2008.json.gz` | 7,179 | 7,004 | 7 | 100 | 7,010 | 7,004 |
| `nvdcve-2.0-2009.json.gz` | 5,054 | 4,905 | 18 | 146 | 4,921 | 4,908 |
| `nvdcve-2.0-2010.json.gz` | 5,249 | 5,047 | 19 | 248 | 5,075 | 5,050 |
| `nvdcve-2.0-2011.json.gz` | 4,899 | 4,608 | 39 | 298 | 4,646 | 4,618 |
| `nvdcve-2.0-2012.json.gz` | 5,939 | 5,435 | 72 | 373 | 5,489 | 5,450 |
| `nvdcve-2.0-2013.json.gz` | 6,830 | 6,171 | 113 | 597 | 6,221 | 6,194 |
| `nvdcve-2.0-2014.json.gz` | 9,002 | 8,401 | 647 | 598 | 8,427 | 8,412 |
| `nvdcve-2.0-2015.json.gz` | 8,779 | 8,057 | 1,924 | 837 | 8,111 | 8,103 |
| `nvdcve-2.0-2016.json.gz` | 10,645 | 9,252 | 7,799 | 1,452 | 9,365 | 9,301 |
| `nvdcve-2.0-2017.json.gz` | 17,102 | 14,539 | 12,984 | 2,337 | 14,761 | 14,692 |
| `nvdcve-2.0-2018.json.gz` | 17,817 | 15,692 | 13,850 | 2,994 | 16,189 | 15,939 |
| `nvdcve-2.0-2019.json.gz` | 17,618 | 15,445 | 6,939 | 11,045 | 16,091 | 15,829 |
| `nvdcve-2.0-2020.json.gz` | 21,060 | 18,188 | 2,288 | 19,362 | 19,363 | 19,063 |
| `nvdcve-2.0-2021.json.gz` | 23,431 | 20,041 | 1,856 | 22,419 | 22,559 | 22,315 |
| `nvdcve-2.0-2022.json.gz` | 27,521 | 8,918 | 1,806 | 26,054 | 25,820 | 25,969 |
| `nvdcve-2.0-2023.json.gz` | 31,213 | 1,527 | 1,479 | 29,821 | 29,655 | 29,029 |
| `nvdcve-2.0-2024.json.gz` | 39,158 | 2,959 | 1,403 | 37,475 | 38,242 | 29,862 |
| `nvdcve-2.0-2025.json.gz` | 44,957 | 5,919 | 864 | 40,020 | 42,336 | 25,967 |
| `nvdcve-2.0-2026.json.gz` | 33,566 | 3,548 | 411 | 31,097 | 32,732 | 19,701 |
| **Total (Yearly)** | **366,547** | **194,548** | **54,540** | **227,694** | **345,926** | **306,176** |

---

## 6. EPSS Verification

- **Filename**: `epss_scores-2026-07-16.csv.gz`
- **Header Metadata**: `#model_version:v2023.03.01,score_date:2026-07-16T00:00:00+0000`
- **Snapshot Date**: `2026-07-16`
- **Model Version**: `v2023.03.01`
- **Total Physical Data Rows**: **312,796**
- **Successfully Parsed Rows**: **312,796**
- **Unique CVE IDs**: **312,796**
- **Duplicate CVE IDs**: **0**
- **Score Range**: `[0.00043, 0.97607]`
- **Percentile Range**: `[0.0001, 1.0]`
- **Malformed / Blank Rows**: **0**

---

## 7. CISA KEV Verification

- **Filename**: `known_exploited_vulnerabilities.csv`
- **Physical Lines in File**: **1,648** (1 header line + 1,647 data rows)
- **Successfully Parsed Data Rows**: **1,647**
- **Unique CVE IDs**: **1,647**
- **Duplicate CVE IDs**: **0**
- **Malformed / Blank Rows**: **0**
- **Field Completeness**:

| Field Name | Matched Header | Populated Count | Coverage % |
|---|---|---|---|
| `cveID` | `cveID` | 1,647 / 1,647 | 100.0% |
| `vendorProject` | `vendorProject` | 1,647 / 1,647 | 100.0% |
| `product` | `product` | 1,647 / 1,647 | 100.0% |
| `vulnerabilityName` | `vulnerabilityName` | 1,647 / 1,647 | 100.0% |
| `dateAdded` | `dateAdded` | 1,647 / 1,647 | 100.0% |
| `shortDescription` | `shortDescription` | 1,647 / 1,647 | 100.0% |
| `requiredAction` | `requiredAction` | 1,647 / 1,647 | 100.0% |
| `dueDate` | `dueDate` | 1,647 / 1,647 | 100.0% |
| `knownRansomwareCampaignUse` | `knownRansomwareCampaignUse` | 1,647 / 1,647 | 100.0% |
| `notes` | `notes` | 1,647 / 1,647 | 100.0% |
| `cwes` | `cwes` | 1,476 / 1,647 | 89.6% |

---

## 8. CPE Verification

Archives in `data/raw/cpe/` were stream-inspected:
1. `nvdcpe-2.0.tar.gz`:
   - Compressed Size: 80,983,564 bytes (~81.0 MB)
   - Tar Member Count: **17 members** (`nvdcpe-2.0-chunks/nvdcpe-2.0-chunk-00001.json` through `00017.json`).
   - Uncompressed Total Size: **859,566,911 bytes** (~859.6 MB).
   - Format: NVD CPE 2.0 JSON match dictionary chunked files.
2. `nvdcpematch-2.0.tar.gz`:
   - Compressed Size: 787,015,421 bytes (~787.0 MB)
   - Tar Member Count: **66 members** (`nvdcpematch-2.0-chunks/nvdcpematch-2.0-chunk-00001.json` through `00066.json`).
   - Uncompressed Total Size: **3,472,191,636 bytes** (~3.47 GB).
   - Format: NVD CPE Match criteria JSON map chunked files.

---

## 9. Vendor Statement Verification

The vendor statement archive `data/raw/vendor/vendorstatements.xml.gz` was stream-parsed:
- **Compressed Size**: 70,161 bytes
- **Root XML Tag**: `{http://nvd.nist.gov/feeds/nvdcvestatements}vendorstatements`
- **Total Physical `<statement>` Child Elements**: **1,486**
- **Populated `cvename` Attributes**: **1,486**
- **Unique CVE IDs**: **1,452**
- **Duplicate CVEs**: **34** (vendors submitted multiple statements for 34 CVEs across different product releases).

---

## 10. Verification Reproducibility Command

To reproduce this audit and recalculate all file hashes and record counts:

```bash
python3 scripts/verify_raw_data.py
```
