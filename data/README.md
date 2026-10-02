# VTS Local Dataset Directory

This directory stores the raw and processed vulnerability datasets, database files, and experiment artifacts for the **Vulnerability Prioritization & Triage System (VTS)**.

Due to file sizes and binary formats, the raw datasets, processed Parquet tables, SQLite databases, and experiment binaries are **kept locally and excluded from Git version control** (via `.gitignore`), ensuring repository lightweightness while guaranteeing complete local reproducibility.

---

## Directory Structure

```text
data/
├── README.md                     # This documentation file (tracked in Git)
├── custom_test_results.json      # Pipeline test execution output (tracked in Git)
├── auth_users.sqlite             # [Local] SQLite user database for RBAC (gitignored)
├── raw/                          # [Local] Upstream feed archives (gitignored)
│   ├── nvd/                      # NVD CVE JSON archives (1988–2026) frozen 2026-07-26
│   ├── known_exploited_vulnerabilities.json # CISA KEV catalog snapshot
│   └── epss_scores-2026-07-16.csv.gz       # FIRST EPSS snapshot (Model v2026.06.15)
├── processed/                    # [Local] Canonical Parquet tables (gitignored)
│   ├── vulnerabilities.parquet   # 366,547 canonical CVE records (1988–2026)
│   ├── cve_cwe.parquet           # CWE weakness mappings and semantic CWE tags
│   ├── cve_cpe.parquet           # CPE software applicability configurations
│   ├── cve_epss.parquet          # EPSS scores and percentiles
│   ├── kev.parquet               # CISA KEV catalog records with date added & due date
│   └── cve_vendor_statements.parquet # Official vendor mitigations and statements
└── experiments/                  # [Local] Experiment models & predictions (gitignored)
    ├── phase3_baseline/          # 15 original baseline artifacts (SHA-256 verified)
    └── phase3_corrected/         # 14 corrected leakage-safe artifacts (EXP-A1, B2, B1, C1)
```

---

## Detailed Contents & Schemas

### 1. Raw Feeds (`data/raw/`)
* **NVD Yearly JSON Feeds (`data/raw/nvd/`)**: Acquired via NVD API 2.0 in a single snapshot on **July 26, 2026**. Contains official CVE metadata, descriptions, CVSS v2/v3.0/v3.1 vector strings, CWE classifications, and CPE match criteria.
* **CISA KEV Catalog (`data/raw/known_exploited_vulnerabilities.json`)**: Authoritative catalog of vulnerabilities known to be actively exploited in the wild, captured on **July 26, 2026** (1,647 cataloged CVEs).
* **FIRST EPSS Snapshot (`data/raw/epss_scores-2026-07-16.csv.gz`)**: Exploit Prediction Scoring System snapshot dated **July 16, 2026T12:03:48Z** (Model `v2026.06.15`).

### 2. Processed Parquet Tables (`data/processed/`)
All tables are stored in Apache Parquet format with snappy compression for high-performance vectorized analytical queries via DuckDB:

| Parquet File | Row Count | Primary Key | Key Columns |
| :--- | :--- | :--- | :--- |
| `vulnerabilities.parquet` | **366,547** | `cve_id` | `cve_id`, `published`, `last_modified`, `cvss_v31_base_score`, `cvss_v31_vector`, `cvss_v30_base_score`, `cvss_v2_base_score`, `description_en`, `has_cwe`, `has_cpe_configuration`, `publication_year` |
| `cve_cwe.parquet` | **374,210** | Composite | `cve_id`, `cwe_id`, `is_semantic_cwe` |
| `cve_cpe.parquet` | **1,529,842**| Composite | `cve_id`, `criteria`, `part`, `vendor`, `product`, `version` |
| `cve_epss.parquet` | **366,547** | `cve_id` | `cve_id`, `epss`, `percentile` |
| `kev.parquet` | **1,647** | `cve_id` | `cve_id`, `vendor_project`, `product`, `vulnerability_name`, `date_added`, `due_date`, `known_ransomware_campaign_use` |
| `cve_vendor_statements.parquet` | **8,124** | Composite | `cve_id`, `organization`, `statement`, `last_modified` |

### 3. Experiment Artifacts (`data/experiments/`)
* **`phase3_baseline/`**: Immutable preserved baseline run containing initial models, predictions, and metrics (with global corpus-fitted preprocessing).
* **`phase3_corrected/`**: Verified leakage-safe experiment run with two-stage inductive preprocessing (fitted strictly on training data during tuning, refitted on train+val before test evaluation):
  * `exp_a1/`: CVSS v3.1 regression model (`model.xgb`), vectorizer, feature names, test predictions, and metrics.
  * `exp_b2/`: KEV prediction without EPSS under temporal split (`model.xgb`, vectorizer, feature names, test predictions, metrics).
  * `exp_b1/`: Retrospective EPSS sensitivity analysis test predictions and metrics.
  * `exp_c1/`: Multi-criteria triage simulation Parquet export (`simulation_rankings.parquet`, 12 columns preserving all 4 tiers without collision) and metrics.
  * `corrected_manifest.json`: Cryptographic SHA-256 manifest of all 14 artifacts.

---

## Reproducing the Processed Datasets

To reconstruct the processed Parquet tables from the raw feeds, execute:
```bash
PYTHONPATH=. .venv/bin/python scripts/build_processed_data.py
```
To run the automated ETL integrity validation tests:
```bash
PYTHONPATH=. .venv/bin/pytest tests/test_etl_invariants.py -v
```
