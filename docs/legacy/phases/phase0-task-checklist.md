# Task: Phase 0 — Repository Bootstrap and Raw Dataset Verification

You are working inside a NEW research-oriented repository:

    wdl-vuln-prioritization

This repository will eventually contain a web-based research project titled:

    Explainable Machine Learning-Based Vulnerability Prioritization System

IMPORTANT:
This is a fresh implementation. Do NOT copy architecture, code, models, assumptions, or implementation decisions from any previous project.

The purpose of this phase is ONLY to:

1. verify the raw research datasets,
2. establish a clean repository structure,
3. document dataset provenance and integrity,
4. prepare the repository for a later ETL pipeline.

Do NOT perform machine-learning training, frontend development, backend API development, SHAP analysis, or dataset transformation in this phase.


# 1. Research Context

The project is based on the research direction proposed in:

K. G. Agyei et al.,
"Explainable Risk-Based Vulnerability Prioritization in Hybrid Cloud:
Integrating CVSS, EPSS, and CISA KEV with Asset Criticality Signals,"
World Journal of Advanced Research and Reviews,
vol. 30, no. 1, pp. 2044–2052, 2026.
DOI: 10.30574/wjarr.2026.30.1.1006

The reference work uses a transparent weighted linear model combining:

- CVSS
- EPSS
- CISA KEV
- asset/context information

The paper identifies the simplification of nonlinear interactions among
severity, exploitation likelihood, and context as a limitation and suggests
machine-learned nonlinear models with explainability as future work.

This repository will investigate that direction.

Do NOT attempt to implement the research model during Phase 0.


# 2. Expected Raw Dataset Layout

The repository should contain data arranged approximately as:

data/
└── raw/
    ├── nvd/
    │   ├── nvdcve-2.0-2002.json.gz
    │   ├── ...
    │   ├── nvdcve-2.0-2026.json.gz
    │   ├── nvdcve-2.0-modified.json.gz
    │   └── nvdcve-2.0-recent.json.gz
    │
    ├── cpe/
    │   ├── nvdcpe-2.0.tar.gz
    │   └── nvdcpematch-2.0.tar.gz
    │
    ├── epss/
    │   └── epss_scores-2026-07-16.csv.gz
    │
    ├── kev/
    │   └── known_exploited_vulnerabilities.csv
    │
    └── vendor/
        └── vendorstatements.xml.gz

If the current raw-data organization differs, inspect it first.

You MAY reorganize raw files into this logical directory structure if doing
so is safe and does not modify file contents.

Raw source files MUST remain byte-for-byte unchanged.


# 3. Git Safety

Verify that raw and generated datasets are excluded from Git.

At minimum, `.gitignore` should prevent accidental commits of:

    data/raw/
    data/processed/
    data/experiments/

Do NOT remove existing useful `.gitignore` rules.

Do NOT commit or push anything yourself.

Report whether any raw dataset is already Git-tracked.

If a large raw file is already tracked, report it rather than silently
rewriting Git history.


# 4. Create Minimal Repository Structure

Create only the structure required at this stage.

Target structure:

wdl-vuln-prioritization/
├── data/
│   ├── raw/
│   ├── processed/
│   └── experiments/
│
├── docs/
│   └── research/
│
├── scripts/
│
├── src/
│   └── ingestion/
│
├── tests/
│
├── .gitignore
└── README.md

Empty directories may contain `.gitkeep` files where necessary.

Do NOT create:

- frontend application
- backend web API
- database
- Docker configuration
- ML models
- notebooks containing experiments
- SHAP code
- XGBoost code
- training pipelines

Those belong to later phases.


# 5. Raw Dataset Verification

Perform a READ-ONLY inspection of every raw source.

Do not fully extract large archives to permanent repository locations merely
for inspection.

For each source, determine where technically possible:

## NVD CVE feeds

Verify:

- expected yearly feeds from 2002 through 2026
- recent feed
- modified feed
- gzip integrity
- valid JSON after decompression
- top-level JSON schema/structure
- number of vulnerability records per yearly feed
- total records across YEARLY feeds only
- earliest and latest publication timestamps
- availability of:
    - CVE ID
    - English description
    - publication date
    - last-modified date
    - CVSS v2
    - CVSS v3.0
    - CVSS v3.1
    - CVSS v4.0
    - CWE
    - configuration/CPE information
    - references

IMPORTANT:

Do NOT include `recent` and `modified` feeds in the canonical total because
they overlap with yearly feeds.

Detect duplicate CVE IDs across YEARLY feeds and report them.


## EPSS

Verify:

- gzip integrity
- CSV readability
- metadata/header format
- snapshot date
- EPSS model version if provided
- record count
- unique CVE count
- duplicate CVE IDs
- minimum/maximum EPSS score
- minimum/maximum percentile
- malformed rows


## CISA KEV

Verify:

- CSV readability
- row count
- unique CVE count
- duplicate CVE IDs
- available columns
- availability of:
    - dateAdded
    - dueDate
    - vendorProject
    - product
    - vulnerabilityName
    - requiredAction
    - knownRansomwareCampaignUse
    - notes
    - cwes

Do not assume column names. Inspect the actual file.


## CPE Dictionary / CPE Match

Verify:

- archive integrity
- archive member names
- archive format
- approximate number of records where it can be determined safely
- whether the contained data can later be parsed without manually extracting
  the entire archive

Do NOT build the CPE ETL yet.


## Vendor Statements

Verify:

- gzip integrity
- XML readability
- root structure
- approximate record structure
- whether useful CVE identifiers or mappings are present

Do NOT integrate this source yet.


# 6. Cryptographic Dataset Manifest

Create:

    docs/research/DATA_MANIFEST.md

For EVERY raw source file record:

- relative path
- filename
- byte size
- SHA-256 hash
- source family
- apparent snapshot/year
- integrity status
- short description

This manifest establishes which exact data snapshot future experiments use.

Do NOT fabricate download URLs or provenance information if they cannot be
determined from the files/repository.

Unknown provenance should explicitly say:

    Unknown / not recorded


# 7. Dataset Audit Report

Create:

    docs/research/PHASE_0_DATA_AUDIT.md

It should contain:

1. Executive Summary
2. Repository Structure
3. Git Safety Verification
4. Raw Dataset Inventory
5. NVD Verification
6. EPSS Verification
7. CISA KEV Verification
8. CPE Verification
9. Vendor Statement Verification
10. Integrity Problems / Warnings
11. Dataset Limitations
12. Recommendations for Phase 1
13. Exact commands/scripts used for verification

Use tables where useful.

Report measured values.

Do not write claims that were not verified.


# 8. Reproducible Verification Script

Create a lightweight script under:

    scripts/verify_raw_data.py

Its purpose is ONLY to reproduce integrity/inventory checks.

Requirements:

- read-only
- no dataset mutation
- no network access
- no ML dependencies
- no extraction into permanent data directories
- deterministic output where possible
- clear errors for corrupt/missing sources

It should be possible to execute approximately as:

    python scripts/verify_raw_data.py

The script may use Python standard-library functionality wherever practical.

If additional dependencies are genuinely necessary, justify them before
adding them.


# 9. README

Update/create README.md with ONLY an early-stage description.

Include:

- project title
- research motivation
- reference paper
- current development status: Phase 0
- raw data families
- repository structure
- warning that raw datasets are intentionally Git-ignored
- how to run the verification script

Do not claim that the final ML approach has already been selected.

Do not claim experimental results.


# 10. Critical Research Rules

These rules apply throughout this task:

1. NEVER fabricate measurements.

2. NEVER silently impute missing authoritative values.

3. Distinguish:
       authoritative source data
       derived values
       ML-generated values

4. Preserve timestamps.

5. Preserve CVSS versions separately.

6. Do not treat current EPSS values as historical EPSS values.

7. Do not treat KEV absence as proof that a vulnerability has never been
   exploited.

8. Do not modify raw datasets.

9. Do not use `nvd_consolidated.csv` as authoritative research input if it
   happens to exist.

10. Do not train anything during this phase.


# 11. Validation

Before completing the task, verify:

- all expected raw files exist or explicitly list missing files
- SHA-256 hashes were successfully calculated
- yearly NVD feeds can be decompressed and parsed
- EPSS can be parsed
- KEV can be parsed
- archive integrity checks succeed
- XML can be decompressed and parsed
- raw files remain unchanged
- `.gitignore` protects the dataset directories
- verification script runs successfully

If any validation fails, DO NOT conceal it.

Document the failure.


# 12. Final Response

When finished, DO NOT give a generic summary such as "everything works."

Return a concise technical report containing:

## Files Created/Modified
List every repository file you created or modified.

## Dataset Results
Report the important measured counts and integrity results.

## Warnings
Report every detected issue, ambiguity, missing field, corrupt source,
unexpected schema, duplicate, or provenance problem.

## Git Safety
State whether any raw/generated dataset is currently tracked.

## Verification
Give the exact command used to reproduce verification.

## Phase 1 Recommendation
Recommend what the ETL should preserve based ONLY on the schemas actually
observed.

## Explicit Confirmation
State explicitly:

- whether any raw dataset was modified;
- whether any ML model was trained;
- whether any frontend/backend application code was created;
- whether any network resources were accessed.

STOP after this report.

Do not begin Phase