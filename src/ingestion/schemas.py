"""
PyArrow / Pandas Schema Definitions for Processed Datasets.
Phase 1: Canonical ETL & Research Dataset Construction.
"""

import pyarrow as pa

# 1. Vulnerabilities Schema
VULNERABILITIES_SCHEMA = pa.schema([
    ("cve_id", pa.string()),
    ("published", pa.string()),
    ("last_modified", pa.string()),
    ("publication_year", pa.int32()),
    ("description_en", pa.string()),
    ("cvss_v2_base_score", pa.float64()),
    ("cvss_v2_vector", pa.string()),
    ("cvss_v2_severity", pa.string()),
    ("cvss_v30_base_score", pa.float64()),
    ("cvss_v30_vector", pa.string()),
    ("cvss_v30_severity", pa.string()),
    ("cvss_v31_base_score", pa.float64()),
    ("cvss_v31_vector", pa.string()),
    ("cvss_v31_severity", pa.string()),
    ("cvss_v40_base_score", pa.float64()),
    ("cvss_v40_vector", pa.string()),
    ("cvss_v40_severity", pa.string()),
    ("reference_count", pa.int64()),
    ("has_cwe", pa.bool_()),
    ("has_cpe_configuration", pa.bool_()),
    ("has_cvss_v2", pa.bool_()),
    ("has_cvss_v30", pa.bool_()),
    ("has_cvss_v31", pa.bool_()),
    ("has_cvss_v40", pa.bool_()),
])

# 2. CVE-CWE Mapping Schema
CVE_CWE_SCHEMA = pa.schema([
    ("cve_id", pa.string()),
    ("cwe_id", pa.string()),
    ("language", pa.string()),
    ("source_description", pa.string()),
    ("is_semantic_cwe", pa.bool_()),
])

# 3. CVE-CPE Applicability Schema
CVE_CPE_SCHEMA = pa.schema([
    ("cve_id", pa.string()),
    ("cpe23_uri", pa.string()),
    ("vulnerable", pa.bool_()),
    ("version_start_including", pa.string()),
    ("version_start_excluding", pa.string()),
    ("version_end_including", pa.string()),
    ("version_end_excluding", pa.string()),
    ("operator", pa.string()),
    ("part", pa.string()),
    ("vendor", pa.string()),
    ("product", pa.string()),
    ("version", pa.string()),
    ("update", pa.string()),
    ("edition", pa.string()),
    ("language", pa.string()),
])

# 4. EPSS Snapshot Schema
EPSS_SCHEMA = pa.schema([
    ("cve_id", pa.string()),
    ("epss", pa.float64()),
    ("percentile", pa.float64()),
    ("score_date", pa.string()),
    ("model_version", pa.string()),
])

# 5. KEV Catalog Schema
KEV_SCHEMA = pa.schema([
    ("cve_id", pa.string()),
    ("vendor_project", pa.string()),
    ("product", pa.string()),
    ("vulnerability_name", pa.string()),
    ("date_added", pa.string()),
    ("short_description", pa.string()),
    ("required_action", pa.string()),
    ("due_date", pa.string()),
    ("known_ransomware_campaign_use", pa.string()),
    ("notes", pa.string()),
    ("cwes", pa.string()),
])

# 6. Vendor Statements Schema
VENDOR_STATEMENTS_SCHEMA = pa.schema([
    ("cve_id", pa.string()),
    ("statement", pa.string()),
    ("organization", pa.string()),
    ("last_modified", pa.string()),
    ("contributor", pa.string()),
])
