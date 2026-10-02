# Processed Data Schema Dictionary (Phase 1.1 Canonical Datasets)

**Repository**: `wdl-vuln-prioritization`  
**Phase**: Phase 1.1 — ETL Reproducibility, Consistency and Dataset Freeze  
**Format**: Apache Parquet with Snappy Compression  
**Base Directory**: `data/processed/`

---

## 1. Table Overview

| Table Name | File Name | Cardinality / Rows | Disk Size | Primary Key / Foreign Keys |
|---|---|---|---|---|
| Vulnerabilities | `vulnerabilities.parquet` | **366,547** | ~53.44 MB | PK: `cve_id` |
| CVE-CWE Mapping | `cve_cwe.parquet` | **430,273** | ~2.91 MB | FK: `cve_id` -> `vulnerabilities.cve_id` |
| CVE-CPE Applicability | `cve_cpe.parquet` | **3,133,450** | ~33.91 MB | FK: `cve_id` -> `vulnerabilities.cve_id` |
| EPSS Snapshot | `epss.parquet` | **348,900** | ~3.87 MB | PK: `cve_id` |
| CISA KEV Catalog | `kev.parquet` | **1,647** | ~0.24 MB | PK: `cve_id` |
| Vendor Statements | `vendor_statements.parquet` | **1,486** | ~0.11 MB | FK: `cve_id` -> `vulnerabilities.cve_id` |

---

## 2. Table Schemas & Field Data Dictionary

### 2.1 `vulnerabilities.parquet`
Canonical vulnerability metadata table (one row per unique CVE ID across 25 yearly NVD feeds 2002–2026).

| Field Name | Data Type | Auth. / Derived | Source | Nullable? | Meaning & Description | Transformation Rule |
|---|---|---|---|---|---|---|
| `cve_id` | `string` | Authoritative | NVD API 2.0 `cve.id` | No | CVE Identifier (e.g. `CVE-2023-38606`) | Extracted directly from root JSON key. |
| `published` | `string` | Authoritative | NVD API 2.0 `cve.published` | No | ISO-8601 publication timestamp | Extracted as raw string timestamp. |
| `last_modified` | `string` | Authoritative | NVD API 2.0 `cve.lastModified` | No | ISO-8601 modification timestamp | Extracted as raw string timestamp. |
| `publication_year` | `int32` | Derived | Authoritative timestamp | No | Calendar publication year | Parsed directly from ISO timestamp string `cve.published[:4]`. |
| `description_en` | `string` | Authoritative | NVD API 2.0 `cve.descriptions` | No | English text description of vulnerability | Selected item with `lang == 'en'`. |
| `cvss_v2_base_score` | `float64` | Authoritative | `metrics.cvssMetricV2` | Yes | CVSS v2 base score [0.0 - 10.0] | Extracted from Primary `cvssData.baseScore`. |
| `cvss_v2_vector` | `string` | Authoritative | `metrics.cvssMetricV2` | Yes | CVSS v2 vector string | Extracted from Primary `cvssData.vectorString`. |
| `cvss_v2_severity` | `string` | Authoritative | `metrics.cvssMetricV2` | Yes | CVSS v2 qualitative severity (`LOW`, `MEDIUM`, `HIGH`) | Extracted from Primary `baseSeverity`. |
| `cvss_v30_base_score` | `float64` | Authoritative | `metrics.cvssMetricV30` | Yes | CVSS v3.0 base score [0.0 - 10.0] | Extracted from Primary `cvssData.baseScore`. |
| `cvss_v30_vector` | `string` | Authoritative | `metrics.cvssMetricV30` | Yes | CVSS v3.0 vector string | Extracted from Primary `cvssData.vectorString`. |
| `cvss_v30_severity` | `string` | Authoritative | `metrics.cvssMetricV30` | Yes | CVSS v3.0 qualitative severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) | Extracted from Primary `baseSeverity`. |
| `cvss_v31_base_score` | `float64` | Authoritative | `metrics.cvssMetricV31` | Yes | CVSS v3.1 base score [0.0 - 10.0] | Extracted from Primary `cvssData.baseScore`. |
| `cvss_v31_vector` | `string` | Authoritative | `metrics.cvssMetricV31` | Yes | CVSS v3.1 vector string | Extracted from Primary `cvssData.vectorString`. |
| `cvss_v31_severity` | `string` | Authoritative | `metrics.cvssMetricV31` | Yes | CVSS v3.1 qualitative severity (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`) | Extracted from Primary `baseSeverity`. |
| `cvss_v40_base_score` | `float64` | Authoritative | `metrics.cvssMetricV40` | Yes | CVSS v4.0 base score [0.0 - 10.0] | Extracted from Primary `cvssData.baseScore`. |
| `cvss_v40_vector` | `string` | Authoritative | `metrics.cvssMetricV40` | Yes | CVSS v4.0 vector string | Extracted from Primary `cvssData.vectorString`. |
| `cvss_v40_severity` | `string` | Authoritative | `metrics.cvssMetricV40` | Yes | CVSS v4.0 qualitative severity | Extracted from Primary `baseSeverity`. |
| `reference_count` | `int64` | Derived | `cve.references` | No | Count of external reference URLs | `len(cve.get('references', []))`. |
| `has_cwe` | `bool` | Derived | `cve.weaknesses` | No | Structural flag indicating CWE presence | `len(weaknesses) > 0`. |
| `has_cpe_configuration` | `bool` | Derived | `cve.configurations` | No | Structural flag indicating CPE config node presence | `len(configurations) > 0`. |
| `has_cvss_v2` | `bool` | Derived | `metrics.cvssMetricV2` | No | Structural flag indicating CVSS v2 presence | `cvss_v2_base_score is not None`. |
| `has_cvss_v30` | `bool` | Derived | `metrics.cvssMetricV30` | No | Structural flag indicating CVSS v3.0 presence | `cvss_v30_base_score is not None`. |
| `has_cvss_v31` | `bool` | Derived | `metrics.cvssMetricV31` | No | Structural flag indicating CVSS v3.1 presence | `cvss_v31_base_score is not None`. |
| `has_cvss_v40` | `bool` | Derived | `metrics.cvssMetricV40` | No | Structural flag indicating CVSS v4.0 presence | `cvss_v40_base_score is not None`. |

---

### 2.2 `cve_cwe.parquet`
Normalized one-to-many weakness taxonomy mapping table.

| Field Name | Data Type | Auth. / Derived | Source | Nullable? | Meaning & Description | Transformation Rule |
|---|---|---|---|---|---|---|
| `cve_id` | `string` | Authoritative | NVD API 2.0 `cve.id` | No | Foreign key to `vulnerabilities.cve_id` | Extracted from cve object. |
| `cwe_id` | `string` | Authoritative | `weaknesses[].description[].value` | No | Raw weakness string e.g. `CWE-79` or `NVD-CWE-noinfo` | Trimmed string representation. |
| `language` | `string` | Authoritative | `weaknesses[].description[].lang` | No | Language code e.g. `en` | Extracted from description object. |
| `source_description` | `string` | Authoritative | `weaknesses[].description[].value` | No | Source description text | Unaltered raw description string. |
| `is_semantic_cwe` | `bool` | Derived | `cwe_id` format | No | Flag indicating genuine CWE vs NVD fallback placeholder | `True` if `cwe_id.startswith('CWE-')` and `cwe_id[4:].isdigit()`, else `False`. |

---

### 2.3 `cve_cpe.parquet`
Normalized one-to-many platform applicability matching table.

| Field Name | Data Type | Auth. / Derived | Source | Nullable? | Meaning & Description | Transformation Rule |
|---|---|---|---|---|---|---|
| `cve_id` | `string` | Authoritative | NVD API 2.0 `cve.id` | No | Foreign key to `vulnerabilities.cve_id` | Extracted from cve object. |
| `cpe23_uri` | `string` | Authoritative | `cpeMatch[].criteria` | No | Authoritative CPE 2.3 URI string | Raw CPE 2.3 formatted string. |
| `vulnerable` | `bool` | Authoritative | `cpeMatch[].vulnerable` | No | Vulnerable status flag | Parsed boolean. |
| `version_start_including` | `string` | Authoritative | `cpeMatch[].versionStartIncluding` | Yes | Version lower bound (inclusive) | String version or `None`. |
| `version_start_excluding` | `string` | Authoritative | `cpeMatch[].versionStartExcluding` | Yes | Version lower bound (exclusive) | String version or `None`. |
| `version_end_including` | `string` | Authoritative | `cpeMatch[].versionEndIncluding` | Yes | Version upper bound (inclusive) | String version or `None`. |
| `version_end_excluding` | `string` | Authoritative | `cpeMatch[].versionEndExcluding` | Yes | Version upper bound (exclusive) | String version or `None`. |
| `operator` | `string` | Authoritative | `node.operator` | Yes | Logical operator (`OR`, `AND`) | String operator or `None`. |
| `part` | `string` | Derived | Parsed from `cpe23_uri` | Yes | CPE Part component (`a`=app, `h`=hardware, `o`=OS) | Split token index 2. |
| `vendor` | `string` | Derived | Parsed from `cpe23_uri` | Yes | Target product vendor string | Split token index 3. |
| `product` | `string` | Derived | Parsed from `cpe23_uri` | Yes | Target product name string | Split token index 4. |
| `version` | `string` | Derived | Parsed from `cpe23_uri` | Yes | Target product version string | Split token index 5. |
| `update` | `string` | Derived | Parsed from `cpe23_uri` | Yes | Target product update/patch string | Split token index 6. |
| `edition` | `string` | Derived | Parsed from `cpe23_uri` | Yes | Target product edition string | Split token index 7. |
| `language` | `string` | Derived | Parsed from `cpe23_uri` | Yes | Target product language string | Split token index 8. |

---

### 2.4 `epss.parquet`
FIRST Exploit Prediction Scoring System snapshot table.

| Field Name | Data Type | Auth. / Derived | Source | Nullable? | Meaning & Description | Transformation Rule |
|---|---|---|---|---|---|---|
| `cve_id` | `string` | Authoritative | Column 1 in CSV | No | Primary Key CVE Identifier | String e.g. `CVE-2023-38606`. |
| `epss` | `float64` | Authoritative | Column 2 in CSV | No | EPSS exploitation probability [0.0, 1.0] | Float parser. |
| `percentile` | `float64` | Authoritative | Column 3 in CSV | No | EPSS percentile ranking [0.0, 1.0] | Float parser. |
| `score_date` | `string` | Authoritative | CSV Header comment | No | ISO score date (`2026-07-16T12:03:48Z`) | Header comment parser. |
| `model_version` | `string` | Authoritative | CSV Header comment | No | EPSS model version (`v2026.06.15`) | Header comment parser. |

---

### 2.5 `kev.parquet`
CISA Known Exploited Vulnerabilities catalog snapshot table.

| Field Name | Data Type | Auth. / Derived | Source | Nullable? | Meaning & Description | Transformation Rule |
|---|---|---|---|---|---|---|
| `cve_id` | `string` | Authoritative | CSV `cveID` | No | Primary Key CVE Identifier | String e.g. `CVE-2023-38606`. |
| `vendor_project` | `string` | Authoritative | CSV `vendorProject` | No | Vendor or project name | Raw string. |
| `product` | `string` | Authoritative | CSV `product` | No | Affected product name | Raw string. |
| `vulnerability_name` | `string` | Authoritative | CSV `vulnerabilityName` | No | CISA title/name | Raw string. |
| `date_added` | `string` | Authoritative | CSV `dateAdded` | No | Date added to KEV catalog (`YYYY-MM-DD`) | Raw string date. |
| `short_description` | `string` | Authoritative | CSV `shortDescription` | No | Summary of exploitation context | Raw string. |
| `required_action` | `string` | Authoritative | CSV `requiredAction` | No | Required remediation action | Raw string. |
| `due_date` | `string` | Authoritative | CSV `dueDate` | No | Remediation due date | Raw string date. |
| `known_ransomware_campaign_use` | `string` | Authoritative | CSV `knownRansomwareCampaignUse` | No | Flag/note on ransomware use (`Known` / `Unknown`) | Raw string. |
| `notes` | `string` | Authoritative | CSV `notes` | No | CISA reference notes | Raw string. |
| `cwes` | `string` | Authoritative | CSV `cwes` | No | Raw CWE text string | Raw string. |

---

### 2.6 `vendor_statements.parquet`
NVD Official Vendor Vulnerability Statements table.

| Field Name | Data Type | Auth. / Derived | Source | Nullable? | Meaning & Description | Transformation Rule |
|---|---|---|---|---|---|---|
| `cve_id` | `string` | Authoritative | Attribute `cvename` | No | Foreign key to `vulnerabilities.cve_id` | Extracted attribute. |
| `statement` | `string` | Authoritative | Element text | No | Official vendor response statement text | Text content of `<statement>`. |
| `organization` | `string` | Authoritative | Attribute `organization` | Yes | Submitting organization name | Attribute value or `None`. |
| `last_modified` | `string` | Authoritative | Attribute `lastmodified` | Yes | Statement modification timestamp | Attribute value or `None`. |
| `contributor` | `string` | Authoritative | Attribute `contributor` | Yes | Submitting contributor name | Attribute value or `None`. |
