# Phase 2 — Data Profile Report (Empirical Dataset Characterization)

**Repository**: `wdl-vuln-prioritization`  
**Phase**: Phase 2 — Experimental Protocol & Dataset Characterization  
**Report Date**: 2026-08-08  
**Data Status**: Frozen & Verified (Phase 1.1 Canonical Datasets)  
**Execution Script**: `scripts/research/characterize_datasets.py`  
**Visualization Script**: `scripts/research/generate_phase2_figures.py`  

---

## 1. Executive Summary & Parquet Inventory

This report documents the empirical descriptive analysis of the six canonical processed Parquet datasets frozen in Phase 1.1 under `data/processed/`. Zero data modifications or machine learning model trainings were performed.

### Canonical Table Cardinality Overview

| Table Name | File Path | Total Records | Column Count | Primary Key / Unique CVEs | Primary Feature / Scope |
|---|---|---|---|---|---|
| Vulnerabilities | `data/processed/vulnerabilities.parquet` | **366,547** | 24 | `cve_id` (366,547 unique) | Canonical NVD CVE metadata (2002–2026 feeds) |
| Weakness Mapping | `data/processed/cve_cwe.parquet` | **430,273** | 5 | Foreign Key (`cve_id` -> 345,926 CVEs) | Normalized 1-to-many CWE taxonomy mappings |
| CPE Applicability | `data/processed/cve_cpe.parquet` | **3,133,450** | 15 | Foreign Key (`cve_id` -> 306,176 CVEs) | Platform applicability nodes & parsed CPE 2.3 URIs |
| EPSS Snapshot | `data/processed/epss.parquet` | **348,900** | 5 | `cve_id` (348,900 unique) | Snapshot score date `2026-07-16T12:03:48Z` (Model `v2026.06.15`) |
| CISA KEV Catalog | `data/processed/kev.parquet` | **1,647** | 11 | `cve_id` (1,647 unique) | CISA Known Exploited Vulnerabilities catalog snapshot |
| Vendor Statements | `data/processed/vendor_statements.parquet` | **1,486** | 5 | Foreign Key (`cve_id` -> 1,452 CVEs) | NVD Official Vendor Response Statements |

---

## 2. CVSS Score & Metric Characterization

NVD records contain four non-overlapping CVSS metric spaces (`cvss_v2`, `cvss_v30`, `cvss_v31`, `cvss_v40`).

### 2.1 Score Summary Statistics Across Versions

| CVSS Version | Populated Count | Missing Count | Coverage % | Min Score | Max Score | Mean Score | Median Score | Std Dev | 25th Pct | 75th Pct |
|---|---|---|---|---|---|---|---|---|---|---|
| **CVSS v2** | 194,548 | 171,999 | **53.08%** | 0.0 | 10.0 | 5.909 | 5.5 | 1.973 | 4.3 | 7.5 |
| **CVSS v3.0** | 54,540 | 312,007 | **14.88%** | 0.0 | 10.0 | 7.192 | 7.5 | 1.667 | 6.1 | 8.6 |
| **CVSS v3.1** | 227,694 | 138,853 | **62.12%** | 0.0 | 10.0 | 7.032 | 7.2 | 1.703 | 5.5 | 8.2 |
| **CVSS v4.0** | 29,964 | 336,583 | **8.17%** | 0.0 | 10.0 | 6.145 | 6.6 | 2.338 | 5.1 | 8.4 |

> [!NOTE]
> CVSS v3.1 is the most widely adopted version in the canonical dataset (62.12% coverage). CVSS v2 was deprecated by NVD after 2021. CVSS v4.0 adoption is actively growing (29,964 CVEs).

### 2.2 Qualitative Severity Breakdown

| Severity Category | CVSS v2 Count | CVSS v3.0 Count | CVSS v3.1 Count | CVSS v4.0 Count |
|---|---|---|---|---|
| **CRITICAL** | N/A | 7,522 (13.79%) | 32,077 (14.09%) | 2,487 (8.30%) |
| **HIGH** | 61,451 (31.59%) | 24,463 (44.85%) | 89,012 (39.09%) | 9,253 (30.88%) |
| **MEDIUM** | 112,598 (57.88%) | 21,068 (38.63%) | 101,613 (44.63%) | 13,111 (43.76%) |
| **LOW** | 20,499 (10.54%) | 1,483 (2.72%) | 4,986 (2.19%) | 5,056 (16.87%) |
| **NONE** | 0 | 4 (0.01%) | 6 (0.00%) | 57 (0.19%) |
| **Total Populated** | **194,548** | **54,540** | **227,694** | **29,964** |

### 2.3 CVSS v3.1 Vector Component Breakdown (n = 227,694)

The vector string components for CVSS v3.1 were extracted and parsed:

| Vector Metric | Key | Value Level 1 | Value Level 2 | Value Level 3 | Value Level 4 |
|---|---|---|---|---|---|
| **Attack Vector** | `AV` | **Network (N)**: 167,209 (73.4%) | **Local (L)**: 53,184 (23.4%) | **Adjacent (A)**: 5,322 (2.3%) | **Physical (P)**: 1,979 (0.9%) |
| **Attack Complexity** | `AC` | **Low (L)**: 213,154 (93.6%) | **High (H)**: 14,540 (6.4%) | — | — |
| **Privileges Required** | `PR` | **None (N)**: 123,996 (54.5%) | **Low (L)**: 83,818 (36.8%) | **High (H)**: 19,880 (8.7%) | — |
| **User Interaction** | `UI` | **None (N)**: 158,240 (69.5%) | **Required (R)**: 69,454 (30.5%) | — | — |
| **Scope** | `S` | **Unchanged (U)**: 181,649 (79.8%) | **Changed (C)**: 46,045 (20.2%) | — | — |
| **Confidentiality Impact** | `C` | **High (H)**: 119,937 (52.7%) | **Low (L)**: 54,642 (24.0%) | **None (N)**: 53,115 (23.3%) | — |
| **Integrity Impact** | `I` | **High (H)**: 101,131 (44.4%) | **None (N)**: 70,249 (30.8%) | **Low (L)**: 56,314 (24.7%) | — |
| **Availability Impact** | `A` | **High (H)**: 121,929 (53.5%) | **None (N)**: 89,262 (39.2%) | **Low (L)**: 16,503 (7.2%) | — |

---

## 3. Vulnerability Description Text Analysis

The `description_en` column in `vulnerabilities.parquet` contains English textual descriptions provided by NVD / CVE Numbering Authorities (CNAs).

### 3.1 Text Length & Word Count Metrics

| Metric | Character Length | Word Count |
|---|---|---|
| **Minimum** | 15 | 2 |
| **25th Percentile (P25)** | 181 | 27 |
| **Median (P50)** | 253 | 37 |
| **Mean** | 333.81 | 47.39 |
| **75th Percentile (P75)** | 378 | 55 |
| **95th Percentile (P95)** | 764 | 109 |
| **99th Percentile (P99)** | 1,693 | 215 |
| **Maximum** | 3,998 | 696 |

### 3.2 Completeness & Duplicate Text Audit

- **Total Records**: **366,547**
- **Unique Description Strings**: **336,267**
- **Empty Descriptions (`len == 0`)**: **0** (100% text completeness)
- **Near-Empty Descriptions (`< 10 chars`)**: **0**
- **Short Descriptions (`< 5 words`)**: **1,048** (0.29%)
- **Duplicated Text Types**: **5,298** unique string texts appear more than once.
- **Duplicated Records Total**: **30,280** records share a duplicate description string with another CVE.

#### Top Duplicate Description Patterns

The vast majority of duplicate descriptions represent rejected or unused CVE candidates:
1. `"Rejected reason: DO NOT USE THIS CANDIDATE NUMBER..."` (**1,033 instances**)
2. `"Rejected reason: Not used..."` (**916 instances**)
3. `"Rejected reason: This CVE ID has been rejected or..."` (**893 instances**)
4. `"Rejected reason: This candidate is unused by its C..."` (**663 instances**)

---

## 4. CWE Weakness Taxonomy Analysis

`cve_cwe.parquet` contains 430,273 records mapping CVEs to weakness identifiers.

### 4.1 CWE Mapping Summary

- **Total Mapping Records**: **430,273**
- **Unique CWE Identifiers**: **794**
- **Unique CVEs Covered**: **345,926** (**94.37%** of canonical vulnerabilities)
- **CVEs Without Any CWE Mapping**: **20,621** (**5.63%**)
- **Semantic CWE Mappings (`CWE-xxx`)**: **364,315** (**84.67%**)
- **Non-Semantic Placeholder Mappings**: **65,958** (**15.33%**)
  - `NVD-CWE-noinfo`: **35,980** (8.36%)
  - `NVD-CWE-Other`: **29,978** (6.97%)

### 4.2 Mapping Density Distribution per CVE

- **0 CWEs**: 20,621 CVEs (5.63%)
- **1 CWE**: 269,632 CVEs (73.56%)
- **Multi-CWEs (2–11 CWEs)**: 76,294 CVEs (20.81%)
- **Maximum CWEs for a Single CVE**: **11**

### 4.3 Top 10 Most Frequent Weakness Identifiers

| Rank | CWE Identifier | Description / Type | Count | % of Total Mappings |
|---|---|---|---|---|
| 1 | `CWE-79` | Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') | 51,984 | 12.08% |
| 2 | `NVD-CWE-noinfo` | NVD Placeholder (Insufficient Information) | 35,980 | 8.36% |
| 3 | `NVD-CWE-Other` | NVD Placeholder (Other Weakness Not in CWE List) | 29,978 | 6.97% |
| 4 | `CWE-89` | Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection') | 23,509 | 5.46% |
| 5 | `CWE-787` | Out-of-bounds Write | 16,769 | 3.90% |
| 6 | `CWE-119` | Improper Restriction of Operations within the Bounds of a Memory Buffer | 14,398 | 3.35% |
| 7 | `CWE-20` | Improper Input Validation | 13,787 | 3.20% |
| 8 | `CWE-22` | Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal') | 10,761 | 2.50% |
| 9 | `CWE-352` | Cross-Site Request Forgery (CSRF) | 10,608 | 2.47% |
| 10 | `CWE-125` | Out-of-bounds Read | 10,603 | 2.46% |

---

## 5. CPE Platform Applicability Analysis

`cve_cpe.parquet` contains 3,133,450 records detailing platform applicability match nodes.

### 5.1 CPE Density & Diversity Metrics

- **Total CPE Records**: **3,133,450**
- **Unique CVEs Covered**: **306,176** (**83.53%** of canonical vulnerabilities)
- **CVEs Without CPE Configurations**: **60,371** (**16.47%**)
- **Unique Product Vendors (`vendor`)**: **36,614**
- **Unique Target Products (`product`)**: **164,307**

### 5.2 CPE Nodes per CVE Distribution

| CPE Mapping Range | CVE Count | Percentage |
|---|---|---|
| **0 CPEs** | 60,371 | 16.47% |
| **1 CPE** | 143,352 | 39.11% |
| **2 to 5 CPEs** | 86,762 | 23.67% |
| **6 to 20 CPEs** | 50,083 | 13.66% |
| **21+ CPEs** | 25,979 | 7.09% |
| **Summary Stats** | Min: 1, Median: 2.0, Mean: 10.23, P90: 17.0, P99: 153.0, Max: 5,821 | — |

### 5.3 CPE Component Distribution & Top Vendors / Products

#### Part Distribution (`part`)
- **Application (`a`)**: 1,336,486 (42.65%)
- **Operating System (`o`)**: 1,209,661 (38.60%)
- **Hardware (`h`)**: 587,303 (18.74%)

#### Top 5 Vendors
1. `qualcomm`: 400,428 mappings
2. `cisco`: 216,344 mappings
3. `linux`: 164,216 mappings
4. `microsoft`: 160,078 mappings
5. `intel`: 112,791 mappings

#### Top 5 Products
1. `linux_kernel`: 163,971 mappings
2. `ios`: 67,816 mappings
3. `junos`: 65,306 mappings
4. `android`: 59,302 mappings
5. `firefox`: 37,756 mappings

---

## 6. EPSS Snapshot Score Analysis

`epss.parquet` contains the FIRST EPSS snapshot dated **2026-07-16T12:03:48Z** (Model `v2026.06.15`).

### 6.1 EPSS Coverage & NVD Overlap

- **Total EPSS Records**: **348,900**
- **Unique EPSS CVE IDs**: **348,900**
- **NVD ∩ EPSS Overlap**: **348,864 CVEs** (**95.18%** of NVD canonical vulnerabilities)
- **NVD CVEs Missing from EPSS Snapshot**: **17,683** (4.82%)
- **EPSS CVEs Absent from Canonical NVD**: **36** (CVEs published outside feed bounds)

### 6.2 Score & Percentile Statistics

| Metric | EPSS Probability Score (`epss`) | EPSS Percentile (`percentile`) |
|---|---|---|
| **Minimum** | 0.00046 | 0.00000 |
| **10th Percentile (P10)** | 0.00200 | 0.10000 |
| **25th Percentile (P25)** | 0.00329 | 0.25001 |
| **Median (P50)** | **0.00727** | **0.50001** |
| **Mean** | **0.02888** | **0.50000** |
| **75th Percentile (P75)** | 0.01728 | 0.75000 |
| **90th Percentile (P90)** | 0.04282 | 0.90000 |
| **95th Percentile (P95)** | 0.09783 | 0.95000 |
| **99th Percentile (P99)** | **0.58648** | 0.99000 |
| **99.9th Percentile (P99.9)** | **0.97856** | 0.99900 |
| **Maximum** | 0.99999 | 1.00000 |
| **Standard Deviation** | 0.09298 | 0.28868 |

> [!IMPORTANT]
> EPSS scores exhibit heavy right-skewness: 50% of vulnerabilities have an exploitation probability $< 0.00727$ (0.73%), and 90% have a score $< 0.04282$ (4.28%). Only 1% of vulnerabilities exceed an EPSS probability of 0.586. Pearson correlation between raw `epss` score and `percentile` is **0.4125**.

---

## 7. CISA KEV Exploitation Catalog Analysis

`kev.parquet` contains 1,647 records representing authoritative observed wild exploitation.

### 7.1 KEV Class Imbalance

- **Total KEV Catalog Records**: **1,647**
- **Unique KEV CVE IDs**: **1,647**
- **NVD ∩ KEV Membership Rate**: **1,647 / 366,547 = 0.4493%** (~1 out of every 222 CVEs)
- **Non-KEV Unobserved Class Count**: **364,900** (**99.5507%**)

### 7.2 Ransomware & Addition Metadata

- **Known Ransomware Campaign Use**:
  - `Unknown`: 1,318 (80.02%)
  - `Known`: 329 (19.98%)
- **KEV Additions by Calendar Year (`date_added`)**:
  - 2021: 311
  - 2022: 555
  - 2023: 187
  - 2024: 186
  - 2025: 245
  - 2026: 163

### 7.3 Timing Analysis: Time Delta Between Publication & KEV Addition

Calculating $\Delta t = \text{date\_added} - \text{published}$ in days:

| Delay Metric | Value (Days) | Value (Years) |
|---|---|---|
| **Minimum Delay** | -290.8 days | -0.80 years |
| **25th Percentile (P25)** | 10.7 days | 0.03 years |
| **Median Delay (P50)** | **285.2 days** | **0.78 years** |
| **Mean Delay** | **890.7 days** | **2.44 years** |
| **75th Percentile (P75)** | 1,402.0 days | 3.84 years |
| **Maximum Delay** | 7,190.8 days | 19.69 years |

#### Time Window Categories
- **Added BEFORE NVD Publication Date ($\Delta t < 0$)**: **210 CVEs** (12.75%)
- **Added within 0–30 Days of Publication**: **288 CVEs** (17.49%)
- **Added within 31–90 Days of Publication**: **124 CVEs** (7.53%)
- **Added within 91–365 Days of Publication**: **249 CVEs** (15.12%)
- **Added Over 1 Year After Publication ($\Delta t > 365$)**: **776 CVEs** (47.12%)

> [!WARNING]
> **Negative Delay Finding**: 210 CVEs (12.75% of KEV) were added to CISA KEV *before* NVD processed and published their official metadata. This reflects zero-day exploitation or delayed NVD indexing, proving that relying strictly on NVD publication timestamps for initial triage creates a blind spot.

---

## 8. Temporal Distribution Summary (2000–2026)

| Publication Year | Total Published | CVSS v2 | CVSS v3.0 | CVSS v3.1 | CVSS v4.0 | EPSS Coverage | KEV Count |
|---|---|---|---|---|---|---|---|
| **2000** | 1,020 | 1,019 | 1 | 9 | 0 | 1,019 | 0 |
| **2001** | 1,679 | 1,676 | 0 | 38 | 0 | 1,676 | 0 |
| **2002** | 2,170 | 2,156 | 0 | 54 | 0 | 2,156 | 1 |
| **2003** | 1,548 | 1,527 | 0 | 17 | 0 | 1,527 | 0 |
| **2004** | 2,479 | 2,451 | 1 | 44 | 0 | 2,451 | 2 |
| **2005** | 5,010 | 4,932 | 1 | 64 | 0 | 4,932 | 1 |
| **2006** | 6,659 | 6,608 | 2 | 47 | 0 | 6,608 | 2 |
| **2007** | 6,596 | 6,516 | 1 | 59 | 0 | 6,516 | 2 |
| **2008** | 5,664 | 5,632 | 1 | 87 | 0 | 5,632 | 6 |
| **2009** | 5,778 | 5,732 | 1 | 107 | 0 | 5,732 | 14 |
| **2010** | 4,667 | 4,639 | 3 | 124 | 0 | 4,639 | 23 |
| **2011** | 4,172 | 4,150 | 3 | 58 | 0 | 4,150 | 9 |
| **2012** | 5,351 | 5,288 | 1 | 114 | 0 | 5,288 | 22 |
| **2013** | 5,324 | 5,187 | 3 | 97 | 0 | 5,187 | 35 |
| **2014** | 8,008 | 7,928 | 10 | 113 | 0 | 7,928 | 34 |
| **2015** | 6,595 | 6,494 | 139 | 94 | 0 | 6,494 | 43 |
| **2016** | 6,517 | 6,449 | 5,474 | 791 | 0 | 6,449 | 53 |
| **2017** | 18,113 | 14,642 | 13,063 | 1,801 | 0 | 14,642 | 89 |
| **2018** | 18,154 | 16,510 | 15,199 | 1,852 | 0 | 16,510 | 76 |
| **2019** | 18,938 | 17,305 | 9,658 | 9,224 | 0 | 17,305 | 128 |
| **2020** | 19,222 | 18,322 | 2,658 | 18,322 | 0 | 18,322 | 146 |
| **2021** | 21,950 | 20,149 | 1,644 | 20,045 | 0 | 20,149 | 213 |
| **2022** | 26,431 | 13,223 | 2,000 | 24,978 | 0 | 25,074 | 130 |
| **2023** | 30,949 | 1,926 | 1,160 | 28,816 | 0 | 28,817 | 164 |
| **2024** | 40,704 | 2,971 | 1,912 | 39,102 | 12,045 | 39,959 | 160 |
| **2025** | 49,972 | 5,899 | 1,150 | 44,081 | 13,510 | 48,167 | 194 |
| **2026** | 41,270 | 3,644 | 455 | 37,523 | 4,409 | 39,962 | 100 |

---

## 9. Generated Research Figures

The following figure artifacts were generated and saved to `docs/research/figures/phase2/`:

1. `cvss_distributions.png`: Boxplot comparison of CVSS v2, v3.0, v3.1, and v4.0 score distributions.
2. `temporal_availability_by_year.png`: CVE volume and feature availability trajectory from 2000 to 2026.
3. `epss_distribution_and_percentiles.png`: Density plot and percentile curve of EPSS scores.
4. `kev_publication_to_added_delay.png`: Delay distribution between NVD publication and KEV addition.
5. `kev_class_imbalance.png`: Visual representation of KEV binary class imbalance (0.45% positive rate).
