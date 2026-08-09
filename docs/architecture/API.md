# Phase 4 — REST API Specification

**Repository**: `seucra/vulnarability-prioritization-triage-system`  
**Base URL**: `http://localhost:5002/api/v1`  
**Interactive OpenAPI Documentation**: `http://localhost:5002/api/v1/docs`  

---

## 1. Vulnerability Endpoints

### `GET /api/v1/vulnerabilities`
Search and filter canonical vulnerabilities dataset.

**Query Parameters**:
- `q` (string, optional): Free text keyword search in vulnerability description.
- `cve_id` (string, optional): Substring filter for CVE ID (e.g., `CVE-2023-`).
- `cwe_id` (string, optional): Exact CWE ID (e.g., `CWE-79`).
- `vendor` (string, optional): CPE vendor substring.
- `product` (string, optional): CPE product substring.
- `min_cvss` (float, optional): Min CVSS v3.1 score $[0.0, 10.0]$.
- `max_cvss` (float, optional): Max CVSS v3.1 score $[0.0, 10.0]$.
- `is_kev` (boolean, optional): Filter by CISA KEV listing status.
- `min_epss` (float, optional): Min EPSS snapshot score $[0.0, 1.0]$.
- `publication_year` (integer, optional): Publication year ($2002–2026$).
- `page` (integer, default=1): Page number.
- `page_size` (integer, default=20, max=100): Page size.
- `sort_by` (string, default='published'): Sort column (`published`, `cve_id`, `cvss_v31_base_score`, `epss`).
- `sort_dir` (string, default='desc'): Sort direction (`asc` or `desc`).

**Example Response**:
```json
{
  "items": [
    {
      "cve_id": "CVE-2021-44228",
      "publication_year": 2021,
      "published": "2021-12-10T10:15:00Z",
      "description_en": "Apache Log4j2 2.0-beta9 through 2.15.0 JNDI features used in configuration...",
      "cvss_v31_base_score": 10.0,
      "cvss_v31_base_severity": "CRITICAL",
      "epss": {
        "epss_score": 0.9754,
        "epss_percentile": 0.9998,
        "snapshot_date": "2026-07-16T12:03:48Z",
        "model_version": "v2026.06.15",
        "is_historical_prediction_input": false
      },
      "is_kev": true
    }
  ],
  "total": 366547,
  "page": 1,
  "page_size": 20,
  "total_pages": 18328
}
```

---

### `GET /api/v1/vulnerabilities/{cve_id}`
Retrieve complete detail record for a single vulnerability.

**Example Response**:
```json
{
  "cve_id": "CVE-2021-44228",
  "publication_year": 2021,
  "published": "2021-12-10T10:15:00Z",
  "authoritative_cvss_v31_base_score": 10.0,
  "cvss_v31_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
  "cvss_v31_base_severity": "CRITICAL",
  "has_cwe": true,
  "has_cpe_configuration": true,
  "epss": {
    "epss_score": 0.9754,
    "epss_percentile": 0.9998,
    "snapshot_date": "2026-07-16T12:03:48Z",
    "model_version": "v2026.06.15",
    "is_historical_prediction_input": false
  },
  "is_kev": true,
  "cwes": [{"cwe_id": "CWE-502", "is_semantic_cwe": true}],
  "cpes": [{"part": "a", "vendor": "apache", "product": "log4j", "version": "2.14.1", "is_vulnerable": true}]
}
```

---

## 2. Model Prediction Endpoints

### `POST /api/v1/predict/cvss`
Estimate CVSS v3.1 base score using EXP-A1 XGBoost Regressor.

**Request Payload**:
```json
{
  "description_en": "An unauthenticated remote code execution vulnerability in Apache Log4j2 JNDI feature allows full system takeover.",
  "cwe_ids": ["CWE-502"],
  "cpe_count": 5,
  "cpe_part_a_count": 5,
  "cpe_part_o_count": 0,
  "cpe_part_h_count": 0,
  "vendor_count": 1,
  "product_count": 1,
  "pub_month": 12
}
```

**Example Response**:
```json
{
  "predicted_cvss_v31_base_score": 9.68,
  "authoritative_cvss_v31_base_score": 10.0,
  "prediction_label": "Predicted CVSS v3.1 Base Score",
  "model_name": "EXP-A1 XGBoost Regressor",
  "mae_test_benchmark": 0.975,
  "disclaimer": "Estimated pre-scoring value derived strictly from initial description text and metadata. Not an official NVD/CNA analyst score."
}
```

---

### `POST /api/v1/predict/kev`
Predict publication-time CISA KEV catalog inclusion probability using EXP-B2 XGBoost Classifier.

> **Strict Boundary Notice**: Sending post-publication EPSS or CVSS vector components will trigger HTTP 422 Unprocessable Entity error.

**Request Payload**:
```json
{
  "description_en": "A buffer overflow vulnerability in openvpn allows remote unauthenticated memory corruption.",
  "cwe_ids": ["CWE-120"],
  "cpe_count": 2,
  "cpe_part_a_count": 1,
  "cpe_part_o_count": 1,
  "cpe_part_h_count": 0,
  "vendor_count": 1,
  "product_count": 1,
  "pub_month": 5
}
```

**Example Response**:
```json
{
  "predicted_kev_probability": 0.38451,
  "risk_classification": "ELEVATED_RISK",
  "prediction_point": "CVE Publication / Initial Triage",
  "model_name": "EXP-B2 XGBoost Classifier",
  "pr_auc_test_benchmark": 0.02884,
  "uplift_vs_random": "8.96x precision multiplier over random baseline (0.00322)",
  "target_definition": "Probability of future CISA KEV catalog inclusion (proxy for exploitation)"
}
```

---

## 3. Prioritization Endpoint

### `POST /api/v1/prioritize`
Computes priority scores under Mode 1 (Linear Equal Weights) and Mode 2 (Nonlinear Interactive Surface).

**Request Payload**:
```json
{
  "cve_id": "CVE-2021-44228",
  "cvss_score": 10.0,
  "epss_score": 0.95,
  "is_kev": true,
  "asset_criticality": 1.0
}
```

**Example Response**:
```json
{
  "cve_id": "CVE-2021-44228",
  "linear_baseline_mode_1": {
    "priority_score": 0.9875,
    "scoring_mode": "MODE 1 — Transparent Linear Baseline (Project-Controlled Equal Weights)",
    "asset_criticality_tier": "Tier 4 (Critical Infrastructure: 1.00)",
    "asset_criticality_x4": 1.0,
    "inputs": {
      "normalized_cvss_x1": 1.0,
      "epss_probability_x2": 0.95,
      "is_kev_x3": 1.0,
      "asset_criticality_x4": 1.0
    }
  },
  "nonlinear_surface_mode_2": {
    "priority_score": 1.0,
    "scoring_mode": "MODE 2 — Nonlinear Interactive Decision Surface (alpha=1.0, beta=1.5)",
    "asset_criticality_tier": "Tier 4 (Critical Infrastructure: 1.00)",
    "asset_criticality_x4": 1.0,
    "inputs": {
      "normalized_cvss_x1": 1.0,
      "epss_probability_x2": 0.95,
      "is_kev_x3": 1.0,
      "asset_criticality_x4": 1.0
    }
  },
  "methodology_note": "Mode 1 uses project-controlled equal weights (0.25 CVSS, 0.25 EPSS, 0.25 KEV, 0.25 Asset). Mode 2 uses non-additive interactive surface scaling (alpha=1.0, beta=1.5)."
}
```

---

## 4. SHAP Explanation Endpoints

### `POST /api/v1/explain/cvss`
Computes local SHAP feature attributions on the EXP-A1 CVSS Regressor.

### `POST /api/v1/explain/kev`
Computes local SHAP feature attributions on the EXP-B2 KEV Classifier.

---

## 5. Research Provenance Endpoint

### `GET /api/v1/provenance`
Returns system provenance metadata, dataset freeze manifest, partition bounds, Phase 3 experiment metrics, and research limitations.
