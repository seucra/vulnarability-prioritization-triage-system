"""
NVD Feed Processor for Phase 1 ETL Pipeline.
Extracts vulnerabilities.parquet and cve_cwe.parquet from NVD API 2.0 yearly feeds.
"""

import gzip
import json
import logging
from pathlib import Path
from typing import Dict, List, Tuple

import pandas as pd

logger = logging.getLogger(__name__)


def parse_cvss_metric(metric_list: list) -> Tuple[float, str, str]:
    """Select Primary metric from NVD CVSS metric list if available, else first item."""
    if not metric_list:
        return None, None, None

    primary_item = next((m for m in metric_list if m.get("type") == "Primary"), metric_list[0])
    cvss_data = primary_item.get("cvssData", {})

    base_score = cvss_data.get("baseScore")
    if base_score is not None:
        try:
            base_score = float(base_score)
        except (ValueError, TypeError):
            base_score = None

    vector_string = cvss_data.get("vectorString")
    severity = cvss_data.get("baseSeverity") or primary_item.get("baseSeverity")

    return base_score, vector_string, severity


def process_nvd_feeds(raw_nvd_dir: Path) -> Tuple[pd.DataFrame, pd.DataFrame]:
    """
    Process 25 yearly NVD feed files (2002-2026).
    Excludes modified and recent feeds to ensure canonical uniqueness.
    Returns (df_vulnerabilities, df_cve_cwe).
    """
    yearly_files = sorted(raw_nvd_dir.glob("nvdcve-2.0-20*.json.gz"))
    logger.info(f"Found {len(yearly_files)} yearly NVD feed files in {raw_nvd_dir}")

    vuln_records: List[Dict] = []
    cwe_records: List[Dict] = []

    seen_cves = set()

    for fp in yearly_files:
        try:
            filename_year = int(fp.name.split("-")[2].split(".")[0])
        except (IndexError, ValueError):
            filename_year = None

        logger.info(f"Ingesting NVD feed: {fp.name}")

        with gzip.open(fp, "rb") as gz:
            data = json.load(gz)

        items = data.get("vulnerabilities", [])

        for item in items:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id")

            if not cve_id:
                continue

            if cve_id in seen_cves:
                logger.warning(f"Duplicate CVE ID encountered across yearly feeds: {cve_id}")
                continue
            seen_cves.add(cve_id)

            published = cve_obj.get("published")
            last_modified = cve_obj.get("lastModified")

            # Parse publication_year directly from authoritative published timestamp string
            if published and len(published) >= 4 and published[:4].isdigit():
                pub_year = int(published[:4])
            else:
                pub_year = filename_year

            # English description
            descs = cve_obj.get("descriptions", [])
            desc_en = next((d.get("value") for d in descs if d.get("lang") == "en"), None)

            # Metrics
            metrics = cve_obj.get("metrics", {})

            # CVSS v2
            v2_score, v2_vec, v2_sev = parse_cvss_metric(metrics.get("cvssMetricV2", []))
            has_v2 = v2_score is not None

            # CVSS v3.0
            v30_score, v30_vec, v30_sev = parse_cvss_metric(metrics.get("cvssMetricV30", []))
            has_v30 = v30_score is not None

            # CVSS v3.1
            v31_score, v31_vec, v31_sev = parse_cvss_metric(metrics.get("cvssMetricV31", []))
            has_v31 = v31_score is not None

            # CVSS v4.0
            v40_score, v40_vec, v40_sev = parse_cvss_metric(metrics.get("cvssMetricV40", []))
            has_v40 = v40_score is not None

            # References
            refs = cve_obj.get("references", [])
            ref_count = len(refs)

            # Configurations
            configs = cve_obj.get("configurations", [])
            has_configs = bool(configs)

            # Weaknesses / CWE
            weaknesses = cve_obj.get("weaknesses", [])
            has_cwe = False

            for weakness in weaknesses:
                desc_items = weakness.get("description", [])
                for d in desc_items:
                    cwe_val = d.get("value")
                    lang = d.get("lang", "en")
                    if cwe_val:
                        has_cwe = True
                        cwe_val_clean = cwe_val.strip()
                        is_semantic = cwe_val_clean.startswith("CWE-") and cwe_val_clean[4:].isdigit()
                        cwe_records.append({
                            "cve_id": cve_id,
                            "cwe_id": cwe_val_clean,
                            "language": lang,
                            "source_description": cwe_val_clean,
                            "is_semantic_cwe": is_semantic,
                        })

            vuln_records.append({
                "cve_id": cve_id,
                "published": published,
                "last_modified": last_modified,
                "publication_year": pub_year,
                "description_en": desc_en,
                "cvss_v2_base_score": v2_score,
                "cvss_v2_vector": v2_vec,
                "cvss_v2_severity": v2_sev,
                "cvss_v30_base_score": v30_score,
                "cvss_v30_vector": v30_vec,
                "cvss_v30_severity": v30_sev,
                "cvss_v31_base_score": v31_score,
                "cvss_v31_vector": v31_vec,
                "cvss_v31_severity": v31_sev,
                "cvss_v40_base_score": v40_score,
                "cvss_v40_vector": v40_vec,
                "cvss_v40_severity": v40_sev,
                "reference_count": ref_count,
                "has_cwe": has_cwe,
                "has_cpe_configuration": has_configs,
                "has_cvss_v2": has_v2,
                "has_cvss_v30": has_v30,
                "has_cvss_v31": has_v31,
                "has_cvss_v40": has_v40,
            })

    df_vulns = pd.DataFrame(vuln_records)
    df_cwe = pd.DataFrame(cwe_records)

    logger.info(f"Processed {len(df_vulns):,} total vulnerabilities from yearly NVD feeds")
    logger.info(f"Extracted {len(df_cwe):,} CVE-CWE mapping records")

    return df_vulns, df_cwe
