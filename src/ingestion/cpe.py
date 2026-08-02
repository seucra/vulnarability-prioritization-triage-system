"""
CPE Configuration Processor for Phase 1 ETL Pipeline.
Extracts cve_cpe.parquet from NVD CVE yearly feeds configuration nodes.
"""

import gzip
import json
import logging
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import pandas as pd

logger = logging.getLogger(__name__)


def parse_cpe23_uri(cpe_uri: str) -> Tuple[Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str], Optional[str]]:
    """
    Deterministically parse standard CPE 2.3 formatted string.
    Format: cpe:2.3:part:vendor:product:version:update:edition:language:...
    """
    if not cpe_uri or not cpe_uri.startswith("cpe:2.3:"):
        return None, None, None, None, None, None, None

    tokens = cpe_uri.split(":")
    part = tokens[2] if len(tokens) > 2 else None
    vendor = tokens[3] if len(tokens) > 3 else None
    product = tokens[4] if len(tokens) > 4 else None
    version = tokens[5] if len(tokens) > 5 else None
    update = tokens[6] if len(tokens) > 6 else None
    edition = tokens[7] if len(tokens) > 7 else None
    language = tokens[8] if len(tokens) > 8 else None

    return part, vendor, product, version, update, edition, language


def process_cpe_configurations(raw_nvd_dir: Path) -> pd.DataFrame:
    """
    Extract CPE platform applicability records from NVD CVE yearly feeds configuration nodes.
    Returns DataFrame matching CVE_CPE_SCHEMA.
    """
    yearly_files = sorted(raw_nvd_dir.glob("nvdcve-2.0-20*.json.gz"))
    cpe_records: List[Dict] = []

    for fp in yearly_files:
        logger.info(f"Extracting CPE configurations from NVD feed: {fp.name}")

        with gzip.open(fp, "rb") as gz:
            data = json.load(gz)

        items = data.get("vulnerabilities", [])

        for item in items:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id")

            if not cve_id:
                continue

            configs = cve_obj.get("configurations", [])
            for config in configs:
                operator = config.get("operator")
                nodes = config.get("nodes", [])

                # Process nodes recursively if nested, or list of nodes
                def extract_matches(node_list, parent_operator=None):
                    for node in node_list:
                        node_op = node.get("operator") or parent_operator or operator
                        cpe_matches = node.get("cpeMatch", [])
                        for match in cpe_matches:
                            criteria = match.get("criteria") or match.get("cpe23Uri")
                            if not criteria:
                                continue

                            vulnerable = bool(match.get("vulnerable", False))
                            v_start_inc = match.get("versionStartIncluding")
                            v_start_exc = match.get("versionStartExcluding")
                            v_end_inc = match.get("versionEndIncluding")
                            v_end_exc = match.get("versionEndExcluding")

                            part, vendor, product, version, update, edition, language = parse_cpe23_uri(criteria)

                            cpe_records.append({
                                "cve_id": cve_id,
                                "cpe23_uri": criteria,
                                "vulnerable": vulnerable,
                                "version_start_including": v_start_inc,
                                "version_start_excluding": v_start_exc,
                                "version_end_including": v_end_inc,
                                "version_end_excluding": v_end_exc,
                                "operator": node_op,
                                "part": part,
                                "vendor": vendor,
                                "product": product,
                                "version": version,
                                "update": update,
                                "edition": edition,
                                "language": language,
                            })

                        # Recursive call if node contains children
                        children = node.get("children", [])
                        if children:
                            extract_matches(children, parent_operator=node_op)

                extract_matches(nodes, parent_operator=operator)

    df_cpe = pd.DataFrame(cpe_records)
    logger.info(f"Extracted {len(df_cpe):,} total CVE-CPE applicability records")
    return df_cpe
