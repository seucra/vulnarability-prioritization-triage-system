"""
Vendor Statements Processor for Phase 1 ETL Pipeline.
Extracts vendor_statements.parquet from gzipped Vendor Statements XML feed.
"""

import gzip
import logging
import xml.etree.ElementTree as ET
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)


def process_vendor_statements(vendor_path: Path) -> pd.DataFrame:
    """
    Process raw Vendor Statements gzipped XML feed.
    Returns DataFrame matching VENDOR_STATEMENTS_SCHEMA.
    """
    logger.info(f"Processing Vendor Statements file: {vendor_path.name}")

    vendor_records = []

    with gzip.open(vendor_path, "rb") as gz:
        tree = ET.parse(gz)
        root = tree.getroot()

    statements = list(root)
    for s in statements:
        cve_id = s.attrib.get("cvename")
        if not cve_id:
            continue

        stmt_text = (s.text or "").strip()
        org = s.attrib.get("organization")
        last_mod = s.attrib.get("lastmodified")
        contrib = s.attrib.get("contributor")

        vendor_records.append({
            "cve_id": cve_id.strip(),
            "statement": stmt_text,
            "organization": org.strip() if org else None,
            "last_modified": last_mod.strip() if last_mod else None,
            "contributor": contrib.strip() if contrib else None,
        })

    df_vendor = pd.DataFrame(vendor_records)
    logger.info(f"Extracted {len(df_vendor):,} Vendor Statement records targeting {df_vendor['cve_id'].nunique():,} unique CVEs")
    return df_vendor
