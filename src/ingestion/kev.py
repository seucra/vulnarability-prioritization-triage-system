"""
CISA KEV Processor for Phase 1 ETL Pipeline.
Extracts kev.parquet from raw CISA KEV CSV catalog.
"""

import csv
import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)


def process_kev(kev_path: Path) -> pd.DataFrame:
    """
    Process CISA Known Exploited Vulnerabilities catalog CSV.
    Preserves all 11 authoritative fields.
    Returns DataFrame matching KEV_SCHEMA.
    """
    logger.info(f"Processing CISA KEV catalog file: {kev_path.name}")

    kev_records = []

    with open(kev_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            cve_id = row.get("cveID") or row.get("CVE ID")
            if not cve_id:
                continue

            kev_records.append({
                "cve_id": cve_id.strip(),
                "vendor_project": row.get("vendorProject", "").strip(),
                "product": row.get("product", "").strip(),
                "vulnerability_name": row.get("vulnerabilityName", "").strip(),
                "date_added": row.get("dateAdded", "").strip(),
                "short_description": row.get("shortDescription", "").strip(),
                "required_action": row.get("requiredAction", "").strip(),
                "due_date": row.get("dueDate", "").strip(),
                "known_ransomware_campaign_use": row.get("knownRansomwareCampaignUse", "").strip(),
                "notes": row.get("notes", "").strip(),
                "cwes": row.get("cwes", "").strip(),
            })

    df_kev = pd.DataFrame(kev_records)
    logger.info(f"Extracted {len(df_kev):,} CISA KEV records")
    return df_kev
