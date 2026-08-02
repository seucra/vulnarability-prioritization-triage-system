"""
EPSS Processor for Phase 1 ETL Pipeline.
Extracts epss.parquet from gzipped EPSS CSV snapshot.
"""

import csv
import gzip
import logging
from pathlib import Path

import pandas as pd

logger = logging.getLogger(__name__)


def process_epss(epss_path: Path) -> pd.DataFrame:
    """
    Process raw EPSS snapshot CSV file.
    Preserves epss score, percentile, score_date, and model_version provenance.
    Returns DataFrame matching EPSS_SCHEMA.
    """
    logger.info(f"Processing EPSS snapshot file: {epss_path.name}")

    header_comments = []
    model_version = "v2026.06.15"
    score_date = "2026-07-16T12:03:48Z"

    epss_records = []

    with gzip.open(epss_path, "rt", encoding="utf-8") as gz:
        for line in gz:
            if line.startswith("#"):
                header_comments.append(line.strip())
                parts = line.strip("#").strip().split(",")
                for part in parts:
                    if "model_version" in part:
                        model_version = part.split(":")[-1].strip()
                    if "score_date" in part:
                        score_date = part.split(":", 1)[-1].strip()
            else:
                # First non-comment line is CSV header 'cve,epss,percentile'
                header_cols = [c.strip() for c in line.strip().split(",")]
                break

        reader = csv.reader(gz)
        for row in reader:
            if not row or len(row) < 3:
                continue

            cve_id = row[0].strip()
            try:
                epss_val = float(row[1].strip())
                perc_val = float(row[2].strip())
            except ValueError:
                continue

            epss_records.append({
                "cve_id": cve_id,
                "epss": epss_val,
                "percentile": perc_val,
                "score_date": score_date,
                "model_version": model_version,
            })

    df_epss = pd.DataFrame(epss_records)
    logger.info(f"Extracted {len(df_epss):,} EPSS records (Snapshot Date: {score_date}, Model: {model_version})")
    return df_epss
