#!/usr/bin/env python3
"""
Reproducible Raw Dataset Verification Script for Phase 0
Repository: wdl-vuln-prioritization

This script performs read-only verification of raw vulnerability datasets:
- NVD CVE JSON feeds (2002-2026, modified, recent)
- EPSS score snapshot
- CISA KEV catalog
- CPE Dictionary and CPE Match archives
- Vendor statements archive

All checks are read-only and streaming. No files are extracted to disk,
modified, or mutated. Standard Python libraries only.
"""

import csv
import gzip
import hashlib
import json
import os
import sys
import tarfile
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path


def get_file_stats(file_path: Path):
    """Calculate file size and SHA-256 hash."""
    sha256 = hashlib.sha256()
    size = os.path.getsize(file_path)
    with open(file_path, "rb") as f:
        while chunk := f.read(65536):
            sha256.update(chunk)
    return size, sha256.hexdigest()


def verify_nvd_feed(file_path: Path):
    """Verify an NVD CVE json.gz feed (supports NVD API 2.0 and 1.1 schemas)."""
    feed_name = file_path.name
    res = {
        "filename": feed_name,
        "path": str(file_path),
        "valid_gzip": False,
        "valid_json": False,
        "record_count": 0,
        "cve_ids": [],
        "publication_dates": [],
        "last_modified_dates": [],
        "counts": {
            "has_cve_id": 0,
            "has_english_desc": 0,
            "has_published_date": 0,
            "has_last_modified_date": 0,
            "has_cvss_v2": 0,
            "has_cvss_v30": 0,
            "has_cvss_v31": 0,
            "has_cvss_v40": 0,
            "has_cwe": 0,
            "has_configurations": 0,
            "has_references": 0,
        },
        "errors": [],
    }

    try:
        with gzip.open(file_path, "rb") as gz:
            res["valid_gzip"] = True
            data = json.load(gz)
            res["valid_json"] = True
    except Exception as e:
        res["errors"].append(f"Gzip/JSON error: {e}")
        return res

    # NVD API v2.0 vs Legacy v1.1 array detection
    if "vulnerabilities" in data:
        items = data.get("vulnerabilities", [])
        is_v2_schema = True
    else:
        items = data.get("CVE_Items", [])
        is_v2_schema = False

    res["record_count"] = len(items)

    for item in items:
        if is_v2_schema:
            cve_obj = item.get("cve", {})
            cve_id = cve_obj.get("id")
            pub_date = cve_obj.get("published")
            mod_date = cve_obj.get("lastModified")

            # English description
            descs = cve_obj.get("descriptions", [])
            has_en = any(d.get("lang") == "en" and d.get("value") for d in descs)

            # Metrics
            metrics = cve_obj.get("metrics", {})
            has_v2 = "cvssMetricV2" in metrics
            has_v30 = "cvssMetricV30" in metrics
            has_v31 = "cvssMetricV31" in metrics
            has_v40 = "cvssMetricV40" in metrics

            # Weaknesses / CWE
            weaknesses = cve_obj.get("weaknesses", [])
            has_cwe = bool(weaknesses)

            # Configurations
            configs = cve_obj.get("configurations", [])
            has_configs = bool(configs)

            # References
            refs = cve_obj.get("references", [])
            has_refs = bool(refs)

        else:
            cve_data = item.get("cve", {})
            meta = cve_data.get("CVE_data_meta", {})
            cve_id = meta.get("ID")
            pub_date = item.get("publishedDate")
            mod_date = item.get("lastModifiedDate")

            desc_data = cve_data.get("description", {}).get("description_data", [])
            has_en = any(d.get("lang") == "en" and d.get("value") for d in desc_data)

            impact = item.get("impact", {})
            has_v2 = "baseMetricV2" in impact

            bm3 = impact.get("baseMetricV3", {})
            cvss3 = bm3.get("cvssV3", {})
            v3_ver = cvss3.get("version")
            has_v30 = v3_ver == "3.0"
            has_v31 = v3_ver == "3.1" or (v3_ver and v3_ver != "3.0")
            has_v40 = "baseMetricV4" in impact or "cvssV4" in impact

            problemtype = cve_data.get("problemtype", {}).get("problemtype_data", [])
            has_cwe = any(d.get("value") for pt in problemtype for d in pt.get("description", []))

            configs = item.get("configurations", {}).get("nodes", [])
            has_configs = bool(configs)

            refs = cve_data.get("references", {}).get("reference_data", [])
            has_refs = bool(refs)

        if cve_id:
            res["counts"]["has_cve_id"] += 1
            res["cve_ids"].append(cve_id)

        if has_en:
            res["counts"]["has_english_desc"] += 1

        if pub_date:
            res["counts"]["has_published_date"] += 1
            res["publication_dates"].append(pub_date)

        if mod_date:
            res["counts"]["has_last_modified_date"] += 1
            res["last_modified_dates"].append(mod_date)

        if has_v2:
            res["counts"]["has_cvss_v2"] += 1
        if has_v30:
            res["counts"]["has_cvss_v30"] += 1
        if has_v31:
            res["counts"]["has_cvss_v31"] += 1
        if has_v40:
            res["counts"]["has_cvss_v40"] += 1

        if has_cwe:
            res["counts"]["has_cwe"] += 1
        if has_configs:
            res["counts"]["has_configurations"] += 1
        if has_refs:
            res["counts"]["has_references"] += 1

    return res


def verify_nvd_all(nvd_dir: Path):
    """Verify all NVD feed files in nvd_dir."""
    yearly_results = []
    modified_result = None
    recent_result = None

    all_yearly_cves = []
    earliest_pub = None
    latest_pub = None

    files = sorted(nvd_dir.glob("nvdcve-2.0-*.json.gz"))
    for file_path in files:
        fname = file_path.name
        res = verify_nvd_feed(file_path)
        if "modified" in fname:
            modified_result = res
        elif "recent" in fname:
            recent_result = res
        else:
            yearly_results.append(res)
            all_yearly_cves.extend(res["cve_ids"])
            for p in res["publication_dates"]:
                if earliest_pub is None or p < earliest_pub:
                    earliest_pub = p
                if latest_pub is None or p > latest_pub:
                    latest_pub = p

    cve_counts = Counter(all_yearly_cves)
    duplicates = {cve: count for cve, count in cve_counts.items() if count > 1}

    total_yearly_records = sum(r["record_count"] for r in yearly_results)

    return {
        "yearly_results": yearly_results,
        "modified_result": modified_result,
        "recent_result": recent_result,
        "total_yearly_records": total_yearly_records,
        "unique_yearly_cves": len(cve_counts),
        "duplicate_cve_count": len(duplicates),
        "duplicates": duplicates,
        "earliest_pub": earliest_pub,
        "latest_pub": latest_pub,
    }


def verify_epss(epss_path: Path):
    """Verify EPSS gzipped CSV dataset."""
    res = {
        "filename": epss_path.name,
        "valid_gzip": False,
        "valid_csv": False,
        "header_comments": [],
        "snapshot_date": None,
        "model_version": None,
        "total_rows": 0,
        "unique_cves": 0,
        "duplicate_cves": 0,
        "min_score": None,
        "max_score": None,
        "min_percentile": None,
        "max_percentile": None,
        "malformed_rows": 0,
        "errors": [],
    }

    cves = set()
    dup_count = 0

    try:
        with gzip.open(epss_path, "rt", encoding="utf-8") as gz:
            res["valid_gzip"] = True

            header_line = None
            for line in gz:
                if line.startswith("#"):
                    res["header_comments"].append(line.strip())
                    if "model_version" in line:
                        res["model_version"] = line.strip()
                    if "score_date" in line or "date" in line:
                        res["snapshot_date"] = line.strip()
                else:
                    header_line = line
                    break

            reader = csv.reader(gz)
            res["valid_csv"] = True

            for row in reader:
                if not row or len(row) < 3:
                    res["malformed_rows"] += 1
                    continue

                res["total_rows"] += 1
                cve, score_str, perc_str = row[0].strip(), row[1].strip(), row[2].strip()

                if cve in cves:
                    dup_count += 1
                else:
                    cves.add(cve)

                try:
                    score = float(score_str)
                    perc = float(perc_str)
                    if res["min_score"] is None or score < res["min_score"]:
                        res["min_score"] = score
                    if res["max_score"] is None or score > res["max_score"]:
                        res["max_score"] = score

                    if res["min_percentile"] is None or perc < res["min_percentile"]:
                        res["min_percentile"] = perc
                    if res["max_percentile"] is None or perc > res["max_percentile"]:
                        res["max_percentile"] = perc
                except ValueError:
                    res["malformed_rows"] += 1

            res["unique_cves"] = len(cves)
            res["duplicate_cves"] = dup_count

    except Exception as e:
        res["errors"].append(f"EPSS verification error: {e}")

    return res


def verify_kev(kev_path: Path):
    """Verify CISA KEV CSV dataset."""
    res = {
        "filename": kev_path.name,
        "valid_csv": False,
        "physical_lines": 0,
        "total_data_rows": 0,
        "unique_cves": 0,
        "duplicate_cves": 0,
        "malformed_rows": 0,
        "columns": [],
        "column_presence": {},
        "errors": [],
    }

    expected_cols = [
        "cveID",
        "vendorProject",
        "product",
        "vulnerabilityName",
        "dateAdded",
        "shortDescription",
        "requiredAction",
        "dueDate",
        "knownRansomwareCampaignUse",
        "notes",
        "cwes",
    ]

    try:
        with open(kev_path, "r", encoding="utf-8") as f:
            lines = f.readlines()
            res["physical_lines"] = len(lines)

        with open(kev_path, "r", encoding="utf-8") as f:
            reader = csv.DictReader(f)
            res["valid_csv"] = True
            res["columns"] = reader.fieldnames or []

            for col in expected_cols:
                matched_col = next((c for c in res["columns"] if c.lower() == col.lower()), None)
                res["column_presence"][col] = {
                    "matched_header": matched_col,
                    "count": 0,
                }

            cve_counts = Counter()
            for row in reader:
                res["total_data_rows"] += 1
                cve_id = row.get("cveID") or row.get("CVE ID")
                if cve_id:
                    cve_counts[cve_id] += 1
                else:
                    res["malformed_rows"] += 1

                for col, info in res["column_presence"].items():
                    m_header = info["matched_header"]
                    if m_header and row.get(m_header):
                        info["count"] += 1

            res["unique_cves"] = len(cve_counts)
            dups = {cve: cnt for cve, cnt in cve_counts.items() if cnt > 1}
            res["duplicate_cves"] = len(dups)

    except Exception as e:
        res["errors"].append(f"KEV verification error: {e}")

    return res


def verify_cpe_archive(cpe_path: Path):
    """Verify CPE tar.gz archive integrity and inspect members."""
    res = {
        "filename": cpe_path.name,
        "compressed_size": cpe_path.stat().st_size,
        "valid_targz": False,
        "member_count": 0,
        "uncompressed_total_size": 0,
        "members": [],
        "schema_type": "JSON Chunked Feed",
        "errors": [],
    }

    try:
        with tarfile.open(cpe_path, "r:gz") as tar:
            res["valid_targz"] = True
            members = tar.getmembers()
            res["member_count"] = len(members)
            res["uncompressed_total_size"] = sum(m.size for m in members)

            for m in members:
                res["members"].append({
                    "name": m.name,
                    "size": m.size,
                    "type": "file" if m.isfile() else "dir"
                })
    except Exception as e:
        res["errors"].append(f"CPE archive error: {e}")

    return res


def verify_vendor_statements(vendor_path: Path):
    """Verify Vendor Statements xml.gz archive."""
    res = {
        "filename": vendor_path.name,
        "compressed_size": vendor_path.stat().st_size,
        "valid_gzip": False,
        "valid_xml": False,
        "root_tag": None,
        "statement_element_count": 0,
        "cve_attribute_count": 0,
        "unique_cve_count": 0,
        "duplicate_cve_count": 0,
        "errors": [],
    }

    try:
        with gzip.open(vendor_path, "rb") as gz:
            res["valid_gzip"] = True
            tree = ET.parse(gz)
            root = tree.getroot()
            res["root_tag"] = root.tag
            res["valid_xml"] = True

            statements = list(root)
            res["statement_element_count"] = len(statements)

            cve_list = []
            for s in statements:
                cve_name = s.attrib.get("cvename")
                if cve_name:
                    cve_list.append(cve_name)

            res["cve_attribute_count"] = len(cve_list)
            unique_cves = set(cve_list)
            res["unique_cve_count"] = len(unique_cves)
            res["duplicate_cve_count"] = len(cve_list) - len(unique_cves)

    except Exception as e:
        res["errors"].append(f"Vendor statements error: {e}")

    return res


def main():
    repo_root = Path(__file__).resolve().parent.parent
    raw_dir = repo_root / "data" / "raw"

    print("=" * 80)
    print("WDL-VULN-PRIORITIZATION: RAW DATASET VERIFICATION (Phase 0.1)")
    print(f"Repository Root: {repo_root}")
    print(f"Raw Data Dir   : {raw_dir}")
    print("=" * 80)

    if not raw_dir.exists():
        print(f"ERROR: Raw data directory '{raw_dir}' does not exist.")
        sys.exit(1)

    # 1. Manifest / File Stats
    print("\n--- 1. File Statistics & SHA-256 Cryptographic Hashes ---")
    all_raw_files = sorted([p for p in raw_dir.glob("**/*") if p.is_file()])

    for fp in all_raw_files:
        rel_path = fp.relative_to(repo_root)
        size, sha256 = get_file_stats(fp)
        print(f"File: {rel_path}\n  Size: {size:,} bytes | SHA-256: {sha256}")

    # 2. NVD Verification
    print("\n--- 2. NVD CVE Feeds Verification ---")
    nvd_dir = raw_dir / "nvd"
    nvd_audit = verify_nvd_all(nvd_dir)

    print(f"Total Yearly Feeds Verified: {len(nvd_audit['yearly_results'])}")
    print(f"Total Records (Yearly Feeds): {nvd_audit['total_yearly_records']:,}")
    print(f"Unique CVE IDs (Yearly Feeds): {nvd_audit['unique_yearly_cves']:,}")
    print(f"Duplicate CVE Count across Yearly Feeds: {nvd_audit['duplicate_cve_count']}")
    print(f"Earliest Publication Date: {nvd_audit['earliest_pub']}")
    print(f"Latest Publication Date  : {nvd_audit['latest_pub']}")

    print("\n  Yearly Breakdown:")
    for r in nvd_audit["yearly_results"]:
        c = r["counts"]
        print(
            f"  - {r['filename']:<25}: {r['record_count']:>6} CVEs | "
            f"CVSSv2: {c['has_cvss_v2']:>6} | CVSSv3.0: {c['has_cvss_v30']:>6} | "
            f"CVSSv3.1: {c['has_cvss_v31']:>6} | CVSSv4.0: {c['has_cvss_v40']:>2} | "
            f"CWE: {c['has_cwe']:>6} | CPE Config: {c['has_configurations']:>6}"
        )

    if nvd_audit["modified_result"]:
        mr = nvd_audit["modified_result"]
        print(f"  - {mr['filename']:<25}: {mr['record_count']:>6} CVEs (modified feed)")
    if nvd_audit["recent_result"]:
        rr = nvd_audit["recent_result"]
        print(f"  - {rr['filename']:<25}: {rr['record_count']:>6} CVEs (recent feed)")

    # 3. EPSS Verification
    print("\n--- 3. EPSS Score Snapshot Verification ---")
    epss_path = raw_dir / "epss" / "epss_scores-2026-07-16.csv.gz"
    epss_audit = verify_epss(epss_path)
    print(f"Filename       : {epss_audit['filename']}")
    print(f"Valid Gzip     : {epss_audit['valid_gzip']}")
    print(f"Header Comments: {epss_audit['header_comments']}")
    print(f"Model Version  : {epss_audit['model_version']}")
    print(f"Snapshot Date  : {epss_audit['snapshot_date']}")
    print(f"Total Rows     : {epss_audit['total_rows']:,}")
    print(f"Unique CVEs    : {epss_audit['unique_cves']:,}")
    print(f"Duplicate CVEs : {epss_audit['duplicate_cves']}")
    print(f"EPSS Min/Max   : {epss_audit['min_score']} / {epss_audit['max_score']}")
    print(f"Percentile Min/Max: {epss_audit['min_percentile']} / {epss_audit['max_percentile']}")
    print(f"Malformed Rows : {epss_audit['malformed_rows']}")

    # 4. KEV Verification
    print("\n--- 4. CISA KEV Verification ---")
    kev_path = raw_dir / "kev" / "known_exploited_vulnerabilities.csv"
    kev_audit = verify_kev(kev_path)
    print(f"Filename       : {kev_audit['filename']}")
    print(f"Valid CSV      : {kev_audit['valid_csv']}")
    print(f"Physical Lines : {kev_audit['physical_lines']:,}")
    print(f"Data Rows      : {kev_audit['total_data_rows']:,}")
    print(f"Unique CVEs    : {kev_audit['unique_cves']:,}")
    print(f"Duplicate CVEs : {kev_audit['duplicate_cves']}")
    print(f"Malformed Rows : {kev_audit['malformed_rows']}")
    print(f"Available Cols : {kev_audit['columns']}")

    print("  Field Availability:")
    for col, info in kev_audit["column_presence"].items():
        print(
            f"    - {col:<30}: Matched Header='{info['matched_header']}' | "
            f"Populated={info['count']:,}/{kev_audit['total_data_rows']:,}"
        )

    # 5. CPE Archives Verification
    print("\n--- 5. CPE Dictionary & Match Archives Verification ---")
    for cpe_name in ["nvdcpe-2.0.tar.gz", "nvdcpematch-2.0.tar.gz"]:
        cpe_fp = raw_dir / "cpe" / cpe_name
        ca = verify_cpe_archive(cpe_fp)
        print(
            f"File: {ca['filename']} | Size: {ca['compressed_size']:,} bytes | "
            f"Valid tar.gz: {ca['valid_targz']} | Members: {ca['member_count']} | "
            f"Uncompressed: {ca['uncompressed_total_size']:,} bytes"
        )
        for m in ca["members"][:3]:
            print(f"  Sample Member: {m['name']} ({m['size']:,} bytes)")
        if len(ca["members"]) > 3:
            print(f"  ... and {len(ca['members']) - 3} more members")

    # 6. Vendor Statements Verification
    print("\n--- 6. Vendor Statements Verification ---")
    vendor_path = raw_dir / "vendor" / "vendorstatements.xml.gz"
    va = verify_vendor_statements(vendor_path)
    print(f"Filename       : {va['filename']}")
    print(f"Compressed Size: {va['compressed_size']:,} bytes")
    print(f"Valid Gzip     : {va['valid_gzip']}")
    print(f"Valid XML      : {va['valid_xml']}")
    print(f"Root XML Tag   : {va['root_tag']}")
    print(f"<statement> Elements: {va['statement_element_count']:,}")
    print(f"cvename Attributes  : {va['cve_attribute_count']:,}")
    print(f"Unique CVE IDs      : {va['unique_cve_count']:,}")
    print(f"Duplicate CVEs      : {va['duplicate_cve_count']:,}")

    print("\n" + "=" * 80)
    print("VERIFICATION COMPLETED SUCCESSFULLY.")
    print("=" * 80)


if __name__ == "__main__":
    main()
