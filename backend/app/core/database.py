"""
DuckDB High-Performance Query Engine over Frozen Parquet Datasets
Repository: seucra/vulnarability-prioritization-triage-system
"""

from typing import Any, Dict, List, Optional, Tuple
import duckdb
import pandas as pd
from backend.app.config import settings


class DatabaseEngine:
    def __init__(self):
        self.vuln_parquet = str(settings.PROCESSED_DATA_DIR / "vulnerabilities.parquet")
        self.cwe_parquet = str(settings.PROCESSED_DATA_DIR / "cve_cwe.parquet")
        self.cpe_parquet = str(settings.PROCESSED_DATA_DIR / "cve_cpe.parquet")
        self.epss_parquet = str(settings.PROCESSED_DATA_DIR / "epss.parquet")
        self.kev_parquet = str(settings.PROCESSED_DATA_DIR / "kev.parquet")
        self.vendor_parquet = str(settings.PROCESSED_DATA_DIR / "vendor_statements.parquet")

    def get_connection(self) -> duckdb.DuckDBPyConnection:
        conn = duckdb.connect(database=":memory:", read_only=False)
        return conn

    def get_vulnerability_by_id(self, cve_id: str) -> Optional[Dict[str, Any]]:
        cve_id_clean = cve_id.strip().upper()
        conn = self.get_connection()
        
        query = f"""
            SELECT 
                v.cve_id,
                v.publication_year,
                v.published,
                v.last_modified,
                v.description_en,
                v.cvss_v31_base_score,
                v.cvss_v31_vector,
                v.cvss_v31_severity,
                v.has_cwe,
                v.has_cpe_configuration,
                e.epss AS epss_score,
                e.percentile AS epss_percentile,
                CASE WHEN k.cve_id IS NOT NULL THEN TRUE ELSE FALSE END AS is_kev,
                k.vendor_project AS kev_vendor_project,
                k.product AS kev_product,
                k.vulnerability_name AS kev_vulnerability_name,
                k.date_added AS kev_date_added,
                k.short_description AS kev_short_description,
                k.required_action AS kev_required_action,
                k.due_date AS kev_due_date,
                k.known_ransomware_campaign_use AS kev_ransomware_campaign_use
            FROM read_parquet('{self.vuln_parquet}') v
            LEFT JOIN read_parquet('{self.epss_parquet}') e ON v.cve_id = e.cve_id
            LEFT JOIN read_parquet('{self.kev_parquet}') k ON v.cve_id = k.cve_id
            WHERE UPPER(v.cve_id) = ?
            LIMIT 1
        """
        res = conn.execute(query, [cve_id_clean]).df()
        conn.close()
        
        if res.empty:
            return None
            
        row = res.iloc[0].to_dict()
        
        for k, val in row.items():
            if pd.isna(val):
                row[k] = None
                
        cwe_conn = self.get_connection()
        cwes = cwe_conn.execute(
            f"SELECT cwe_id, is_semantic_cwe FROM read_parquet('{self.cwe_parquet}') WHERE cve_id = ?",
            [cve_id_clean]
        ).df().to_dict(orient="records")
        row["cwes"] = cwes
        
        cpes = cwe_conn.execute(
            f"SELECT part, vendor, product, version, vulnerable AS is_vulnerable FROM read_parquet('{self.cpe_parquet}') WHERE cve_id = ? LIMIT 20",
            [cve_id_clean]
        ).df().to_dict(orient="records")
        row["cpes"] = cpes
        
        statements = cwe_conn.execute(
            f"SELECT organization, last_modified, statement FROM read_parquet('{self.vendor_parquet}') WHERE cve_id = ?",
            [cve_id_clean]
        ).df().to_dict(orient="records")
        row["vendor_statements"] = statements
        cwe_conn.close()
        
        return row

    def search_vulnerabilities(
        self,
        q: Optional[str] = None,
        cve_id: Optional[str] = None,
        cwe_id: Optional[str] = None,
        vendor: Optional[str] = None,
        product: Optional[str] = None,
        min_cvss: Optional[float] = None,
        max_cvss: Optional[float] = None,
        is_kev: Optional[bool] = None,
        min_epss: Optional[float] = None,
        publication_year: Optional[int] = None,
        page: int = 1,
        page_size: int = 20,
        sort_by: str = "published",
        sort_dir: str = "desc"
    ) -> Tuple[List[Dict[str, Any]], int]:
        conn = self.get_connection()
        where_clauses = ["1=1"]
        params = []
        
        if cve_id:
            where_clauses.append("UPPER(v.cve_id) LIKE ?")
            params.append(f"%{cve_id.strip().upper()}%")
            
        if q:
            where_clauses.append("LOWER(v.description_en) LIKE ?")
            params.append(f"%{q.strip().lower()}%")
            
        if min_cvss is not None:
            where_clauses.append("v.cvss_v31_base_score >= ?")
            params.append(min_cvss)
            
        if max_cvss is not None:
            where_clauses.append("v.cvss_v31_base_score <= ?")
            params.append(max_cvss)
            
        if publication_year is not None:
            where_clauses.append("v.publication_year = ?")
            params.append(publication_year)
            
        if min_epss is not None:
            where_clauses.append("e.epss >= ?")
            params.append(min_epss)
            
        if is_kev is not None:
            if is_kev:
                where_clauses.append("k.cve_id IS NOT NULL")
            else:
                where_clauses.append("k.cve_id IS NULL")

        if cwe_id:
            where_clauses.append(f"v.cve_id IN (SELECT cve_id FROM read_parquet('{self.cwe_parquet}') WHERE UPPER(cwe_id) = ?)")
            params.append(cwe_id.strip().upper())
            
        if vendor or product:
            cpe_sub = f"SELECT cve_id FROM read_parquet('{self.cpe_parquet}') WHERE 1=1"
            if vendor:
                cpe_sub += " AND LOWER(vendor) LIKE ?"
                params.append(f"%{vendor.strip().lower()}%")
            if product:
                cpe_sub += " AND LOWER(product) LIKE ?"
                params.append(f"%{product.strip().lower()}%")
            where_clauses.append(f"v.cve_id IN ({cpe_sub})")
            
        where_stmt = " AND ".join(where_clauses)
        
        sort_map = {
            "published": "v.published",
            "cve_id": "v.cve_id",
            "cvss_v31_base_score": "v.cvss_v31_base_score",
            "epss": "e.epss",
            "publication_year": "v.publication_year"
        }
        order_col = sort_map.get(sort_by.lower(), "v.published")
        order_dir = "DESC" if sort_dir.lower() == "desc" else "ASC"
        
        count_sql = f"""
            SELECT COUNT(*) AS total
            FROM read_parquet('{self.vuln_parquet}') v
            LEFT JOIN read_parquet('{self.epss_parquet}') e ON v.cve_id = e.cve_id
            LEFT JOIN read_parquet('{self.kev_parquet}') k ON v.cve_id = k.cve_id
            WHERE {where_stmt}
        """
        total_rows = conn.execute(count_sql, params).fetchone()[0]
        
        offset = (page - 1) * page_size
        fetch_params = params + [page_size, offset]
        
        fetch_sql = f"""
            SELECT 
                v.cve_id,
                v.publication_year,
                v.published,
                v.description_en,
                v.cvss_v31_base_score,
                v.cvss_v31_severity AS cvss_v31_base_severity,
                e.epss AS epss_score,
                e.percentile AS epss_percentile,
                CASE WHEN k.cve_id IS NOT NULL THEN TRUE ELSE FALSE END AS is_kev
            FROM read_parquet('{self.vuln_parquet}') v
            LEFT JOIN read_parquet('{self.epss_parquet}') e ON v.cve_id = e.cve_id
            LEFT JOIN read_parquet('{self.kev_parquet}') k ON v.cve_id = k.cve_id
            WHERE {where_stmt}
            ORDER BY {order_col} {order_dir} NULLS LAST
            LIMIT ? OFFSET ?
        """
        df_res = conn.execute(fetch_sql, fetch_params).df()
        conn.close()
        
        records = df_res.to_dict(orient="records")
        for r in records:
            for k, val in r.items():
                if pd.isna(val):
                    r[k] = None
                    
        return records, total_rows

    def get_dataset_stats(self) -> Dict[str, Any]:
        conn = self.get_connection()
        total_vulns = conn.execute(f"SELECT COUNT(*) FROM read_parquet('{self.vuln_parquet}')").fetchone()[0]
        scored_cvss = conn.execute(f"SELECT COUNT(*) FROM read_parquet('{self.vuln_parquet}') WHERE cvss_v31_base_score IS NOT NULL").fetchone()[0]
        total_epss = conn.execute(f"SELECT COUNT(*) FROM read_parquet('{self.epss_parquet}')").fetchone()[0]
        total_kev = conn.execute(f"SELECT COUNT(*) FROM read_parquet('{self.kev_parquet}')").fetchone()[0]
        year_dist = conn.execute(f"SELECT publication_year, COUNT(*) AS count FROM read_parquet('{self.vuln_parquet}') GROUP BY publication_year ORDER BY publication_year").df().to_dict(orient="records")
        conn.close()
        
        return {
            "total_vulnerabilities": total_vulns,
            "cvss_v31_scored_vulnerabilities": scored_cvss,
            "epss_records": total_epss,
            "cisa_kev_records": total_kev,
            "publication_year_distribution": year_dist,
        }


db_engine = DatabaseEngine()
