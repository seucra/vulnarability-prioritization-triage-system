"""
Vulnerabilities Search, Retrieval & Detail API Endpoints
Repository: seucra/vulnarability-prioritization-triage-system
"""

from typing import Optional
from fastapi import APIRouter, Query, status
from backend.app.schemas.vulnerability import (
    VulnerabilityDetail,
    VulnerabilitySearchResponse,
)
from backend.app.services.vulnerability_service import vulnerability_service

router = APIRouter(prefix="/vulnerabilities", tags=["Vulnerabilities"])


@router.get(
    "",
    response_model=VulnerabilitySearchResponse,
    status_code=status.HTTP_200_OK,
    summary="Search & Filter Vulnerabilities",
    description="Query canonical NVD vulnerabilities dataset using text search, CVE ID, CWE, vendor/product, CVSS range, KEV status, EPSS score range, and publication year."
)
def search_vulnerabilities(
    q: Optional[str] = Query(None, description="Free text keyword search in vulnerability description"),
    cve_id: Optional[str] = Query(None, description="CVE ID pattern search (e.g. 'CVE-2023-')"),
    cwe_id: Optional[str] = Query(None, description="Exact CWE ID filter (e.g. 'CWE-79')"),
    vendor: Optional[str] = Query(None, description="CPE Vendor substring filter"),
    product: Optional[str] = Query(None, description="CPE Product substring filter"),
    min_cvss: Optional[float] = Query(None, ge=0.0, le=10.0, description="Minimum CVSS v3.1 score"),
    max_cvss: Optional[float] = Query(None, ge=0.0, le=10.0, description="Maximum CVSS v3.1 score"),
    is_kev: Optional[bool] = Query(None, description="Filter by CISA KEV catalog membership"),
    min_epss: Optional[float] = Query(None, ge=0.0, le=1.0, description="Minimum EPSS snapshot score"),
    publication_year: Optional[int] = Query(None, description="Publication year filter (2002-2026)"),
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(20, ge=1, le=100, description="Results per page (max 100)"),
    sort_by: str = Query("published", description="Sort field: 'published', 'cve_id', 'cvss_v31_base_score', 'epss'"),
    sort_dir: str = Query("desc", description="Sort direction: 'asc' or 'desc'")
):
    return vulnerability_service.search_vulnerabilities(
        q=q,
        cve_id=cve_id,
        cwe_id=cwe_id,
        vendor=vendor,
        product=product,
        min_cvss=min_cvss,
        max_cvss=max_cvss,
        is_kev=is_kev,
        min_epss=min_epss,
        publication_year=publication_year,
        page=page,
        page_size=page_size,
        sort_by=sort_by,
        sort_dir=sort_dir
    )


@router.get(
    "/{cve_id}",
    response_model=VulnerabilityDetail,
    status_code=status.HTTP_200_OK,
    summary="Get Vulnerability Detail",
    description="Retrieve complete vulnerability record, including authoritative CVSS scores, CWE taxonomy, CPE applicability, vendor statements, and separate current EPSS snapshot metadata."
)
def get_vulnerability_detail(cve_id: str):
    return vulnerability_service.get_vulnerability_detail(cve_id)
