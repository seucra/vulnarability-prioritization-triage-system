"""
Batch Vulnerability Triage Queue API Test Suite
Repository: seucra/vulnarability-prioritization-triage-system

Tests POST /api/v1/prioritize/batch for batch CVE triage processing, metadata auto-population,
analyst score overrides, item error handling, 100-item batch limits, deterministic tie-breaking,
and RBAC enforcement across Security Analyst, Administrator, Academic Researcher, and Guest roles.
"""

from fastapi.testclient import TestClient
import pytest
from backend.app.main import app

client = TestClient(app)


@pytest.fixture(scope="module")
def admin_token():
    resp = client.post("/api/v1/auth/login", json={
        "email": "admin@vuln-triage.sec",
        "password": "AdminDemoPassword123!"
    })
    return resp.json()["access_token"]


@pytest.fixture(scope="module")
def analyst_token():
    # Register analyst if needed
    reg_payload = {
        "email": "batch_analyst@test.sec",
        "password": "AnalystPassword123!",
        "name": "Batch Test Analyst",
        "role": "analyst"
    }
    client.post("/api/v1/auth/register", json=reg_payload)
    resp = client.post("/api/v1/auth/login", json={
        "email": "batch_analyst@test.sec",
        "password": "AnalystPassword123!"
    })
    return resp.json()["access_token"]


@pytest.fixture(scope="module")
def researcher_token():
    reg_payload = {
        "email": "batch_researcher@test.sec",
        "password": "ResearcherPassword123!",
        "name": "Batch Test Researcher",
        "role": "researcher"
    }
    client.post("/api/v1/auth/register", json=reg_payload)
    resp = client.post("/api/v1/auth/login", json={
        "email": "batch_researcher@test.sec",
        "password": "ResearcherPassword123!"
    })
    return resp.json()["access_token"]


def test_batch_prioritize_valid_cves(analyst_token):
    payload = {
        "items": [
            {"cve_id": "CVE-2021-44228"},
            {"cve_id": "CVE-2023-23397"}
        ],
        "default_asset_criticality": 1.0,
        "primary_sort": "mode_2",
        "sort_dir": "desc"
    }
    resp = client.post("/api/v1/prioritize/batch", json=payload, headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp.status_code == 200


    data = resp.json()
    
    assert data["total_requested"] == 2
    assert data["total_processed"] == 2
    assert data["total_errors"] == 0
    assert len(data["items"]) == 2
    
    # Check ranking and metadata population
    item1 = data["items"][0]
    assert item1["rank"] == 1
    assert item1["cve_id"] == "CVE-2021-44228"
    assert item1["cvss_score"] == 10.0
    assert item1["is_kev"] is True
    assert item1["status"] == "success"
    assert item1["linear_score"] > 0.0
    assert item1["nonlinear_score"] > 0.0
    assert item1["is_analyst_override"] is False


def test_batch_prioritize_analyst_overrides(analyst_token):
    payload = {
        "items": [
            {
                "cve_id": "CVE-2021-44228",
                "asset_criticality": 0.50,
                "custom_label": "Analyst Override Test"
            },
            {
                "custom_label": "Zero-Day Custom Vulnerability",
                "cvss_score": 9.5,
                "epss_score": 0.80,
                "is_kev": True,
                "asset_criticality": 1.0
            }
        ],
        "default_asset_criticality": 0.75
    }
    resp = client.post("/api/v1/prioritize/batch", json=payload, headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert data["total_processed"] == 2
    
    # Custom item check
    override_item = next(it for it in data["items"] if it["custom_label"] == "Zero-Day Custom Vulnerability")
    assert override_item["status"] == "success"
    assert override_item["is_analyst_override"] is True
    assert override_item["cvss_score"] == 9.5
    assert override_item["epss_score"] == 0.80


def test_batch_max_limit_exceeded(analyst_token):
    # 101 items
    items = [{"cve_id": f"CVE-2021-{1000 + i}"} for i in range(101)]
    payload = {"items": items}
    resp = client.post("/api/v1/prioritize/batch", json=payload, headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp.status_code == 422
    detail_str = str(resp.json()["detail"])
    assert "100 items" in detail_str


def test_batch_empty_request_rejected(analyst_token):
    payload = {"items": []}
    resp = client.post("/api/v1/prioritize/batch", json=payload, headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp.status_code == 422


def test_batch_invalid_and_unknown_cve_handling(analyst_token):
    payload = {
        "items": [
            {"cve_id": "CVE-2021-44228"},
            {"cve_id": "CVE-NONEXISTENT-9999"},
            {"custom_label": "Incomplete Custom Item"} # Missing scores & CVE ID
        ]
    }
    resp = client.post("/api/v1/prioritize/batch", json=payload, headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp.status_code == 200
    data = resp.json()
    
    assert data["total_requested"] == 3
    assert data["total_processed"] == 1
    assert data["total_errors"] == 2
    
    # Check unknown CVE
    unknown_item = next(it for it in data["items"] if it["cve_id"] == "CVE-NONEXISTENT-9999")
    assert unknown_item["status"] == "not_found"
    assert "not found" in unknown_item["error_message"]
    
    # Check invalid item
    invalid_item = next(it for it in data["items"] if it["custom_label"] == "Incomplete Custom Item")
    assert invalid_item["status"] == "validation_error"


def test_batch_deterministic_tie_breaking(analyst_token):
    payload = {
        "items": [
            {"cve_id": "CVE-2021-44228"},
            {"cve_id": "CVE-2021-44228"} # Duplicate with identical scores
        ]
    }
    resp = client.post("/api/v1/prioritize/batch", json=payload, headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp.status_code == 200
    data = resp.json()
    assert len(data["items"]) == 2
    assert data["items"][0]["rank"] == 1
    assert data["items"][1]["rank"] == 2


def test_batch_rbac_permissions(admin_token, analyst_token, researcher_token):
    payload = {"items": [{"cve_id": "CVE-2021-44228"}]}
    
    # Admin -> 200 OK
    resp_admin = client.post("/api/v1/prioritize/batch", json=payload, headers={"Authorization": f"Bearer {admin_token}"})
    assert resp_admin.status_code == 200
    
    # Analyst -> 200 OK
    resp_analyst = client.post("/api/v1/prioritize/batch", json=payload, headers={"Authorization": f"Bearer {analyst_token}"})
    assert resp_analyst.status_code == 200
    
    # Researcher -> 403 Forbidden
    resp_researcher = client.post("/api/v1/prioritize/batch", json=payload, headers={"Authorization": f"Bearer {researcher_token}"})
    assert resp_researcher.status_code == 403
    
    # Unauthenticated -> 401 Unauthorized
    resp_guest = client.post("/api/v1/prioritize/batch", json=payload)
    assert resp_guest.status_code == 401
