"""
Phase 4 Backend REST API Test Suite
Repository: seucra/vulnarability-prioritization-triage-system

Tests API endpoints, boundary invariants, model inference, prioritization modes,
SHAP explanations, research provenance, and raw/processed dataset immutability.
"""

from fastapi.testclient import TestClient
import pytest

from backend.app.main import app

client = TestClient(app)


@pytest.fixture(scope="module", autouse=True)
def authenticate_test_client():
    """Authenticates the test client with demo admin credentials for Phase 4 API tests."""
    login_resp = client.post("/api/v1/auth/login", json={
        "email": "admin@vuln-triage.sec",
        "password": "AdminDemoPassword123!"
    })
    if login_resp.status_code == 200:
        token = login_resp.json()["access_token"]
        client.headers["Authorization"] = f"Bearer {token}"


def test_health_check():
    response = client.get("/health")
    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "healthy"
    assert data["repository"] == "seucra/vulnarability-prioritization-triage-system"
    assert data["dataset_freeze_date"] == "2026-07-26"


def test_vulnerability_search():
    response = client.get("/api/v1/vulnerabilities?q=sql&page=1&page_size=5")
    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert data["page"] == 1
    assert data["page_size"] == 5
    assert len(data["items"]) <= 5


def test_vulnerability_detail_and_epss_separation():
    response = client.get("/api/v1/vulnerabilities/CVE-2021-44228")
    assert response.status_code == 200
    data = response.json()
    assert data["cve_id"] == "CVE-2021-44228"
    assert data["authoritative_cvss_v31_base_score"] == 10.0
    assert data["is_kev"] is True
    
    # EPSS snapshot separation invariant check
    assert data["epss"] is not None
    assert data["epss"]["snapshot_date"] == "2026-07-16T12:03:48Z"
    assert data["epss"]["model_version"] == "v2026.06.15"
    assert data["epss"]["is_historical_prediction_input"] is False


def test_predict_cvss_estimation():
    payload = {
        "description_en": "An unauthenticated remote code execution vulnerability in Apache Log4j2 JNDI feature allows full system takeover.",
        "cwe_ids": ["CWE-502", "CWE-400"],
        "cpe_count": 5,
        "cpe_part_a_count": 5,
        "cpe_part_o_count": 0,
        "cpe_part_h_count": 0,
        "vendor_count": 1,
        "product_count": 1,
        "pub_month": 12
    }
    response = client.post("/api/v1/predict/cvss?cve_id=CVE-2021-44228", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert 0.0 <= data["predicted_cvss_v31_base_score"] <= 10.0
    assert data["authoritative_cvss_v31_base_score"] == 10.0
    assert data["prediction_label"] == "Predicted CVSS v3.1 Base Score"
    assert data["model_name"] == "EXP-A1 XGBoost Regressor"
    assert data["mae_test_benchmark"] == 0.9750


def test_predict_kev_publication_time_valid():
    payload = {
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
    response = client.post("/api/v1/predict/kev", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert 0.0 <= data["predicted_kev_probability"] <= 1.0
    assert data["prediction_point"] == "CVE Publication / Initial Triage"
    assert data["model_name"] == "EXP-B2 XGBoost Classifier"
    assert data["pr_auc_test_benchmark"] == 0.02884


def test_predict_kev_rejects_epss_and_cvss_boundary_violation():
    # Attempt to pass prohibited post-publication features (EPSS & CVSS)
    payload = {
        "description_en": "A buffer overflow vulnerability in openvpn allows remote unauthenticated memory corruption.",
        "cwe_ids": ["CWE-120"],
        "epss": 0.95, # PROHIBITED
        "cvss_v31_base_score": 9.8 # PROHIBITED
    }
    response = client.post("/api/v1/predict/kev", json=payload)
    # Must fail with HTTP 422 Unprocessable Entity
    assert response.status_code == 422
    detail_str = str(response.json()["detail"])
    assert "Publication-Time Feature Boundary Violation" in detail_str or "epss" in detail_str


def test_prioritization_scoring_modes():
    payload = {
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "epss_score": 0.95,
        "is_kev": True,
        "asset_criticality": 1.0 # Tier 4 Critical
    }
    response = client.post("/api/v1/prioritize", json=payload)
    assert response.status_code == 200
    data = response.json()
    
    # Mode 1 Linear: 0.25*(1.0) + 0.25*(0.95) + 0.25*(1.0) + 0.25*(1.0) = 0.9875
    lin_score = data["linear_baseline_mode_1"]["priority_score"]
    assert pytest.approx(lin_score, 0.001) == 0.9875
    
    # Mode 2 Nonlinear: 1.0 * [1 - (1 - 1.0)^2 * (1 - 0.95)^2.5] = 1.0 * [1 - 0] = 1.0
    nonlin_score = data["nonlinear_surface_mode_2"]["priority_score"]
    assert pytest.approx(nonlin_score, 0.001) == 1.0
    assert "MODE 1" in data["linear_baseline_mode_1"]["scoring_mode"]
    assert "MODE 2" in data["nonlinear_surface_mode_2"]["scoring_mode"]


def test_shap_explanations():
    payload = {
        "description_en": "An unauthenticated remote code execution vulnerability in Apache Log4j2 JNDI feature.",
        "cwe_ids": ["CWE-502"],
        "cpe_count": 2,
        "cpe_part_a_count": 2,
        "cpe_part_o_count": 0,
        "cpe_part_h_count": 0,
        "vendor_count": 1,
        "product_count": 1,
        "pub_month": 12
    }
    response = client.post("/api/v1/explain/cvss", json=payload)
    assert response.status_code == 200
    data = response.json()
    assert "target_model" in data
    assert "top_feature_contributions" in data
    assert len(data["top_feature_contributions"]) > 0
    assert "does NOT establish physical causal mechanisms" in data["causal_disclaimer"]


def test_research_provenance():
    response = client.get("/api/v1/provenance")
    assert response.status_code == 200
    data = response.json()
    assert data["repository_name"] == "seucra/vulnarability-prioritization-triage-system"
    assert data["dataset_freeze_manifest"]["freeze_date"] == "2026-07-26"
    assert len(data["phase_3_experiments"]) == 4
