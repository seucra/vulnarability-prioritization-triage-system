"""
Authentication & Role-Based Access Control (RBAC) Test Suite
Repository: seucra/vulnarability-prioritization-triage-system

Tests registration, authentication, token verification, role permissions (Analyst, Researcher, Admin),
privilege escalation prevention, account disabling, and route authorization.
"""

from fastapi.testclient import TestClient
import pytest
from backend.app.main import app
from backend.app.core.auth_db import auth_db

client = TestClient(app)


@pytest.fixture(autouse=True)
def cleanup_test_users():
    """Removes non-admin test users created during test runs."""
    yield
    with auth_db._get_connection() as conn:
        cursor = conn.cursor()
        cursor.execute("DELETE FROM users WHERE email LIKE '%@test.sec'")
        conn.commit()


def test_1_register_analyst():
    payload = {
        "email": "analyst1@test.sec",
        "password": "AnalystPassword123!",
        "name": "Test Security Analyst",
        "role": "analyst"
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "analyst1@test.sec"
    assert data["role"] == "analyst"
    assert "password" not in data
    assert "password_hash" not in data


def test_2_register_researcher():
    payload = {
        "email": "researcher1@test.sec",
        "password": "ResearcherPassword123!",
        "name": "Test Academic Researcher",
        "role": "researcher"
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 201
    data = response.json()
    assert data["email"] == "researcher1@test.sec"
    assert data["role"] == "researcher"


def test_3_duplicate_registration_rejected():
    payload = {
        "email": "analyst1@test.sec",
        "password": "AnalystPassword123!",
        "name": "Test Duplicate User",
        "role": "analyst"
    }
    client.post("/api/v1/auth/register", json=payload)
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code == 400
    assert "already registered" in response.json()["detail"]


def test_4_login_succeeds():
    payload_reg = {
        "email": "analyst2@test.sec",
        "password": "AnalystPassword123!",
        "name": "Test Analyst Two",
        "role": "analyst"
    }
    client.post("/api/v1/auth/register", json=payload_reg)

    payload_login = {
        "email": "analyst2@test.sec",
        "password": "AnalystPassword123!"
    }
    response = client.post("/api/v1/auth/login", json=payload_login)
    assert response.status_code == 200
    data = response.json()
    assert "access_token" in data
    assert data["user"]["email"] == "analyst2@test.sec"
    assert data["user"]["role"] == "analyst"


def test_5_invalid_credentials_rejected():
    payload_login = {
        "email": "nonexistent@test.sec",
        "password": "WrongPassword123!"
    }
    response = client.post("/api/v1/auth/login", json=payload_login)
    assert response.status_code == 401


def test_6_auth_me_returns_context():
    reg = client.post("/api/v1/auth/register", json={
        "email": "analyst3@test.sec",
        "password": "AnalystPassword123!",
        "name": "Analyst Three",
        "role": "analyst"
    })
    token = client.post("/api/v1/auth/login", json={
        "email": "analyst3@test.sec",
        "password": "AnalystPassword123!"
    }).json()["access_token"]

    response = client.get("/api/v1/auth/me", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert data["email"] == "analyst3@test.sec"
    assert data["role"] == "analyst"


def test_7_logout_works():
    token = client.post("/api/v1/auth/login", json={
        "email": "admin@vuln-triage.sec",
        "password": "AdminDemoPassword123!"
    }).json()["access_token"]

    response = client.post("/api/v1/auth/logout", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_8_protected_endpoint_rejects_unauthenticated():
    response = client.post("/api/v1/predict/cvss", json={
        "description_en": "Remote code execution in apache log4j2 vulnerability.",
        "cwe_ids": ["CWE-502"]
    })
    assert response.status_code == 401


def test_9_analyst_can_access_prioritization():
    client.post("/api/v1/auth/register", json={
        "email": "analyst4@test.sec",
        "password": "AnalystPassword123!",
        "name": "Analyst Four",
        "role": "analyst"
    })
    token = client.post("/api/v1/auth/login", json={
        "email": "analyst4@test.sec",
        "password": "AnalystPassword123!"
    }).json()["access_token"]

    payload = {
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "epss_score": 0.95,
        "is_kev": True,
        "asset_criticality": 0.75
    }
    response = client.post("/api/v1/prioritize", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_10_researcher_can_access_explanation():
    client.post("/api/v1/auth/register", json={
        "email": "researcher2@test.sec",
        "password": "ResearcherPassword123!",
        "name": "Researcher Two",
        "role": "researcher"
    })
    token = client.post("/api/v1/auth/login", json={
        "email": "researcher2@test.sec",
        "password": "ResearcherPassword123!"
    }).json()["access_token"]

    payload = {
        "description_en": "Memory corruption in openvpn buffer overflow.",
        "cwe_ids": ["CWE-120"]
    }
    response = client.post("/api/v1/explain/cvss", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200


def test_11_non_admin_cannot_access_admin_users_endpoint():
    client.post("/api/v1/auth/register", json={
        "email": "analyst5@test.sec",
        "password": "AnalystPassword123!",
        "name": "Analyst Five",
        "role": "analyst"
    })
    token = client.post("/api/v1/auth/login", json={
        "email": "analyst5@test.sec",
        "password": "AnalystPassword123!"
    }).json()["access_token"]

    response = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403


def test_12_admin_can_access_admin_users_endpoint():
    token = client.post("/api/v1/auth/login", json={
        "email": "admin@vuln-triage.sec",
        "password": "AdminDemoPassword123!"
    }).json()["access_token"]

    response = client.get("/api/v1/auth/users", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    data = response.json()
    assert len(data) >= 1
    assert any(u["email"] == "admin@vuln-triage.sec" for u in data)


def test_13_role_escalation_prevented():
    payload = {
        "email": "fakeadmin@test.sec",
        "password": "FakeAdminPassword123!",
        "name": "Fake Admin User",
        "role": "admin"  # Illegal role registration
    }
    response = client.post("/api/v1/auth/register", json=payload)
    assert response.status_code in [400, 422]


def test_14_disabled_user_cannot_authenticate():
    client.post("/api/v1/auth/register", json={
        "email": "disabled@test.sec",
        "password": "DisabledPassword123!",
        "name": "Disabled User",
        "role": "analyst"
    })
    user_id = auth_db.get_user_by_email("disabled@test.sec")["id"]
    auth_db.set_user_active_status(user_id, False)

    response = client.post("/api/v1/auth/login", json={
        "email": "disabled@test.sec",
        "password": "DisabledPassword123!"
    })
    assert response.status_code == 401


def test_15_researcher_forbidden_from_prioritization():
    client.post("/api/v1/auth/register", json={
        "email": "researcher3@test.sec",
        "password": "ResearcherPassword123!",
        "name": "Researcher Three",
        "role": "researcher"
    })
    token = client.post("/api/v1/auth/login", json={
        "email": "researcher3@test.sec",
        "password": "ResearcherPassword123!"
    }).json()["access_token"]

    payload = {
        "cve_id": "CVE-2021-44228",
        "cvss_score": 10.0,
        "epss_score": 0.95,
        "is_kev": True,
        "asset_criticality": 0.75
    }
    response = client.post("/api/v1/prioritize", json=payload, headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 403

