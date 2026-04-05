"""
Tests for Phase 2-9 SSO Router
Tests cover:
  - GET /oidc/logout: id_token_hint length validation (SSO-9-NOTE1)
  - POST /oidc/logout: action=logout_confirmed
  - POST /saml/slo: IdP-initiated SLO with client_id + sp_session_id
  - Admin endpoints: force_logout_session, force_logout_user
  - Dead letter listing
"""
import uuid
from unittest.mock import AsyncMock, MagicMock, patch
from datetime import datetime, timezone

import pytest

import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from fastapi.testclient import TestClient
from fastapi import FastAPI

from app.sso import router as sso_router
from app.sso import service as sso_service


# ---------------------------------------------------------------------------
# Minimal test app setup
# ---------------------------------------------------------------------------

class FakeDB:
    """Minimal fake async DB session."""
    def __init__(self):
        self.commits = 0

    async def execute(self, *args, **kwargs):
        return FakeResult()

    async def commit(self):
        self.commits += 1


class FakeResult:
    async def fetchone(self):
        return None

    async def fetchall(self):
        return []

    @property
    def rowcount(self):
        return 1


# ---------------------------------------------------------------------------
# Test: GET /oidc/logout rejects oversized id_token_hint
# ---------------------------------------------------------------------------
def test_oidc_logout_get_rejects_oversized_token():
    """
    [SSO-9-NOTE1] id_token_hint > 4096 bytes should return 400.
    """
    app = FastAPI()
    app.include_router(sso_router.router)

    # Override get_db
    async def _get_db():
        yield FakeDB()

    app.dependency_overrides[sso_router.get_db] = _get_db

    client = TestClient(app, raise_server_exceptions=False)

    long_token = "x" * 5000
    response = client.get(f"/oidc/logout?id_token_hint={long_token}")

    # Should either reject at FastAPI layer (query param max_length)
    # or at the route handler
    assert response.status_code in (400, 422)


# ---------------------------------------------------------------------------
# Test: GET /oidc/logout accepts valid token
# ---------------------------------------------------------------------------
def test_oidc_logout_get_accepts_valid_token():
    """
    id_token_hint ≤ 4096 bytes should be accepted.
    """
    app = FastAPI()
    app.include_router(sso_router.router)

    async def _get_db():
        yield FakeDB()

    app.dependency_overrides[sso_router.get_db] = _get_db

    client = TestClient(app, raise_server_exceptions=False)

    valid_token = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.test"
    response = client.get(f"/oidc/logout?id_token_hint={valid_token}")

    # Will redirect since no user found, but should not 400
    assert response.status_code == 302


# ---------------------------------------------------------------------------
# Test: POST /oidc/logout with logout_confirmed
# ---------------------------------------------------------------------------
def test_oidc_logout_post_confirmed():
    """
    POST /oidc/logout with action=logout_confirmed should return OK.
    """
    app = FastAPI()
    app.include_router(sso_router.router)

    async def _get_db():
        yield FakeDB()

    app.dependency_overrides[sso_router.get_db] = _get_db

    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        "/oidc/logout",
        json={
            "action": "logout_confirmed",
            "logout_id": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 200
    data = response.json()
    assert data["status"] == "ok"


# ---------------------------------------------------------------------------
# Test: POST /oidc/logout rejects unknown action
# ---------------------------------------------------------------------------
def test_oidc_logout_post_rejects_unknown_action():
    """
    Unknown action should return 400.
    """
    app = FastAPI()
    app.include_router(sso_router.router)

    async def _get_db():
        yield FakeDB()

    app.dependency_overrides[sso_router.get_db] = _get_db

    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        "/oidc/logout",
        json={
            "action": "unknown_action",
            "logout_id": str(uuid.uuid4()),
        },
    )

    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Test: POST /saml/slo with IdP-initiated params
# ---------------------------------------------------------------------------
def test_saml_slo_idp_initiated():
    """
    POST /saml/slo with client_id + sp_session_id (IdP-initiated SLO)
    should trigger idp_initiated_logout and return 200.
    """
    app = FastAPI()
    app.include_router(sso_router.router)

    async def _get_db():
        yield FakeDB()

    app.dependency_overrides[sso_router.get_db] = _get_db

    client = TestClient(app, raise_server_exceptions=False)

    response = client.post(
        "/saml/slo",
        json={
            "client_id": "my-saml-client",
            "sp_session_id": "sp-session-abc",
        },
    )

    # Will return 404 if session not found (expected in mock DB),
    # but should not 400 (request is valid)
    assert response.status_code in (200, 404)


# ---------------------------------------------------------------------------
# Test: POST /saml/slo rejects when no params provided
# ---------------------------------------------------------------------------
def test_saml_slo_rejects_missing_params():
    """
    POST /saml/slo without SAMLRequest or client_id/sp_session_id
    should return 400.
    """
    app = FastAPI()
    app.include_router(sso_router.router)

    async def _get_db():
        yield FakeDB()

    app.dependency_overrides[sso_router.get_db] = _get_db

    client = TestClient(app, raise_server_exceptions=False)

    response = client.post("/saml/slo", json={})

    assert response.status_code == 400


# ---------------------------------------------------------------------------
# Test: DELETE /api/v1/admin/v1/sessions/{session_id} — session not found
# ---------------------------------------------------------------------------
def test_force_logout_session_not_found():
    """
    Force logout a non-existent session should return 404.
    """
    app = FastAPI()
    app.include_router(sso_router.router)

    async def _get_db():
        yield FakeDB()

    app.dependency_overrides[sso_router.get_db] = _get_db

    client = TestClient(app, raise_server_exceptions=False)

    fake_session_id = uuid.uuid4()
    response = client.delete(f"/api/v1/admin/v1/sessions/{fake_session_id}")

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Test: DELETE /api/v1/admin/v1/sessions/user/{user_id} — no sessions found
# ---------------------------------------------------------------------------
def test_force_logout_user_not_found():
    """
    Force logout a user with no active sessions should return 404.
    """
    app = FastAPI()
    app.include_router(sso_router.router)

    async def _get_db():
        yield FakeDB()

    app.dependency_overrides[sso_router.get_db] = _get_db

    client = TestClient(app, raise_server_exceptions=False)

    fake_user_id = uuid.uuid4()
    response = client.delete(f"/api/v1/admin/v1/sessions/user/{fake_user_id}")

    assert response.status_code == 404


# ---------------------------------------------------------------------------
# Test: GET /api/v1/admin/v1/dead-letters returns paginated list
# ---------------------------------------------------------------------------
def test_list_dead_letters_returns_paginated():
    """
    GET /api/v1/admin/v1/dead-letters should return a paginated list.
    """
    app = FastAPI()
    app.include_router(sso_router.router)

    async def _get_db():
        yield FakeDB()

    app.dependency_overrides[sso_router.get_db] = _get_db

    client = TestClient(app, raise_server_exceptions=False)

    response = client.get("/api/v1/admin/v1/dead-letters")

    assert response.status_code == 200
    data = response.json()
    assert "items" in data
    assert "total" in data
    assert "page" in data
    assert "page_size" in data
