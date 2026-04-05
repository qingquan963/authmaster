"""
Tests for Phase 2-9 SSO Schemas
Tests:
  - [SSO-9-NOTE1] id_token_hint length validation
  - OIDCLogoutGet max_length enforcement
  - Schema serialization / deserialization
"""
import uuid

import pytest
from pydantic import ValidationError

from app.sso.schemas import (
    Protocol,
    LogoutStatus,
    OIDCLogoutGet,
    OIDCLogoutPost,
    OIDCLogoutResponse,
    IdPInitiatedLogoutResponse,
    ForceLogoutResponse,
    SPSessionItem,
    SessionListResponse,
    SAMLSLOResponse,
    SAMLSLORequest,
    DeadLetterItem,
)


# ---------------------------------------------------------------------------
# [SSO-9-NOTE1] id_token_hint length validation
# ---------------------------------------------------------------------------
def test_oidc_logout_get_rejects_oversized_id_token_hint():
    """
    [SSO-9-NOTE1] id_token_hint > 4096 bytes must be rejected.
    """
    long_token = "x" * 5000  # 5000 bytes > 4096 limit

    with pytest.raises(ValidationError) as exc_info:
        OIDCLogoutGet(id_token_hint=long_token)

    assert "id_token_hint" in str(exc_info.value)


def test_oidc_logout_get_accepts_valid_id_token_hint():
    """
    id_token_hint ≤ 4096 bytes should be accepted.
    """
    token = "eyJhbGciOiJSUzI1NiJ9." + "a" * 100  # short JWT
    obj = OIDCLogoutGet(id_token_hint=token)
    assert obj.id_token_hint == token


def test_oidc_logout_get_optional_id_token_hint():
    """
    id_token_hint is optional.
    """
    obj = OIDCLogoutGet()
    assert obj.id_token_hint is None


# ---------------------------------------------------------------------------
# Schema serialization
# ---------------------------------------------------------------------------
def test_oidc_logout_response_serialization():
    resp = OIDCLogoutResponse(
        status="completed",
        logout_id="123e4567-e89b-12d3-a456-426614174000",
        sp_notified=5,
        message="All SPs notified",
    )
    data = resp.model_dump()
    assert data["status"] == "completed"
    assert data["sp_notified"] == 5


def test_idp_initiated_logout_response():
    resp = IdPInitiatedLogoutResponse(
        status="already_completed",
        logout_id="123e4567-e89b-12d3-a456-426614174000",
        sp_notified=3,
        sp_failed=0,
    )
    assert resp.status == "already_completed"
    assert resp.sp_notified == 3


def test_force_logout_response():
    resp = ForceLogoutResponse(
        status="ok",
        sessions_revoked=2,
        sp_notified=10,
    )
    data = resp.model_dump()
    assert data["sessions_revoked"] == 2
    assert data["sp_notified"] == 10


def test_session_list_response():
    items = [
        SPSessionItem(
            session_id=uuid.uuid4(),
            user_id=uuid.uuid4(),
            user_email="admin@example.com",
            login_method="oidc_google",
            created_at="2026-04-03T08:00:00Z",
            sp_count=3,
        ),
    ]
    resp = SessionListResponse(items=items, total=1, page=1, page_size=50)
    assert len(resp.items) == 1
    assert resp.total == 1


def test_dead_letter_item():
    item = DeadLetterItem(
        id=uuid.uuid4(),
        logout_id=uuid.uuid4(),
        sp_session_id=uuid.uuid4(),
        client_id="client-a",
        protocol="oidc",
        error_message="Connection timeout",
        attempt_count=5,
        created_at="2026-04-03T08:00:00Z",
    )
    assert item.attempt_count == 5
    assert item.protocol == "oidc"


def test_saml_slo_request_minimal():
    req = SAMLSLORequest()
    assert req.SAMLRequest is None
    assert req.client_id is None


def test_saml_slo_request_with_client_id():
    req = SAMLSLORequest(
        client_id="my-saml-sp",
        sp_session_id="sp-session-abc",
        RelayState="return-to-app",
    )
    assert req.client_id == "my-saml-sp"
    assert req.RelayState == "return-to-app"


def test_protocol_enum():
    assert Protocol.OIDC == "oidc"
    assert Protocol.SAML == "saml"


def test_logout_status_enum():
    assert LogoutStatus.PENDING == "pending"
    assert LogoutStatus.COMPLETED == "completed"
    assert LogoutStatus.FAILED == "failed"
