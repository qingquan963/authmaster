"""
AuthMaster SDK - Test Suite

Run with:
    pytest tests/ -v
"""

import json
import time
import hashlib
import hmac
import uuid
from typing import Optional
from unittest.mock import patch, MagicMock
import pytest

import sys, os

# Ensure the package is importable from source tree.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from authmaster import AuthMasterClient
from authmaster.exceptions import (
    AuthMasterError,
    InvalidCredentialsError,
    MFARequiredError,
    NotFoundError,
    PermissionDeniedError,
    QuotaExceededError,
    RateLimitExceededError,
    TokenExpiredError,
    ValidationError,
    InternalServerError,
    ServerUnavailableError,
)
from authmaster.models import (
    LoginResult,
    UserProfile,
    RoleInfo,
    PaginatedResponse,
    QuotaInfo,
    SessionInfo,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def api_key() -> str:
    return "ak_test_xxxxxxxxxxxx"


@pytest.fixture
def api_secret() -> str:
    return "sk_test_xxxxxxxxxxxx"


@pytest.fixture
def base_url() -> str:
    return "https://test.authmaster.example.com/api/v1"


@pytest.fixture
def mock_response() -> MagicMock:
    """Factory for a mocked requests.Response object."""
    def _make(
        status_code: int = 200,
        json_data: Optional[dict] = None,
        headers: Optional[dict] = None,
    ) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status_code
        resp.content = b"" if json_data is None else json.dumps(json_data).encode()
        resp.json.return_value = json_data or {}
        resp.headers = headers or {"Content-Type": "application/json"}
        resp.url = "https://test.authmaster.example.com/api/v1/test"
        return resp
    return _make


@pytest.fixture
def client(api_key: str, api_secret: str, base_url: str) -> AuthMasterClient:
    """Client with a fake session (no real HTTP calls)."""
    sess = MagicMock()
    return AuthMasterClient(
        api_key=api_key,
        api_secret=api_secret,
        base_url=base_url,
        session=sess,
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def sign_request(
    client: AuthMasterClient,
    method: str,
    path: str,
    body: str = "",
) -> dict[str, str]:
    """Compute the HMAC-SHA256 signature headers for a request."""
    timestamp = int(time.time())
    msg = method.upper() + path + str(timestamp) + body
    sig = hmac.new(
        client.api_secret.encode(),
        msg.encode(),
        hashlib.sha256,
    ).hexdigest()
    return {
        "X-API-Key": client.api_key,
        "X-API-Signature": sig,
        "X-Timestamp": str(timestamp),
    }


def make_json_response(data: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = data
    resp.headers = {"Content-Type": "application/json"}
    resp.content = json.dumps(data).encode()
    return resp


# ---------------------------------------------------------------------------
# Signature tests
# ---------------------------------------------------------------------------

class TestSignature:
    def test_sign_produces_hex_digest(self, client: AuthMasterClient):
        sig = client._sign("POST", "/sdk/auth/login", 1234567890, '{"username":"a"}')
        assert len(sig) == 64  # SHA256 hex = 64 chars
        assert all(c in "0123456789abcdef" for c in sig)

    def test_sign_deterministic(self, client: AuthMasterClient):
        s1 = client._sign("POST", "/sdk/users", 1000000000, '{"x":1}')
        s2 = client._sign("POST", "/sdk/users", 1000000000, '{"x":1}')
        assert s1 == s2

    def test_sign_different_body_differs(self, client: AuthMasterClient):
        s1 = client._sign("POST", "/sdk/users", 1000000000, '{"x":1}')
        s2 = client._sign("POST", "/sdk/users", 1000000000, '{"x":2}')
        assert s1 != s2

    def test_sign_different_method_differs(self, client: AuthMasterClient):
        s1 = client._sign("POST", "/sdk/users", 1000000000, "")
        s2 = client._sign("GET", "/sdk/users", 1000000000, "")
        assert s1 != s2


# ---------------------------------------------------------------------------
# Client construction tests
# ---------------------------------------------------------------------------

class TestClientConstruction:
    def test_requires_api_key(self):
        with pytest.raises(ValueError, match="api_key"):
            AuthMasterClient(api_key="", api_secret="sk_xxx")

    def test_requires_api_secret(self):
        with pytest.raises(ValueError, match="api_secret"):
            AuthMasterClient(api_key="ak_xxx", api_secret="")

    def test_default_base_url(self):
        c = AuthMasterClient(api_key="ak_x", api_secret="sk_x")
        assert c.base_url == "https://auth.example.com/api/v1"

    def test_base_url_strips_trailing_slash(self):
        c = AuthMasterClient(api_key="ak_x", api_secret="sk_x", base_url="https://foo.com/api/v1/")
        assert c.base_url == "https://foo.com/api/v1"

    def test_version_attribute(self):
        from authmaster import __version__
        assert AuthMasterClient.VERSION == __version__

    def test_is_not_authenticated_initially(self, client: AuthMasterClient):
        assert not client.is_authenticated

    def test_is_authenticated_after_login(self, client: AuthMasterClient, mock_response):
        resp = mock_response(json_data={
            "data": {
                "access_token": "at_xxx",
                "refresh_token": "rt_xxx",
                "expires_in": 7200,
            }
        })
        resp.status_code = 200
        client._session.request.return_value = resp

        result = client.login("user@example.com", "password")
        assert client.is_authenticated
        assert result.access_token == "at_xxx"

    def test_repr_includes_masked_api_key(self, client: AuthMasterClient):
        r = repr(client)
        assert "ak_test_xxxx" in r or "****" in r
        assert "AuthMasterClient" in r


# ---------------------------------------------------------------------------
# Token management tests
# ---------------------------------------------------------------------------

class TestTokenManagement:
    def test_set_and_get_access_token(self, client: AuthMasterClient):
        client.set_token(access_token="tok_abc", expires_in=3600)
        assert client.access_token == "tok_abc"

    def test_set_and_get_refresh_token(self, client: AuthMasterClient):
        client.set_token(access_token="tok", refresh_token="ref", expires_in=7200)
        assert client.refresh_token == "ref"

    def test_clear_token(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        client.clear_token()
        assert client.access_token is None
        assert client.refresh_token is None

    def test_is_authenticated_with_valid_token(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=3600)
        assert client.is_authenticated is True

    def test_is_authenticated_false_after_clear(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=3600)
        client.clear_token()
        assert client.is_authenticated is False


# ---------------------------------------------------------------------------
# Login flow tests
# ---------------------------------------------------------------------------

class TestLogin:
    def test_login_success(self, client: AuthMasterClient):
        login_resp = {
            "data": {
                "access_token": "access_token_value",
                "refresh_token": "refresh_token_value",
                "expires_in": 7200,
                "token_type": "Bearer",
                "user_id": "user-uuid-123",
                "tenant_id": "tenant-uuid-456",
            }
        }
        client._session.request.return_value = make_json_response(login_resp)

        result = client.login("user@example.com", "password123")

        assert isinstance(result, LoginResult)
        assert result.access_token == "access_token_value"
        assert result.refresh_token == "refresh_token_value"
        assert result.user_id == "user-uuid-123"

        # Verify the token was stored in the client.
        assert client.access_token == "access_token_value"
        assert client.refresh_token == "refresh_token_value"

    def test_login_stores_token_for_subsequent_calls(self, client: AuthMasterClient):
        # Login
        client._session.request.return_value = make_json_response({
            "data": {"access_token": "tok1", "refresh_token": "ref1", "expires_in": 7200}
        })
        client.login("user@example.com", "password")

        # Second request should include Authorization header
        client._session.request.return_value = make_json_response({
            "data": {"items": [], "total": 0, "page": 1, "page_size": 20}
        })
        client.list_users()

        call_kwargs = client._session.request.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert "Authorization" in headers

    def test_login_invalid_credentials_raises(self, client: AuthMasterClient):
        client._session.request.return_value = make_json_response(
            {"error": {"code": "INVALID_CREDENTIALS", "message": "账号或密码错误"}},
            status=401,
        )

        with pytest.raises(InvalidCredentialsError) as exc_info:
            client.login("user@example.com", "wrong_password")

        assert exc_info.value.code == "INVALID_CREDENTIALS"

    def test_login_mfa_required_raises(self, client: AuthMasterClient):
        client._session.request.return_value = make_json_response(
            {
                "error": {
                    "code": "MFA_REQUIRED",
                    "message": "需要 MFA 验证",
                    "details": {"session_id": "sess_mfa_123"},
                }
            },
            status=403,
        )

        with pytest.raises(MFARequiredError) as exc_info:
            client.login("user@example.com", "password123")

        assert exc_info.value.code == "MFA_REQUIRED"
        assert exc_info.value.details.get("session_id") == "sess_mfa_123"

    def test_verify_mfa_success(self, client: AuthMasterClient):
        # Pre-set session so MFA step doesn't raise auth error
        client.set_token(access_token="tok_pre", expires_in=3600)

        client._session.request.return_value = make_json_response({
            "data": {
                "access_token": "tok_after_mfa",
                "refresh_token": "ref_after_mfa",
                "expires_in": 7200,
            }
        })

        result = client.verify_mfa(session_id="sess_123", mfa_code="123456")

        assert result.access_token == "tok_after_mfa"
        assert client.access_token == "tok_after_mfa"

    def test_logout_clears_token(self, client: AuthMasterClient):
        client.set_token(access_token="tok", refresh_token="ref", expires_in=7200)
        client._session.request.return_value = make_json_response({})

        client.logout()

        assert client.access_token is None
        assert not client.is_authenticated

    def test_refresh_token_success(self, client: AuthMasterClient):
        client.set_token(access_token="old_tok", refresh_token="old_ref", expires_in=7200)
        client._session.request.return_value = make_json_response({
            "data": {
                "access_token": "new_tok",
                "refresh_token": "new_ref",
                "expires_in": 7200,
            }
        })

        result = client.refresh_access_token()

        assert result.access_token == "new_tok"
        assert result.refresh_token == "new_ref"
        assert client.access_token == "new_tok"

    def test_refresh_token_requires_refresh_token(self, client: AuthMasterClient):
        client.clear_token()
        with pytest.raises(AuthMasterError, match="No refresh token"):
            client.refresh_access_token()


# ---------------------------------------------------------------------------
# User management tests
# ---------------------------------------------------------------------------

class TestUserManagement:
    def test_list_users_returns_paginated_response(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)

        client._session.request.return_value = make_json_response({
            "data": {
                "items": [
                    {
                        "user_id": "u1",
                        "email": "alice@example.com",
                        "username": "alice",
                        "status": "active",
                        "mfa_enabled": False,
                        "roles": ["user"],
                        "permissions": [],
                    },
                    {
                        "user_id": "u2",
                        "email": "bob@example.com",
                        "username": "bob",
                        "status": "active",
                        "mfa_enabled": True,
                        "roles": ["admin"],
                        "permissions": [],
                    },
                ],
                "total": 2,
                "page": 1,
                "page_size": 20,
            }
        })

        result = client.list_users(page=1, page_size=20)

        assert isinstance(result, PaginatedResponse)
        assert len(result.items) == 2
        assert result.total == 2
        assert result.page == 1
        assert isinstance(result.items[0], UserProfile)
        assert result.items[0].email == "alice@example.com"
        assert result.items[1].mfa_enabled is True

    def test_list_users_pagination_properties(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        client._session.request.return_value = make_json_response({
            "data": {"items": [], "total": 55, "page": 2, "page_size": 10}
        })

        result = client.list_users(page=2, page_size=10)

        assert result.total_pages == 6
        assert result.has_next is True

    def test_get_user_returns_user_profile(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        uid = "user-uuid-abc"
        client._session.request.return_value = make_json_response({
            "data": {
                "user_id": uid,
                "email": "alice@example.com",
                "username": "alice",
                "nickname": "Alice Chen",
                "status": "active",
                "mfa_enabled": False,
                "roles": ["user"],
                "permissions": ["user:read"],
            }
        })

        user = client.get_user(uid)

        assert isinstance(user, UserProfile)
        assert user.user_id == uid
        assert user.nickname == "Alice Chen"

    def test_get_user_not_found_raises(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        client._session.request.return_value = make_json_response(
            {"error": {"code": "NOT_FOUND", "message": "资源不存在"}},
            status=404,
        )

        with pytest.raises(NotFoundError) as exc:
            client.get_user("nonexistent-uuid")

        assert exc.value.code == "NOT_FOUND"

    def test_create_user_success(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        new_user_data = {
            "user_id": "new-uuid",
            "username": "newuser",
            "email": "newuser@example.com",
            "status": "active",
            "mfa_enabled": False,
            "roles": ["user"],
            "permissions": [],
        }
        client._session.request.return_value = make_json_response({"data": new_user_data})

        user = client.create_user(
            username="newuser",
            email="newuser@example.com",
            password="SecurePass123!",
            roles=["user"],
            idempotency_key="create_user:newuser@example.com",
        )

        assert isinstance(user, UserProfile)
        assert user.username == "newuser"
        assert user.email == "newuser@example.com"

        # Verify idempotency key was passed.
        call_kwargs = client._session.request.call_args
        headers = call_kwargs.kwargs.get("headers", {})
        assert headers.get("Idempotency-Key") == "create_user:newuser@example.com"

    def test_update_user_success(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        uid = "user-uuid-abc"
        client._session.request.return_value = make_json_response({
            "data": {
                "user_id": uid,
                "nickname": "Updated Name",
                "status": "active",
                "mfa_enabled": False,
                "roles": ["admin"],
                "permissions": [],
            }
        })

        user = client.update_user(uid, nickname="Updated Name", roles=["admin"])

        assert user.nickname == "Updated Name"

    def test_delete_user_success(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        client._session.request.return_value = make_json_response({"data": {}})

        result = client.delete_user("user-uuid-abc")
        assert isinstance(result, dict)

    def test_permission_denied_raises(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        client._session.request.return_value = make_json_response(
            {"error": {"code": "PERMISSION_DENIED", "message": "权限不足"}},
            status=403,
        )

        with pytest.raises(PermissionDeniedError) as exc:
            client.list_users()

        assert exc.value.code == "PERMISSION_DENIED"


# ---------------------------------------------------------------------------
# Role management tests
# ---------------------------------------------------------------------------

class TestRoleManagement:
    def test_list_roles(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        client._session.request.return_value = make_json_response({
            "data": {
                "items": [
                    {
                        "role_id": "r1",
                        "name": "管理员",
                        "code": "admin",
                        "description": "管理员角色",
                        "is_system": True,
                        "permissions": ["*"],
                    },
                    {
                        "role_id": "r2",
                        "name": "普通用户",
                        "code": "user",
                        "description": "",
                        "is_system": True,
                        "permissions": [],
                    },
                ],
                "total": 2,
                "page": 1,
                "page_size": 20,
            }
        })

        result = client.list_roles()

        assert len(result.items) == 2
        assert isinstance(result.items[0], RoleInfo)
        assert result.items[0].code == "admin"
        assert result.items[1].permissions == []

    def test_create_role(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        client._session.request.return_value = make_json_response({
            "data": {
                "role_id": "r_new",
                "name": "内容编辑",
                "code": "content_editor",
                "description": "负责内容发布和编辑",
                "is_system": False,
                "permissions": ["article:create", "article:update"],
            }
        })

        role = client.create_role(
            name="内容编辑",
            code="content_editor",
            description="负责内容发布和编辑",
            permissions=["article:create", "article:update"],
        )

        assert role.role_id == "r_new"
        assert "article:create" in role.permissions

    def test_assign_permission(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        client._session.request.return_value = make_json_response({"data": {"ok": True}})

        result = client.assign_permission("role-uuid", permission="user:delete")
        assert isinstance(result, dict)


# ---------------------------------------------------------------------------
# Quota tests
# ---------------------------------------------------------------------------

class TestQuota:
    def test_get_quota(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        client._session.request.return_value = make_json_response({
            "data": {
                "monthly_limit": 100000,
                "monthly_used": 4521,
                "daily_limit": 10000,
                "daily_used": 452,
                "rate_limit_rps": 100,
                "rate_limit_burst": 200,
                "reset_at": "2026-05-01T00:00:00Z",
                "remaining": 95479,
            }
        })

        quota = client.get_quota()

        assert isinstance(quota, QuotaInfo)
        assert quota.monthly_limit == 100000
        assert quota.monthly_used == 4521
        assert quota.remaining == 95479
        assert quota.rate_limit_rps == 100

    def test_get_quota_usage(self, client: AuthMasterClient):
        client.set_token(access_token="tok", expires_in=7200)
        client._session.request.return_value = make_json_response({
            "data": {"period": "monthly", "total_requests": 4521, "breakdown": []}
        })

        usage = client.get_quota_usage(period="monthly")
        assert isinstance(usage, dict)


# ---------------------------------------------------------------------------
# Error code hierarchy tests
# ---------------------------------------------------------------------------

class TestErrorCodeHierarchy:
    def test_invalid_credentials_subclass(self):
        exc = InvalidCredentialsError()
        assert isinstance(exc, AuthMasterError)
        assert exc.code == "INVALID_CREDENTIALS"
        assert exc.should_not_retry is True

    def test_mfa_required_subclass(self):
        exc = MFARequiredError()
        assert isinstance(exc, AuthMasterError)
        assert exc.code == "MFA_REQUIRED"
        assert exc.should_not_retry is True

    def test_rate_limit_exc_has_retry_details(self):
        exc = RateLimitExceededError(
            details={
                "limit": 100,
                "remaining": 0,
                "reset_at": "2026-04-03T08:00:00Z",
                "retry_after_seconds": 30,
            }
        )
        assert exc.retry_after_seconds == 30
        assert exc.limit == 100
        assert exc.should_retry is True

    def test_not_found_subclass(self):
        exc = NotFoundError()
        assert isinstance(exc, AuthMasterError)
        assert exc.should_not_retry is True

    def test_permission_denied_subclass(self):
        exc = PermissionDeniedError()
        assert exc.should_not_retry is True

    def test_validation_error_subclass(self):
        exc = ValidationError()
        assert exc.should_not_retry is True

    def test_quota_exceeded_subclass(self):
        exc = QuotaExceededError()
        assert exc.should_not_retry is True

    def test_token_expired_subclass(self):
        exc = TokenExpiredError()
        assert exc.should_retry is True

    def test_internal_server_error_retryable(self):
        exc = InternalServerError()
        assert exc.should_retry is True

    def test_server_unavailable_retryable(self):
        exc = ServerUnavailableError()
        assert exc.should_retry is True

    def test_from_response_creates_correct_subclass(self):
        payload = {
            "error": {
                "code": "RATE_LIMIT_EXCEEDED",
                "message": "rate limit",
                "details": {"retry_after_seconds": 15},
            }
        }
        exc = AuthMasterError.from_response(payload, http_status=429)
        assert isinstance(exc, RateLimitExceededError)
        assert exc.http_status == 429

    def test_from_response_unknown_code_returns_base(self):
        payload = {"error": {"code": "SOME_WEIRD_CODE", "message": "hmm"}}
        exc = AuthMasterError.from_response(payload, http_status=418)
        assert type(exc) == AuthMasterError
        assert exc.http_status == 418


# ---------------------------------------------------------------------------
# Context manager tests
# ---------------------------------------------------------------------------

class TestContextManager:
    def test_context_manager_closes_session(self, api_key, api_secret, base_url):
        sess = MagicMock()
        with AuthMasterClient(api_key=api_key, api_secret=api_secret, base_url=base_url, session=sess) as client:
            assert client is not None
        sess.close.assert_called_once()


# ---------------------------------------------------------------------------
# SDK-6.5: All error codes have corresponding subclasses
# ---------------------------------------------------------------------------

class TestErrorSubclassesExist:
    """Verify all documented error codes have a dedicated subclass (SDK-6.5)."""

    def test_all_documented_error_codes_have_subclass(self):
        expected_codes = {
            "INVALID_CREDENTIALS",
            "TOKEN_EXPIRED",
            "REFRESH_TOKEN_EXPIRED",
            "MFA_REQUIRED",
            "PERMISSION_DENIED",
            "NOT_FOUND",
            "RATE_LIMIT_EXCEEDED",
            "QUOTA_EXCEEDED",
            "VALIDATION_ERROR",
            "INTERNAL_ERROR",
            "SERVER_UNAVAILABLE",
        }
        registered = set(AuthMasterError._SUB_CLASSES.keys())
        assert expected_codes.issubset(registered), (
            f"Missing subclasses for: {expected_codes - registered}"
        )


# ---------------------------------------------------------------------------
# SDK-6.10: Version accessible
# ---------------------------------------------------------------------------

class TestVersionAccess:
    def test_version_accessible_from_module(self):
        from authmaster import __version__
        assert __version__

    def test_version_accessible_from_client_class(self):
        assert AuthMasterClient.VERSION
        assert "." in AuthMasterClient.VERSION


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
