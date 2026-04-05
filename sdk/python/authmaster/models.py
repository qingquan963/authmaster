"""
AuthMaster SDK - Data Models

Typed dataclasses / TypedDicts for all API request and response objects.
These models represent the wire format documented in the API specification
and do not carry behaviour.
"""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from datetime import datetime
from typing import (
    Any,
    Callable,
    Generic,
    Literal,
    Optional,
    TypeVar,
    Union,
    TYPE_CHECKING,
)

if sys.version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


# ---------------------------------------------------------------------------
# Utility types
# ---------------------------------------------------------------------------

T = TypeVar("T")


@dataclass(frozen=True)
class PaginatedResponse(Generic[T]):
    """
    Generic paginated list wrapper.

    Attributes
    ----------
    items : list[T]
        Current page of items.
    total : int
        Total number of items across all pages.
    page : int
        Current page number (1-indexed).
    page_size : int
        Number of items per page.
    """
    items: list[T]
    total: int
    page: int
    page_size: int

    @property
    def total_pages(self) -> int:
        """Calculate the total number of pages."""
        if self.page_size <= 0:
            return 0
        return (self.total + self.page_size - 1) // self.page_size

    @property
    def has_next(self) -> bool:
        """Return True when there are more pages after the current one."""
        return self.page < self.total_pages


@dataclass
class QuotaInfo:
    """API quota usage summary."""

    monthly_limit: Optional[int] = None
    monthly_used: int = 0
    daily_limit: Optional[int] = None
    daily_used: int = 0
    rate_limit_rps: int = 0
    rate_limit_burst: int = 0
    reset_at: Optional[str] = None
    remaining: Optional[int] = None


@dataclass
class LoginResult:
    """Result of a successful login or token-refresh operation."""

    access_token: str
    refresh_token: str
    token_type: str = "Bearer"
    expires_in: int = 7200
    scope: Optional[str] = None
    user_id: Optional[str] = None
    tenant_id: Optional[str] = None
    session_id: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "LoginResult":
        data = data.get("data", data)
        return cls(
            access_token=data.get("access_token", ""),
            refresh_token=data.get("refresh_token", ""),
            token_type=data.get("token_type", "Bearer"),
            expires_in=data.get("expires_in", 7200),
            scope=data.get("scope"),
            user_id=data.get("user_id"),
            tenant_id=data.get("tenant_id"),
            session_id=data.get("session_id"),
        )


@dataclass
class SessionInfo:
    """Current session information."""

    session_id: str
    user_id: str
    tenant_id: Optional[str] = None
    login_method: Optional[str] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None
    created_at: Optional[str] = None
    last_active_at: Optional[str] = None
    scopes: list[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "SessionInfo":
        data = data.get("data", data)
        return cls(
            session_id=data.get("session_id", ""),
            user_id=data.get("user_id", ""),
            tenant_id=data.get("tenant_id"),
            login_method=data.get("login_method"),
            ip_address=data.get("ip_address"),
            user_agent=data.get("user_agent"),
            created_at=data.get("created_at"),
            last_active_at=data.get("last_active_at"),
            scopes=data.get("scopes", []),
        )


@dataclass
class UserProfile:
    """User profile / account information."""

    user_id: str
    username: Optional[str] = None
    email: Optional[str] = None
    phone: Optional[str] = None
    nickname: Optional[str] = None
    avatar_url: Optional[str] = None
    status: str = "active"
    mfa_enabled: bool = False
    roles: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    last_login_at: Optional[str] = None
    created_at: Optional[str] = None
    updated_at: Optional[str] = None
    tenant_id: Optional[str] = None
    extra: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "UserProfile":
        data = data.get("data", data)
        return cls(
            user_id=data.get("user_id") or data.get("id", ""),
            username=data.get("username"),
            email=data.get("email"),
            phone=data.get("phone"),
            nickname=data.get("nickname"),
            avatar_url=data.get("avatar_url"),
            status=data.get("status", "active"),
            mfa_enabled=data.get("mfa_enabled", False),
            roles=data.get("roles", []),
            permissions=data.get("permissions", []),
            last_login_at=data.get("last_login_at"),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
            tenant_id=data.get("tenant_id"),
            extra={
                k: v
                for k, v in data.items()
                if k
                not in {
                    "user_id",
                    "id",
                    "username",
                    "email",
                    "phone",
                    "nickname",
                    "avatar_url",
                    "status",
                    "mfa_enabled",
                    "roles",
                    "permissions",
                    "last_login_at",
                    "created_at",
                    "updated_at",
                    "tenant_id",
                }
            },
        )

    def to_dict(self) -> dict[str, Any]:
        """Serialize back to a plain dict suitable for API calls."""
        return {
            "user_id": self.user_id,
            "username": self.username,
            "email": self.email,
            "phone": self.phone,
            "nickname": self.nickname,
            "avatar_url": self.avatar_url,
            "status": self.status,
            "mfa_enabled": self.mfa_enabled,
            "roles": self.roles,
            "permissions": self.permissions,
            "last_login_at": self.last_login_at,
            "created_at": self.created_at,
            "updated_at": self.updated_at,
            "tenant_id": self.tenant_id,
            **self.extra,
        }


@dataclass
class RoleInfo:
    """Role summary."""

    role_id: str
    name: str
    code: str
    description: Optional[str] = None
    is_system: bool = False
    permissions: list[str] = field(default_factory=list)
    created_at: Optional[str] = None
    updated_at: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "RoleInfo":
        data = data.get("data", data)
        return cls(
            role_id=data.get("role_id") or data.get("id", ""),
            name=data.get("name", ""),
            code=data.get("code", ""),
            description=data.get("description"),
            is_system=data.get("is_system", False),
            permissions=data.get("permissions", []),
            created_at=data.get("created_at"),
            updated_at=data.get("updated_at"),
        )


@dataclass
class PermissionInfo:
    """Permission definition."""

    permission_id: str
    code: str
    name: str
    resource: str
    action: str
    description: Optional[str] = None

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "PermissionInfo":
        data = data.get("data", data)
        return cls(
            permission_id=data.get("permission_id") or data.get("id", ""),
            code=data.get("code", ""),
            name=data.get("name", ""),
            resource=data.get("resource", ""),
            action=data.get("action", ""),
            description=data.get("description"),
        )


# ---------------------------------------------------------------------------
# Request builders (pure data, no validation here – done by pydantic in app)
# ---------------------------------------------------------------------------

class LoginRequest(dict):
    """
    Payload for :meth:`AuthMasterClient.login`.

    Parameters
    ----------
    username : str
        User's email or phone number (depending on auth_type).
    password : str
        Plain-text password.
    auth_type : {"email", "phone"}, default "email"
    extra : dict, optional
        Additional fields forwarded to the login endpoint (e.g. ``captcha_token``).
    """

    def __init__(
        self,
        username: str,
        password: str,
        auth_type: Literal["email", "phone"] = "email",
        **extra: Any,
    ):
        super().__init__(
            username=username,
            password=password,
            auth_type=auth_type,
            **extra,
        )


class MFAVerifyRequest(dict):
    """
    Payload for :meth:`AuthMasterClient.verify_mfa`.

    Parameters
    ----------
    session_id : str
        Session ID returned by the login response when MFA is required.
    mfa_code : str
        One-time TOTP / SMS code.
    mfa_type : {"totp", "sms", "email"}, default "totp"
    """

    def __init__(
        self,
        session_id: str,
        mfa_code: str,
        mfa_type: Literal["totp", "sms", "email"] = "totp",
    ):
        super().__init__(
            session_id=session_id,
            mfa_code=mfa_code,
            mfa_type=mfa_type,
        )


class RefreshTokenRequest(dict):
    """Payload for :meth:`AuthMasterClient.refresh_token`."""

    def __init__(self, refresh_token: str):
        super().__init__(refresh_token=refresh_token)


class CreateUserRequest(dict):
    """
    Payload for :meth:`AuthMasterClient.create_user`.

    Parameters
    ----------
    username : str
        Unique username within the tenant.
    email : str
        Email address.
    password : str
        Initial password.
    nickname : str, optional
    phone : str, optional
    roles : list[str], optional
        List of role codes to assign at creation time.
    extra : dict, optional
        Additional custom fields.
    """

    def __init__(
        self,
        username: str,
        email: str,
        password: str,
        *,
        nickname: Optional[str] = None,
        phone: Optional[str] = None,
        roles: Optional[list[str]] = None,
        **extra: Any,
    ):
        super().__init__(
            username=username,
            email=email,
            password=password,
            nickname=nickname,
            phone=phone,
            roles=roles or [],
            **extra,
        )


class UpdateUserRequest(dict):
    """
    Partial update payload for :meth:`AuthMasterClient.update_user`.

    All fields are optional — only supplied fields are updated.
    """

    def __init__(
        self,
        *,
        nickname: Optional[str] = None,
        email: Optional[str] = None,
        phone: Optional[str] = None,
        status: Optional[str] = None,
        mfa_enabled: Optional[bool] = None,
        roles: Optional[list[str]] = None,
        **extra: Any,
    ):
        super().__init__(
            nickname=nickname,
            email=email,
            phone=phone,
            status=status,
            mfa_enabled=mfa_enabled,
            roles=roles,
            **extra,
        )


class CreateRoleRequest(dict):
    """Payload for :meth:`AuthMasterClient.create_role`."""

    def __init__(
        self,
        name: str,
        code: str,
        description: str = "",
        *,
        permissions: Optional[list[str]] = None,
        **extra: Any,
    ):
        super().__init__(
            name=name,
            code=code,
            description=description,
            permissions=permissions or [],
            **extra,
        )


class AssignPermissionRequest(dict):
    """Payload for :meth:`AuthMasterClient.assign_permission`."""

    def __init__(self, permission: str):
        super().__init__(permission=permission)
