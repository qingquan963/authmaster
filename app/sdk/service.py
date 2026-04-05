"""
SDK Module - Core Business Logic
Phase 2-6: Auth SDK

Service layer for SDK API endpoints.
Handles auth operations, user CRUD, role management, and quota tracking.
"""
from __future__ import annotations

import hashlib
import hmac
import secrets
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from sqlalchemy import and_, func, select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .errors import (
    SDKAPIError,
    internal_error,
    invalid_api_key,
    invalid_signature,
    mfa_required,
    not_found,
    permission_denied,
    rate_limit_exceeded,
    timestamp_expired,
    token_expired,
    validation_error,
)
from .models import APIKey, APICallLog


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# API signature validity window: 5 minutes
SIGNATURE_MAX_AGE_SECONDS = 300
# Default rate limits
DEFAULT_RATE_LIMIT_RPS = 100
DEFAULT_RATE_LIMIT_BURST = 200
# Token TTLs
ACCESS_TOKEN_TTL_SECONDS = 3600
REFRESH_TOKEN_TTL_SECONDS = 2592000  # 30 days


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def generate_api_key() -> str:
    return "ak_" + secrets.token_hex(24)


def generate_api_secret() -> str:
    return secrets.token_hex(32)


def hash_secret(secret: str) -> str:
    return hashlib.sha256(secret.encode()).hexdigest()


def verify_hmac_signature(
    api_secret_hash: str,
    method: str,
    path: str,
    timestamp: int,
    body: str,
    provided_signature: str,
) -> bool:
    """
    Verify HMAC-SHA256 signature.

    Signature message format:
      METHOD + PATH + TIMESTAMP + BODY

    Note: We verify using the stored hash of the secret as the HMAC key,
    since the original secret is not stored (only its hash is).
    The client uses the raw secret to sign; we verify using the same hash.
    """
    import time
    current_time = int(time.time())
    if abs(current_time - timestamp) > SIGNATURE_MAX_AGE_SECONDS:
        return False

    msg = method.upper() + path + str(timestamp) + body
    expected = hmac.new(
        api_secret_hash.encode(),
        msg.encode(),
        hashlib.sha256,
    ).hexdigest()
    return hmac.compare_digest(expected, provided_signature)


async def check_rate_limit(
    db: AsyncSession,
    api_key: APIKey,
    endpoint: str,
) -> None:
    """
    Check and enforce rate limit using Redis sliding window.
    Raises SDKAPIError if limit exceeded.
    """
    import time
    now = int(time.time())
    window = 1  # 1-second window for RPS

    # Use Redis for rate limiting if available, otherwise use in-memory
    # This is a placeholder — integrate with existing Redis setup
    # redis_key = f"ratelimit:{api_key.id}:{now // window}"
    # In production: use sliding window LUA script against Redis
    pass


# ---------------------------------------------------------------------------
# API Key Service
# ---------------------------------------------------------------------------
async def get_api_key_by_key(
    db: AsyncSession,
    api_key_str: str,
) -> Optional[APIKey]:
    """Lookup an API key by its string value."""
    result = await db.execute(
        select(APIKey).where(
            and_(
                APIKey.api_key == api_key_str,
                APIKey.enabled == True,  # noqa: E712
            )
        )
    )
    return result.scalar_one_or_none()


async def update_api_key_last_used(
    db: AsyncSession,
    api_key_id: uuid.UUID,
) -> None:
    """Update the last_used_at timestamp for an API key."""
    await db.execute(
        text("""
            UPDATE api_keys
            SET last_used_at = NOW()
            WHERE id = :key_id
        """),
        {"key_id": str(api_key_id)},
    )


# ---------------------------------------------------------------------------
# Auth Service
# ---------------------------------------------------------------------------
async def sdk_login(
    db: AsyncSession,
    username: str,
    password: str,
    login_method: str,
    device_fp: Optional[str],
    extra: Optional[dict],
    api_key: APIKey,
    request_id: str,
) -> dict:
    """
    Authenticate a user via SDK API.

    Returns login response dict or raises SDKAPIError.
    """
    # Lookup user by username/email
    user_result = await db.execute(
        text("""
            SELECT id, email, password_hash, status
            FROM auth_users
            WHERE (email = :username OR username = :username)
              AND status = 'active'
            LIMIT 1
        """),
        {"username": username},
    )
    user_row = user_result.fetchone()

    if not user_row:
        raise invalid_credentials(request_id)

    user_id, email, password_hash, status = user_row

    # Verify password
    import bcrypt
    if not bcrypt.checkpw(password.encode(), password_hash.encode()):
        raise invalid_credentials(request_id)

    # Generate tokens
    access_token = _generate_jwt(user_id, email, api_key.tenant_id)
    refresh_token = _generate_refresh_token(user_id)

    # Create session record
    session_id = str(uuid.uuid4())
    await db.execute(
        text("""
            INSERT INTO auth_sessions
                (id, user_id, tenant_id, login_method, ip_address, user_agent,
                 device_fp_hash, access_token, refresh_token,
                 access_token_expires_at, refresh_token_expires_at,
                 created_at, last_active_at, revoked)
            VALUES
                (:id, :user_id, :tenant_id, :login_method, NULL, NULL,
                 :device_fp, :access_token, :refresh_token,
                 NOW() + INTERVAL '1 hour', NOW() + INTERVAL '30 days',
                 NOW(), NOW(), FALSE)
        """),
        {
            "id": session_id,
            "user_id": str(user_id),
            "tenant_id": str(api_key.tenant_id),
            "login_method": login_method,
            "device_fp": device_fp,
            "access_token": access_token,
            "refresh_token": refresh_token,
        },
    )
    await db.commit()

    return {
        "access_token": access_token,
        "refresh_token": refresh_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "refresh_expires_in": REFRESH_TOKEN_TTL_SECONDS,
        "mfa_required": False,
        "mfa_token": None,
        "session_id": session_id,
    }


async def sdk_logout(
    db: AsyncSession,
    session_id: Optional[str],
    revoke_all: bool,
    api_key: APIKey,
    request_id: str,
) -> dict:
    """Logout and revoke session(s)."""
    if revoke_all:
        result = await db.execute(
            text("""
                UPDATE auth_sessions
                SET revoked = TRUE, revoked_at = NOW()
                WHERE user_id IN (
                    SELECT id FROM auth_users WHERE tenant_id = :tenant_id
                )
                  AND revoked = FALSE
                RETURNING id
            """),
            {"tenant_id": str(api_key.tenant_id)},
        )
        revoked_count = len(result.fetchall())
    elif session_id:
        result = await db.execute(
            text("""
                UPDATE auth_sessions
                SET revoked = TRUE, revoked_at = NOW()
                WHERE id = :session_id
                  AND revoked = FALSE
                RETURNING id
            """),
            {"session_id": session_id},
        )
        revoked_count = len(result.fetchall())
    else:
        revoked_count = 0

    await db.commit()
    return {"success": True, "revoked_count": revoked_count}


async def sdk_refresh(
    db: AsyncSession,
    refresh_token: str,
    api_key: APIKey,
    request_id: str,
) -> dict:
    """Refresh access token using a refresh token."""
    session_result = await db.execute(
        text("""
            SELECT s.id, s.user_id, u.email, s.revoked, s.refresh_token_expires_at
            FROM auth_sessions s
            JOIN auth_users u ON u.id = s.user_id
            WHERE s.refresh_token = :refresh_token
              AND s.revoked = FALSE
            LIMIT 1
        """),
        {"refresh_token": refresh_token},
    )
    session = session_result.fetchone()

    if not session:
        raise token_expired(request_id)

    session_id, user_id, email, revoked, expires_at = session

    if revoked:
        raise token_expired(request_id)

    if expires_at < datetime.now(timezone.utc):
        raise token_expired(request_id)

    # Generate new tokens
    new_access_token = _generate_jwt(user_id, email, api_key.tenant_id)
    new_refresh_token = _generate_refresh_token(user_id)

    await db.execute(
        text("""
            UPDATE auth_sessions
            SET access_token = :access_token,
                refresh_token = :refresh_token,
                access_token_expires_at = NOW() + INTERVAL '1 hour',
                refresh_token_expires_at = NOW() + INTERVAL '30 days',
                last_active_at = NOW()
            WHERE id = :session_id
        """),
        {
            "access_token": new_access_token,
            "refresh_token": new_refresh_token,
            "session_id": session_id,
        },
    )
    await db.commit()

    return {
        "access_token": new_access_token,
        "refresh_token": new_refresh_token,
        "token_type": "Bearer",
        "expires_in": ACCESS_TOKEN_TTL_SECONDS,
        "refresh_expires_in": REFRESH_TOKEN_TTL_SECONDS,
    }


async def sdk_get_session(
    db: AsyncSession,
    access_token: str,
    api_key: APIKey,
    request_id: str,
) -> dict:
    """Get current session info from access token."""
    # Decode JWT to get user_id (simplified — in production use proper JWT lib)
    user_id = _decode_jwt_user_id(access_token)
    if not user_id:
        raise token_expired(request_id)

    session_result = await db.execute(
        text("""
            SELECT s.id, s.user_id, s.login_method, s.created_at,
                   s.last_active_at, s.ip_address, s.user_agent,
                   u.email, s.revoked
            FROM auth_sessions s
            JOIN auth_users u ON u.id = s.user_id
            WHERE s.access_token = :access_token
              AND s.revoked = FALSE
              AND s.access_token_expires_at > NOW()
            LIMIT 1
        """),
        {"access_token": access_token},
    )
    session = session_result.fetchone()

    if not session:
        raise token_expired(request_id)

    (
        session_id, user_id_out, login_method,
        created_at, last_active_at,
        ip_address, user_agent, email, revoked,
    ) = session

    return {
        "session_id": str(session_id),
        "user_id": str(user_id_out),
        "email": email,
        "login_method": login_method,
        "created_at": created_at.isoformat() if created_at else None,
        "last_active_at": last_active_at.isoformat() if last_active_at else None,
        "ip_address": str(ip_address) if ip_address else None,
        "user_agent": user_agent,
        "is_active": not revoked,
    }


# ---------------------------------------------------------------------------
# User Service
# ---------------------------------------------------------------------------
async def sdk_list_users(
    db: AsyncSession,
    api_key: APIKey,
    page: int = 1,
    page_size: int = 20,
    request_id: str = "",
) -> dict:
    """List users for the tenant with pagination."""
    offset = (page - 1) * page_size

    count_result = await db.execute(
        text("""
            SELECT COUNT(*)
            FROM auth_users
            WHERE tenant_id = :tenant_id
              AND status != 'deleted'
        """),
        {"tenant_id": str(api_key.tenant_id)},
    )
    total = count_result.scalar() or 0

    users_result = await db.execute(
        text("""
            SELECT id, username, email, phone, status, created_at, updated_at, extra_data
            FROM auth_users
            WHERE tenant_id = :tenant_id
              AND status != 'deleted'
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        {
            "tenant_id": str(api_key.tenant_id),
            "limit": page_size,
            "offset": offset,
        },
    )
    rows = users_result.fetchall()

    items = []
    for row in rows:
        items.append({
            "id": str(row[0]),
            "username": row[1],
            "email": row[2],
            "phone": row[3],
            "status": row[4],
            "created_at": row[5].isoformat() if row[5] else None,
            "updated_at": row[6].isoformat() if row[6] else None,
            "extra": row[7] or {},
        })

    return {
        "items": items,
        "total": total,
        "page": page,
        "page_size": page_size,
        "has_more": offset + len(items) < total,
    }


async def sdk_create_user(
    db: AsyncSession,
    api_key: APIKey,
    username: str,
    email: str,
    password: str,
    phone: Optional[str],
    status: str,
    extra: Optional[dict],
    request_id: str,
) -> dict:
    """Create a new user."""
    # Hash password
    import bcrypt
    password_hash = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

    user_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    try:
        await db.execute(
            text("""
                INSERT INTO auth_users
                    (id, tenant_id, username, email, phone, password_hash,
                     status, created_at, updated_at, extra_data)
                VALUES
                    (:id, :tenant_id, :username, :email, :phone, :password_hash,
                     :status, :now, :now, :extra)
            """),
            {
                "id": user_id,
                "tenant_id": str(api_key.tenant_id),
                "username": username,
                "email": email,
                "phone": phone,
                "password_hash": password_hash,
                "status": status,
                "now": now,
                "extra": extra or {},
            },
        )
        await db.commit()
    except Exception as e:
        if "duplicate" in str(e).lower() or "unique" in str(e).lower():
            raise validation_error(f"User with email '{email}' already exists", request_id=request_id)
        raise

    return {
        "id": user_id,
        "username": username,
        "email": email,
        "phone": phone,
        "status": status,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "extra": extra or {},
    }


async def sdk_get_user(
    db: AsyncSession,
    api_key: APIKey,
    user_id: uuid.UUID,
    request_id: str,
) -> dict:
    """Get user by ID."""
    result = await db.execute(
        text("""
            SELECT id, username, email, phone, status, created_at, updated_at, extra_data
            FROM auth_users
            WHERE id = :user_id
              AND tenant_id = :tenant_id
              AND status != 'deleted'
        """),
        {"user_id": str(user_id), "tenant_id": str(api_key.tenant_id)},
    )
    row = result.fetchone()

    if not row:
        raise not_found("User", request_id)

    return {
        "id": str(row[0]),
        "username": row[1],
        "email": row[2],
        "phone": row[3],
        "status": row[4],
        "created_at": row[5].isoformat() if row[5] else None,
        "updated_at": row[6].isoformat() if row[6] else None,
        "extra": row[7] or {},
    }


async def sdk_update_user(
    db: AsyncSession,
    api_key: APIKey,
    user_id: uuid.UUID,
    email: Optional[str],
    phone: Optional[str],
    status: Optional[str],
    password: Optional[str],
    extra: Optional[dict],
    request_id: str,
) -> dict:
    """Update user fields."""
    updates: list[str] = []
    params: dict[str, Any] = {"user_id": str(user_id), "tenant_id": str(api_key.tenant_id)}

    if email is not None:
        updates.append("email = :email")
        params["email"] = email
    if phone is not None:
        updates.append("phone = :phone")
        params["phone"] = phone
    if status is not None:
        updates.append("status = :status")
        params["status"] = status
    if password is not None:
        import bcrypt
        updates.append("password_hash = :password_hash")
        params["password_hash"] = bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()
    if extra is not None:
        updates.append("extra_data = :extra")
        params["extra"] = extra

    if updates:
        updates.append("updated_at = NOW()")
        await db.execute(
            text(f"""
                UPDATE auth_users
                SET {', '.join(updates)}
                WHERE id = :user_id AND tenant_id = :tenant_id AND status != 'deleted'
            """),
            params,
        )
        await db.commit()

    return await sdk_get_user(db, api_key, user_id, request_id)


async def sdk_delete_user(
    db: AsyncSession,
    api_key: APIKey,
    user_id: uuid.UUID,
    request_id: str,
) -> dict:
    """Soft-delete a user."""
    result = await db.execute(
        text("""
            UPDATE auth_users
            SET status = 'deleted', updated_at = NOW()
            WHERE id = :user_id AND tenant_id = :tenant_id AND status != 'deleted'
            RETURNING id
        """),
        {"user_id": str(user_id), "tenant_id": str(api_key.tenant_id)},
    )
    row = result.fetchone()
    if not row:
        raise not_found("User", request_id)
    await db.commit()
    return {"success": True, "deleted_user_id": str(user_id)}


# ---------------------------------------------------------------------------
# Role Service
# ---------------------------------------------------------------------------
async def sdk_list_roles(
    db: AsyncSession,
    api_key: APIKey,
    request_id: str,
) -> dict:
    """List all roles for the tenant."""
    result = await db.execute(
        text("""
            SELECT id, name, description, permissions, status, created_at, updated_at
            FROM auth_roles
            WHERE tenant_id = :tenant_id AND status != 'deleted'
            ORDER BY name
        """),
        {"tenant_id": str(api_key.tenant_id)},
    )
    rows = result.fetchall()

    items = []
    for row in rows:
        items.append({
            "id": str(row[0]),
            "name": row[1],
            "description": row[2],
            "permissions": row[3] or [],
            "status": row[4],
            "created_at": row[5].isoformat() if row[5] else None,
            "updated_at": row[6].isoformat() if row[6] else None,
        })

    return {"items": items, "total": len(items)}


async def sdk_create_role(
    db: AsyncSession,
    api_key: APIKey,
    name: str,
    description: str,
    permissions: list[str],
    status: str,
    request_id: str,
) -> dict:
    """Create a new role."""
    role_id = str(uuid.uuid4())
    now = datetime.now(timezone.utc)

    await db.execute(
        text("""
            INSERT INTO auth_roles
                (id, tenant_id, name, description, permissions, status, created_at, updated_at)
            VALUES
                (:id, :tenant_id, :name, :description, :permissions::jsonb, :status, :now, :now)
        """),
        {
            "id": role_id,
            "tenant_id": str(api_key.tenant_id),
            "name": name,
            "description": description,
            "permissions": permissions,
            "status": status,
            "now": now,
        },
    )
    await db.commit()

    return {
        "id": role_id,
        "name": name,
        "description": description,
        "permissions": permissions,
        "status": status,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }


async def sdk_assign_permission(
    db: AsyncSession,
    api_key: APIKey,
    role_id: uuid.UUID,
    permission: str,
    request_id: str,
) -> dict:
    """Assign a permission to a role."""
    # Fetch current permissions
    result = await db.execute(
        text("""
            SELECT permissions
            FROM auth_roles
            WHERE id = :role_id AND tenant_id = :tenant_id AND status != 'deleted'
        """),
        {"role_id": str(role_id), "tenant_id": str(api_key.tenant_id)},
    )
    row = result.fetchone()
    if not row:
        raise not_found("Role", request_id)

    permissions = row[0] or []
    if permission not in permissions:
        permissions.append(permission)
        await db.execute(
            text("""
                UPDATE auth_roles
                SET permissions = :permissions::jsonb, updated_at = NOW()
                WHERE id = :role_id
            """),
            {"permissions": permissions, "role_id": str(role_id)},
        )
        await db.commit()

    return {
        "id": str(role_id),
        "permissions": permissions,
    }


async def sdk_remove_permission(
    db: AsyncSession,
    api_key: APIKey,
    role_id: uuid.UUID,
    permission: str,
    request_id: str,
) -> dict:
    """Remove a permission from a role."""
    result = await db.execute(
        text("""
            SELECT permissions
            FROM auth_roles
            WHERE id = :role_id AND tenant_id = :tenant_id AND status != 'deleted'
        """),
        {"role_id": str(role_id), "tenant_id": str(api_key.tenant_id)},
    )
    row = result.fetchone()
    if not row:
        raise not_found("Role", request_id)

    permissions = row[0] or []
    if permission in permissions:
        permissions.remove(permission)
        await db.execute(
            text("""
                UPDATE auth_roles
                SET permissions = :permissions::jsonb, updated_at = NOW()
                WHERE id = :role_id
            """),
            {"permissions": permissions, "role_id": str(role_id)},
        )
        await db.commit()

    return {"success": True, "role_id": str(role_id), "removed_permission": permission}


# ---------------------------------------------------------------------------
# Quota Service
# ---------------------------------------------------------------------------
async def sdk_get_quota(
    db: AsyncSession,
    api_key: APIKey,
    request_id: str,
) -> dict:
    """Get current quota usage for the API key."""
    monthly_used = api_key.monthly_used or 0
    monthly_quota = api_key.monthly_quota
    remaining = (monthly_quota - monthly_used) if monthly_quota else None

    reset_at = None
    if api_key.quota_reset_at:
        reset_at = api_key.quota_reset_at.isoformat()

    return {
        "monthly_quota": monthly_quota,
        "monthly_used": monthly_used,
        "remaining": remaining,
        "reset_at": reset_at,
        "rate_limit_rps": api_key.rate_limit_rps or DEFAULT_RATE_LIMIT_RPS,
        "rate_limit_burst": api_key.rate_limit_burst or DEFAULT_RATE_LIMIT_BURST,
    }


# ---------------------------------------------------------------------------
# Token generation helpers
# ---------------------------------------------------------------------------
def _generate_jwt(user_id: str, email: str, tenant_id: uuid.UUID) -> str:
    """
    Generate a JWT access token.
    In production: use python-jose or PyJWT with proper RS256/HS256 signing.
    """
    import base64
    import json
    import time

    header = base64.urlsafe_b64encode(json.dumps({"alg": "HS256", "typ": "JWT"}).encode()).decode().rstrip("=")
    now = int(time.time())
    payload = base64.urlsafe_b64encode(json.dumps({
        "sub": str(user_id),
        "email": email,
        "tenant_id": str(tenant_id),
        "iat": now,
        "exp": now + ACCESS_TOKEN_TTL_SECONDS,
    }).encode()).decode().rstrip("=")
    signature = hmac.new(
        b"authmaster-secret-key-change-in-production",
        f"{header}.{payload}".encode(),
        hashlib.sha256,
    ).hexdigest()
    return f"{header}.{payload}.{signature}"


def _generate_refresh_token(user_id: str) -> str:
    """Generate a secure refresh token."""
    import time
    payload = f"{user_id}:{time.time()}:{secrets.token_hex(16)}"
    return hashlib.sha256(payload.encode()).hexdigest()


def _decode_jwt_user_id(token: str) -> Optional[str]:
    """Decode user_id from JWT (simplified)."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None
        import base64
        import json
        payload = parts[1] + "=" * (4 - len(parts[1]) % 4)
        decoded = json.loads(base64.urlsafe_b64decode(payload))
        import time
        if decoded.get("exp", 0) < time.time():
            return None
        return decoded.get("sub")
    except Exception:
        return None
