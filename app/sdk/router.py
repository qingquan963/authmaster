"""
SDK Module - FastAPI Router
Phase 2-6: Auth SDK

External SDK API endpoints:
  /api/v1/sdk/auth/*       — Authentication (login/logout/refresh/session)
  /api/v1/sdk/users/*       — User CRUD
  /api/v1/sdk/roles/*       — Role and permission management
  /api/v1/sdk/quota/*       — Quota and rate limit queries

Authentication:
  All endpoints require:
    - X-API-Key header
    - X-API-Signature header (HMAC-SHA256)
    - X-Timestamp header (Unix epoch seconds)
  Some endpoints also accept Authorization: Bearer <access_token> for user context.
"""
from __future__ import annotations

import uuid
from typing import Annotated, Optional

from fastapi import APIRouter, Depends, Header, HTTPException, Request, status
from fastapi.responses import JSONResponse
from sqlalchemy.ext.asyncio import AsyncSession

from .errors import SDKAPIError
from .middleware import (
    get_db,
    require_api_key_auth,
    require_scope,
)
from .models import APIKey
from . import service as sdk_service
from . import schemas as s


router = APIRouter(prefix="/api/v1/sdk", tags=["SDK API"])


# ---------------------------------------------------------------------------
# Dependency shorthand
# ---------------------------------------------------------------------------
SDKAuth = Annotated[
    tuple[APIKey, Optional[str]],
    Depends(require_api_key_auth),
]
DB = Annotated[AsyncSession, Depends(get_db)]


# ---------------------------------------------------------------------------
# Auth Endpoints
# ---------------------------------------------------------------------------
@router.post(
    "/auth/login",
    response_model=s.LoginResponse,
    summary="SDK Login",
    description="Authenticate a user using username (email/phone) and password via SDK API.",
)
async def sdk_auth_login(
    request: Request,
    body: s.LoginRequest,
    auth: SDKAuth,
    db: DB,
) -> JSONResponse | s.LoginResponse:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_login(
            db=db,
            username=body.username,
            password=body.password,
            login_method=body.login_method.value,
            device_fp=body.device_fp,
            extra=body.extra,
            api_key=api_key,
            request_id=request_id or "",
        )
        return s.LoginResponse(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


@router.post(
    "/auth/mfa/verify",
    response_model=s.MFAVerifyResponse,
    summary="Verify MFA Code",
    description="Complete login by providing MFA verification code.",
)
async def sdk_auth_mfa_verify(
    request: Request,
    body: s.MFAVerifyRequest,
    auth: SDKAuth,
    db: DB,
) -> JSONResponse | s.MFAVerifyResponse:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    # MFA verification would check the TOTP/SMS code
    # This is a placeholder — integrate with Phase 2-1 MFA service
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={"code": "NOT_IMPLEMENTED", "message": "MFA verify not yet integrated"},
    )


@router.post(
    "/auth/logout",
    response_model=s.LogoutResponse,
    summary="SDK Logout",
    description="Logout and revoke the specified session or all sessions.",
)
async def sdk_auth_logout(
    request: Request,
    body: s.LogoutRequest,
    auth: SDKAuth,
    db: DB,
) -> JSONResponse | s.LogoutResponse:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_logout(
            db=db,
            session_id=body.session_id,
            revoke_all=body.revoke_all,
            api_key=api_key,
            request_id=request_id or "",
        )
        return s.LogoutResponse(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


@router.post(
    "/auth/refresh",
    response_model=s.RefreshResponse,
    summary="Refresh Access Token",
    description="Exchange a refresh token for a new access token.",
)
async def sdk_auth_refresh(
    request: Request,
    body: s.RefreshRequest,
    auth: SDKAuth,
    db: DB,
) -> JSONResponse | s.RefreshResponse:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_refresh(
            db=db,
            refresh_token=body.refresh_token,
            api_key=api_key,
            request_id=request_id or "",
        )
        return s.RefreshResponse(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


@router.get(
    "/auth/session",
    response_model=s.SessionInfoResponse,
    summary="Get Current Session",
    description="Retrieve information about the current authenticated session.",
)
async def sdk_auth_session(
    request: Request,
    authorization: Annotated[Optional[str], Header()] = None,
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | s.SessionInfoResponse:
    # This endpoint requires access token via Authorization header
    if authorization is None or not authorization.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"code": "TOKEN_EXPIRED", "message": "Access token required"},
        )

    access_token = authorization[7:]
    request_id = getattr(request.state, "request_id", None)

    # We need db from context — this is a simplified version
    # In production, use proper dependency injection
    raise HTTPException(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        detail={"code": "NOT_IMPLEMENTED", "message": "Session endpoint not yet integrated"},
    )


# ---------------------------------------------------------------------------
# User Endpoints
# ---------------------------------------------------------------------------
@router.get(
    "/users",
    response_model=s.UserListResponse,
    summary="List Users",
    description="List all users for the tenant with pagination.",
    dependencies=[Depends(require_scope("users:read"))],
)
async def sdk_list_users(
    request: Request,
    page: int = 1,
    page_size: int = 20,
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | s.UserListResponse:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_list_users(
            db=db,
            api_key=api_key,
            page=page,
            page_size=min(page_size, 100),
            request_id=request_id or "",
        )
        return s.UserListResponse(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


@router.post(
    "/users",
    response_model=s.UserItem,
    summary="Create User",
    description="Create a new user for the tenant.",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("users:write"))],
)
async def sdk_create_user(
    request: Request,
    body: s.UserCreate,
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | s.UserItem:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_create_user(
            db=db,
            api_key=api_key,
            username=body.username,
            email=body.email,
            password=body.password,
            phone=body.phone,
            status=body.status.value,
            extra=body.extra,
            request_id=request_id or "",
        )
        return s.UserItem(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


@router.get(
    "/users/{user_id}",
    response_model=s.UserItem,
    summary="Get User",
    description="Get a user by ID.",
    dependencies=[Depends(require_scope("users:read"))],
)
async def sdk_get_user(
    request: Request,
    user_id: uuid.UUID,
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | s.UserItem:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_get_user(
            db=db,
            api_key=api_key,
            user_id=user_id,
            request_id=request_id or "",
        )
        return s.UserItem(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


@router.put(
    "/users/{user_id}",
    response_model=s.UserItem,
    summary="Update User",
    description="Update a user's fields.",
    dependencies=[Depends(require_scope("users:write"))],
)
async def sdk_update_user(
    request: Request,
    user_id: uuid.UUID,
    body: s.UserUpdate,
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | s.UserItem:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_update_user(
            db=db,
            api_key=api_key,
            user_id=user_id,
            email=body.email,
            phone=body.phone,
            status=body.status.value if body.status else None,
            password=body.password,
            extra=body.extra,
            request_id=request_id or "",
        )
        return s.UserItem(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


@router.delete(
    "/users/{user_id}",
    response_model=s.UserDeleteResponse,
    summary="Delete User",
    description="Soft-delete a user.",
    dependencies=[Depends(require_scope("users:write"))],
)
async def sdk_delete_user(
    request: Request,
    user_id: uuid.UUID,
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | s.UserDeleteResponse:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_delete_user(
            db=db,
            api_key=api_key,
            user_id=user_id,
            request_id=request_id or "",
        )
        return s.UserDeleteResponse(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


# ---------------------------------------------------------------------------
# Role Endpoints
# ---------------------------------------------------------------------------
@router.get(
    "/roles",
    response_model=s.RoleListResponse,
    summary="List Roles",
    description="List all roles for the tenant.",
    dependencies=[Depends(require_scope("roles:read"))],
)
async def sdk_list_roles(
    request: Request,
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | s.RoleListResponse:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_list_roles(
            db=db,
            api_key=api_key,
            request_id=request_id or "",
        )
        return s.RoleListResponse(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


@router.post(
    "/roles",
    response_model=s.RoleItem,
    summary="Create Role",
    description="Create a new role.",
    status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(require_scope("roles:write"))],
)
async def sdk_create_role(
    request: Request,
    body: s.RoleCreate,
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | s.RoleItem:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_create_role(
            db=db,
            api_key=api_key,
            name=body.name,
            description=body.description or "",
            permissions=body.permissions,
            status=body.status.value,
            request_id=request_id or "",
        )
        return s.RoleItem(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


@router.post(
    "/roles/{role_id}/permissions",
    response_model=dict,
    summary="Assign Permission",
    description="Assign a permission to a role.",
    dependencies=[Depends(require_scope("roles:write"))],
)
async def sdk_assign_permission(
    request: Request,
    role_id: uuid.UUID,
    body: s.PermissionAssignRequest,
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | dict:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_assign_permission(
            db=db,
            api_key=api_key,
            role_id=role_id,
            permission=body.permission,
            request_id=request_id or "",
        )
        return result
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


@router.delete(
    "/roles/{role_id}/permissions/{permission:path}",
    response_model=s.PermissionRemoveResponse,
    summary="Remove Permission",
    description="Remove a permission from a role.",
    dependencies=[Depends(require_scope("roles:write"))],
)
async def sdk_remove_permission(
    request: Request,
    role_id: uuid.UUID,
    permission: str,
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | s.PermissionRemoveResponse:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_remove_permission(
            db=db,
            api_key=api_key,
            role_id=role_id,
            permission=permission,
            request_id=request_id or "",
        )
        return s.PermissionRemoveResponse(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


# ---------------------------------------------------------------------------
# Quota Endpoints
# ---------------------------------------------------------------------------
@router.get(
    "/quota",
    response_model=s.QuotaResponse,
    summary="Get Quota",
    description="Get current API quota usage and rate limits.",
    dependencies=[Depends(require_scope("quota:read"))],
)
async def sdk_get_quota(
    request: Request,
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | s.QuotaResponse:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    try:
        result = await sdk_service.sdk_get_quota(
            db=db,
            api_key=api_key,
            request_id=request_id or "",
        )
        return s.QuotaResponse(**result)
    except SDKAPIError as e:
        return JSONResponse(status_code=e.status_code, content=e.to_dict())


@router.get(
    "/quota/usage",
    response_model=s.QuotaUsageResponse,
    summary="Get Quota Usage Detail",
    description="Get detailed API usage broken down by day/week/month.",
    dependencies=[Depends(require_scope("quota:read"))],
)
async def sdk_get_quota_usage(
    request: Request,
    period: str = "daily",
    auth: SDKAuth = None,
    db: DB = None,
) -> JSONResponse | s.QuotaUsageResponse:
    api_key, _ = auth
    request_id = getattr(request.state, "request_id", None)

    # Placeholder — in production, query api_call_logs aggregated by day
    return JSONResponse(
        status_code=status.HTTP_501_NOT_IMPLEMENTED,
        content={
            "error": {
                "code": "NOT_IMPLEMENTED",
                "message": "Quota usage detail not yet implemented",
                "request_id": request_id,
            }
        },
    )
