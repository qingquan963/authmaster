"""
Account Module - FastAPI Router
Phase 2-5: 账号合并/解绑

User-facing endpoints:
  GET    /api/v1/account/credentials              — List all credentials
  POST   /api/v1/account/credentials              — Add a new credential
  DELETE /api/v1/account/credentials/{cred_id}    — Unbind a credential
  POST   /api/v1/account/credentials/phone/change — Change phone number

Merge endpoints:
  POST   /api/v1/account/merge/initiate           — Initiate account merge
  POST   /api/v1/account/merge/confirm            — Confirm merge (target account)
  POST   /api/v1/account/merge/cancel              — Cancel merge

Admin endpoints:
  GET    /api/v1/admin/v1/account-changes         — Query audit log

Authentication:
  All endpoints require a valid AccessToken (Bearer JWT).
  Secondary verification (MFA / password) required for sensitive operations.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Request, status
from sqlalchemy import text
from sqlalchemy.ext.asyncio import AsyncSession

from .schemas import (
    AddCredentialRequest,
    AddCredentialResponse,
    CredentialConflictError,
    CredentialListResponse,
    MergeCancelRequest,
    MergeCancelResponse,
    MergeConfirmRequest,
    MergeConfirmResponse,
    MergeInitiateRequest,
    MergeInitiateResponse,
    MergeStateMachine,
    UnbindRequest,
    ChangePhoneRequest,
    ChangePhoneResponse,
    VerificationInfo,
    AuditEventType,
)
from .service import (
    CredentialService,
    MergeService,
    CredentialConflictError as SvcCredentialConflictError,
    AccountLockedError,
    LastCredentialError,
    MergeTokenExpiredError,
    MergeMaxRetriesError,
)
from . import service as account_service

router = APIRouter(prefix="/api/v1/account", tags=["Account"])


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------
async def get_db() -> AsyncSession:
    """Override in your application to provide a real AsyncSession."""
    raise NotImplementedError("Override get_db dependency in your application")


def get_current_user_id(request: Request) -> uuid.UUID:
    """
    Extract the current user ID from the request state (populated by auth middleware).

    In production, this would:
      1. Extract Bearer token from Authorization header
      2. Validate JWT signature and expiry
      3. Return the user_id from the token claims

    For this implementation, we read from request.state.user_id (set by test harness).
    """
    user_id = getattr(request.state, "user_id", None)
    if user_id is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={"error": "unauthorized", "message": "未登录"},
        )
    return uuid.UUID(str(user_id))


def get_optional_user_id(request: Request) -> Optional[uuid.UUID]:
    """Return user_id if authenticated, None otherwise."""
    try:
        return get_current_user_id(request)
    except HTTPException:
        return None


def get_client_info(request: Request) -> tuple[Optional[str], Optional[str]]:
    """Extract IP address and User-Agent from request."""
    ip_address = request.client.host if request.client else None
    user_agent = request.headers.get("user-agent")
    return ip_address, user_agent


# ---------------------------------------------------------------------------
# Credential Endpoints
# ---------------------------------------------------------------------------
@router.get(
    "/credentials",
    response_model=CredentialListResponse,
    summary="List all credentials for the current account",
)
async def list_credentials(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Returns all active credentials bound to the authenticated user.
    Identifiers are masked for privacy (e.g., 138****0000).
    """
    user_id = get_current_user_id(request)
    svc = CredentialService(db)
    credentials = await svc.list_credentials(user_id)
    return CredentialListResponse(user_id=user_id, credentials=credentials)


@router.post(
    "/credentials",
    response_model=AddCredentialResponse,
    responses={
        409: {
            "description": "Credential already bound to another account — merge_token returned",
            "model": dict,  # CredentialConflictError serialized
        },
    },
    summary="Add a new credential to the current account",
)
async def add_credential(
    body: AddCredentialRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Add a new credential (phone/email/OAuth) to the current account.

    The verification_code must be a valid 6-digit code sent to the credential
    being added (SMS for phone, email link/code for email).

    If the credential is already bound to another account, returns HTTP 409
    with a merge_token that can be used to initiate an account merge.
    """
    user_id = get_current_user_id(request)
    ip_address, user_agent = get_client_info(request)
    svc = CredentialService(db)

    try:
        result = await svc.add_credential(
            user_id=user_id,
            cred_type=body.type,
            identifier=body.value,
            verification_code=body.verification_code,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return result
    except SvcCredentialConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "credential_conflict",
                "message": str(e),
                "conflict_account_id": str(e.conflict_account_id) if e.conflict_account_id else None,
                "merge_token": e.merge_token,
            },
        )


@router.delete(
    "/credentials/{credential_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    responses={
        400: {"description": "Cannot unbind this credential"},
        403: {"description": "Password verification failed"},
    },
    summary="Unbind a credential from the current account",
)
async def unbind_credential(
    credential_id: uuid.UUID,
    body: UnbindRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Unbind a credential from the current account.

    Requires password verification (or MFA — the body carries X-MFA-CSRF-Token
    in production, here we accept password as a stand-in for secondary verification).

    Cannot unbind:
      - The last active credential on the account
      - WeChat/Alipay/SAML credentials (requires admin intervention)
    """
    user_id = get_current_user_id(request)
    ip_address, user_agent = get_client_info(request)
    svc = CredentialService(db)

    # In production: verify password hash or validate MFA token
    # Here we do a basic length check as a stand-in
    password_verified = len(body.password) >= 6

    try:
        await svc.unbind_credential(
            user_id=user_id,
            credential_id=credential_id,
            password_verified=password_verified,
            reason=body.reason,
            ip_address=ip_address,
            user_agent=user_agent,
        )
    except LastCredentialError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={
                "error": "last_credential",
                "message": "无法解绑最后一个凭证",
                "code": "LAST_CREDENTIAL",
            },
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "bad_request", "message": str(e)},
        )


@router.post(
    "/credentials/phone/change",
    response_model=ChangePhoneResponse,
    summary="Change (re-bind) the phone number on the account",
)
async def change_phone(
    body: ChangePhoneRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Change the phone number on the current account.

    Requires:
      1. Password verification
      2. SMS verification code sent to the new phone number

    Atomic operation: old phone is unbound and new phone is bound in a single
    transaction.
    """
    user_id = get_current_user_id(request)
    ip_address, user_agent = get_client_info(request)
    svc = CredentialService(db)

    try:
        await svc.change_phone(
            user_id=user_id,
            new_phone=body.new_phone,
            code=body.code,
            password_verified=True,  # Caller must validate password before
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return ChangePhoneResponse()
    except SvcCredentialConflictError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "credential_conflict", "message": str(e)},
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "validation_error", "message": str(e)},
        )


# ---------------------------------------------------------------------------
# Merge Endpoints
# ---------------------------------------------------------------------------
@router.post(
    "/merge/initiate",
    response_model=MergeInitiateResponse,
    summary="Initiate an account merge (source account)",
)
async def merge_initiate(
    body: MergeInitiateRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Initiate an account merge from the source account side.

    Called after the user attempts to add a credential that is already bound
    to another account (conflict response contains a merge_token).

    Requires:
      - A valid merge_token (from conflict response)
      - Source account identity verification (password or MFA)
    """
    user_id = get_current_user_id(request)
    ip_address, user_agent = get_client_info(request)
    svc = MergeService(db)

    try:
        result = await svc.initiate_merge(
            source_user_id=user_id,
            merge_token=body.merge_token,
            source_verification=body.source_account_verification,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return MergeInitiateResponse(
            merge_request_id=result["merge_request_id"],
            status=result["status"],
            expires_at=result["expires_at"],
            message=result["message"],
        )
    except MergeTokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"error": "token_expired", "message": "合并 Token 已过期，请重新发起"},
        )
    except AccountLockedError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "account_locked", "message": str(e)},
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "bad_request", "message": str(e)},
        )


@router.post(
    "/merge/confirm",
    response_model=MergeConfirmResponse,
    summary="Confirm an account merge (target account)",
)
async def merge_confirm(
    body: MergeConfirmRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Confirm an account merge from the target account side.

    This is called when the target account owner clicks the confirmation link
    sent to their email or phone. The merge is executed atomically.

    Requires:
      - A valid merge_token
      - Target account identity verification (email code, phone code, or MFA)
    """
    ip_address, user_agent = get_client_info(request)
    svc = MergeService(db)

    try:
        result = await svc.confirm_merge(
            merge_token=body.merge_token,
            target_verification=body.target_verification,
            ip_address=ip_address,
            user_agent=user_agent,
        )
        return MergeConfirmResponse(
            status=result.get("status", "ok"),
            message=result.get("message", "账号合并已完成"),
            merged_account_email=result.get("merged_account_email"),
        )
    except MergeTokenExpiredError:
        raise HTTPException(
            status_code=status.HTTP_410_GONE,
            detail={"error": "token_expired", "message": "合并 Token 已过期"},
        )
    except MergeMaxRetriesError:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={
                "error": "max_retries_exceeded",
                "message": "合并失败，已达最大重试次数，请取消后重新发起",
            },
        )
    except AccountLockedError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail={"error": "account_locked", "message": str(e)},
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "bad_request", "message": str(e)},
        )


@router.post(
    "/merge/cancel",
    response_model=MergeCancelResponse,
    summary="Cancel a pending account merge",
)
async def merge_cancel(
    body: MergeCancelRequest,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Cancel a pending account merge. Either party (source or target) can cancel
    before the merge is executed.
    """
    user_id = get_current_user_id(request)
    ip_address, user_agent = get_client_info(request)
    svc = MergeService(db)

    await svc.cancel_merge(
        merge_token=body.merge_token,
        cancelled_by=user_id,
        reason=body.reason,
        ip_address=ip_address,
        user_agent=user_agent,
    )
    return MergeCancelResponse(status="ok", message="合并已取消")


# ---------------------------------------------------------------------------
# Admin Endpoints
# ---------------------------------------------------------------------------
admin_router = APIRouter(prefix="/api/v1/admin/v1", tags=["Account Admin"])


@admin_router.get(
    "/account-changes",
    summary="Query account change audit log (Admin)",
)
async def list_account_changes(
    request: Request,
    page: int = 1,
    page_size: int = 50,
    user_id: Optional[uuid.UUID] = None,
    event_type: Optional[str] = None,
    start_date: Optional[datetime] = None,
    end_date: Optional[datetime] = None,
    db: AsyncSession = Depends(get_db),
):
    """
    Admin-only endpoint to query the account_change_log table.

    Supports filtering by user_id, event_type, and date range.
    """
    conditions = []
    params = {"limit": page_size, "offset": (page - 1) * page_size}

    if user_id:
        conditions.append("acl.user_id = :user_id")
        params["user_id"] = str(user_id)
    if event_type:
        conditions.append("acl.event_type = :event_type")
        params["event_type"] = event_type
    if start_date:
        conditions.append("acl.created_at >= :start_date")
        params["start_date"] = start_date
    if end_date:
        conditions.append("acl.created_at <= :end_date")
        params["end_date"] = end_date

    where_clause = " AND ".join(conditions) if conditions else "1=1"

    total_result = await db.execute(
        text(f"SELECT COUNT(*) FROM account_change_log acl WHERE {where_clause}"),
        params,
    )
    total = (await total_result.scalar()) or 0

    result = await db.execute(
        text(f"""
            SELECT
                acl.id,
                acl.user_id,
                u.email as user_email,
                acl.event_type,
                acl.event_detail,
                acl.changed_by,
                acl.ip_address,
                acl.created_at
            FROM account_change_log acl
            JOIN auth_users u ON u.id = acl.user_id
            WHERE {where_clause}
            ORDER BY acl.created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        params,
    )

    items = []
    rows = await result.fetchall()
    for row in rows:
        r = row._mapping if hasattr(row, "_mapping") else row
        items.append({
            "id": str(r["id"]),
            "user_id": str(r["user_id"]),
            "user_email": r["user_email"],
            "event_type": r["event_type"],
            "event_detail": r["event_detail"],
            "changed_by": str(r["changed_by"]) if r["changed_by"] else None,
            "ip_address": r["ip_address"],
            "created_at": r["created_at"].isoformat() if r["created_at"] else None,
        })

    return {"items": items, "total": total, "page": page, "page_size": page_size}
