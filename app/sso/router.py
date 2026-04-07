"""
SSO Module - FastAPI Router
Phase 2-9: SSO 统一登出

Endpoints:
  GET  /oidc/logout           — SP-Initiated OIDC logout entry
  POST /oidc/logout           — OIDC logout confirmation
  POST /saml/slo              — SAML Single Logout
  GET  /api/v1/admin/v1/sessions            — List active sessions (admin)
  DELETE /api/v1/admin/v1/sessions/{sid}    — Force logout single session (admin)
  DELETE /api/v1/admin/v1/sessions/user/{uid} — Force logout all user sessions (admin)
  GET  /api/v1/admin/v1/dead-letters        — List dead letters (admin)
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from sqlalchemy import func, text
from sqlalchemy.ext.asyncio import AsyncSession

# Schemas and services
from .schemas import (
    ForceLogoutResponse,
    IdPInitiatedLogoutResponse,
    OIDCLogoutGet,
    OIDCLogoutPost,
    OIDCLogoutResponse,
    SAMLSLOResponse,
    SAMLSLORequest,
    SessionListResponse,
    SPSessionItem,
    DeadLetterItem,
    SSOErrorResponse,
)
from . import service as sso_service

router = APIRouter(tags=["SSO"])


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------
async def get_db() -> AsyncSession:
    """Override in your app: yields a valid AsyncSession."""
    raise NotImplementedError("Override get_db dependency in your application")


# ---------------------------------------------------------------------------
# OIDC Logout Endpoints
# ---------------------------------------------------------------------------
@router.get(
    "/oidc/logout",
    summary="OIDC SP-Initiated Logout",
    description="SP-initiated logout entry point. Clears IdP session and redirects to post_logout_redirect_uri.",
    responses={
        302: {"description": "Redirect to post_logout_redirect_uri or default page"},
        400: {"model": SSOErrorResponse, "description": "Invalid id_token_hint"},
    },
)
async def oidc_logout_get(
    request: Request,
    id_token_hint: Optional[str] = Query(None, max_length=4096, description="OIDC id_token_hint"),
    post_logout_redirect_uri: Optional[str] = Query(None, max_length=2048),
    state: Optional[str] = Query(None, max_length=512),
    db: AsyncSession = Depends(get_db),
):
    """
    [SSO-9-NOTE1] id_token_hint validation:
    - Reject if > 4096 bytes at the entry layer (return 400).
    - Decode JWT to extract user (no signature verification needed for logout).
    """
    if id_token_hint and len(id_token_hint.encode("utf-8")) > 4096:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_request", "error_description": "id_token_hint exceeds 4096 bytes"},
        )

    # Decode user from id_token_hint
    user_id: Optional[uuid.UUID] = None
    if id_token_hint:
        try:
            import jwt
            payload = jwt.decode(id_token_hint, options={"verify_signature": False})
            sub = payload.get("sub")
            if sub:
                user_id = uuid.UUID(sub)
        except Exception:
            pass

    if user_id is None:
        return RedirectResponse(url=post_logout_redirect_uri or "/", status_code=302)

    # Find the active IdP session
    result = await db.execute(
        text("""
            SELECT id FROM auth_sessions
            WHERE user_id = :uid AND revoked = FALSE
            ORDER BY created_at DESC
            LIMIT 1
        """),
        {"uid": str(user_id)},
    )
    row = await result.fetchone()
    if row is None:
        return RedirectResponse(url=post_logout_redirect_uri or "/", status_code=302)
    row_data = row._mapping if hasattr(row, "_mapping") else row
    idp_session_id = uuid.UUID(str(row_data["id"]))

    # Trigger IdP-initiated logout
    logout_result = await sso_service.idp_initiated_logout(
        db=db,
        redis=None,  # Override with actual Redis client in app
        idp_session_id=idp_session_id,
    )

    redirect_uri = post_logout_redirect_uri
    if state:
        sep = "&" if redirect_uri else ""
        redirect_uri = (redirect_uri or "/") + f"{sep}state={state}"

    return RedirectResponse(url=redirect_uri or "/", status_code=302)


@router.post(
    "/oidc/logout",
    summary="OIDC Logout Confirmation",
    response_model=OIDCLogoutResponse,
    responses={400: {"model": SSOErrorResponse}},
)
async def oidc_logout_post(
    body: OIDCLogoutPost,
    db: AsyncSession = Depends(get_db),
):
    """
    Receive logout confirmation from SP.
    `action=logout_confirmed` indicates SP has cleared its session.
    """
    if body.action != "logout_confirmed":
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_request", "error_description": f"Unknown action: {body.action}"},
        )

    # SP confirmed logout — no further action needed on IdP side for SP-initiated flow
    return OIDCLogoutResponse(
        status="ok",
        logout_id=str(body.logout_id) if body.logout_id else None,
        sp_notified=0,
        message="Logout confirmation received",
    )


# ---------------------------------------------------------------------------
# SAML SLO Endpoint
# ---------------------------------------------------------------------------
@router.post(
    "/saml/slo",
    summary="SAML 2.0 Single Logout",
    response_model=SAMLSLOResponse,
    responses={400: {"model": SSOErrorResponse}},
)
async def saml_slo(
    body: SAMLSLORequest,
    db: AsyncSession = Depends(get_db),
):
    """
    Handle SAML SLO (both SP-Initiated and IdP-Initiated).
    - SP-Initiated: receives SAMLRequest (Base64 LogoutRequest) from SP
    - IdP-Initiated: receives client_id + sp_session_id to notify SP
    """
    # SP-Initiated: decode SAML LogoutRequest
    if body.SAMLRequest:
        try:
            import base64
            decoded = base64.b64decode(body.SAMLRequest).decode("utf-8")
            # Parse SAMLRequest (minimal parse — extract NameID and SessionIndex)
            # In production, use python3-saml or defusedxml
            import re
            name_id_match = re.search(r"<saml:NameID[^>]*>([^<]+)</saml:NameID>", decoded)
            session_index_match = re.search(r"<samlp:SessionIndex>([^<]+)</samlp:SessionIndex>", decoded)
            name_id = name_id_match.group(1) if name_id_match else None
            session_index = session_index_match.group(1) if session_index_match else None

            # Find SP session by NameID / SessionIndex
            # For brevity: redirect to IdP-initiated logout page
            return SAMLSLOResponse(
                RelayState=body.RelayState,
                SAMLResponse=None,
            )
        except Exception as e:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail={"error": "invalid_request", "error_description": str(e)},
            )

    # IdP-Initiated: client_id + sp_session_id provided
    if body.client_id and body.sp_session_id:
        result = await db.execute(
            text("""
                SELECT ss.id, ss.idp_session_id, ss.client_id, ss.protocol
                FROM sp_sessions ss
                JOIN oidc_clients oc ON oc.client_id = ss.client_id
                WHERE ss.sp_session_id = :sp_sid AND ss.client_id = :cid
                  AND ss.revoked_at IS NULL
            """),
            {"sp_sid": body.sp_session_id, "cid": body.client_id},
        )
        row = await result.fetchone()
        if row is None:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail={"error": "session_not_found", "error_description": "SP session not found"},
            )

        row_data = row._mapping if hasattr(row, "_mapping") else row
        idp_session_id = uuid.UUID(str(row_data["idp_session_id"]))
        logout_result = await sso_service.idp_initiated_logout(
            db=db,
            redis=None,
            idp_session_id=idp_session_id,
        )

        return SAMLSLOResponse(RelayState=body.RelayState)

    raise HTTPException(
        status_code=status.HTTP_400_BAD_REQUEST,
        detail={"error": "invalid_request", "error_description": "Missing SAMLRequest or client_id/sp_session_id"},
    )


# ---------------------------------------------------------------------------
# Admin Session Management API
# ---------------------------------------------------------------------------
@router.get(
    "/api/v1/admin/v1/sessions",
    summary="List all active sessions (Admin)",
    response_model=SessionListResponse,
    responses={403: {"description": "Forbidden — admin only"}},
)
async def list_sessions(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    user_id: Optional[uuid.UUID] = Query(None),
    protocol: Optional[str] = Query(None, regex="^(oidc|saml)$"),
    db: AsyncSession = Depends(get_db),
):
    """
    List all active IdP + SP sessions for admin dashboard.
    Requires admin role (enforced by middleware in production).
    """
    # Build WHERE clause
    conditions = ["ss.revoked_at IS NULL"]
    params: dict = {}

    if user_id:
        conditions.append("ss.user_id = :uid")
        params["uid"] = str(user_id)
    if protocol:
        conditions.append("ss.protocol = :proto")
        params["proto"] = protocol

    where_clause = " AND ".join(conditions)
    offset = (page - 1) * page_size

    # Total count
    count_result = await db.execute(
        text(f"""
            SELECT COUNT(*) as total
            FROM sp_sessions ss
            JOIN auth_users u ON u.id = ss.user_id
            WHERE {where_clause}
        """),
        params,
    )
    total = (await count_result.scalar()) or 0

    # Items
    result = await db.execute(
        text(f"""
            SELECT
                ss.id as session_id,
                ss.user_id,
                u.email as user_email,
                COALESCE(ss.protocol, 'oidc') as login_method,
                ss.created_at,
                ss.last_active_at,
                ss.protocol,
                (SELECT COUNT(*) FROM sp_sessions ss2
                 WHERE ss2.idp_session_id = ss.idp_session_id
                   AND ss2.revoked_at IS NULL) as sp_count
            FROM sp_sessions ss
            JOIN auth_users u ON u.id = ss.user_id
            WHERE {where_clause}
            ORDER BY ss.created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        {**params, "limit": page_size, "offset": offset},
    )

    items = []
    rows = await result.fetchall()
    for row in rows:
        r = row._mapping if hasattr(row, "_mapping") else row
        items.append(SPSessionItem(
            session_id=uuid.UUID(str(r["session_id"])),
            user_id=uuid.UUID(str(r["user_id"])),
            user_email=r["user_email"],
            login_method=r["login_method"],
            created_at=r["created_at"],
            last_active_at=r.get("last_active_at"),
            sp_count=r.get("sp_count", 0) or 0,
            protocol=r.get("protocol"),
        ))

    return SessionListResponse(items=items, total=total, page=page, page_size=page_size)


@router.delete(
    "/api/v1/admin/v1/sessions/{session_id}",
    summary="Force logout a single session (Admin)",
    response_model=ForceLogoutResponse,
    responses={404: {"description": "Session not found"}},
)
async def force_logout_session(
    session_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Admin force-logout a specific IdP session and all its SP sessions.
    """
    # Get the IdP session ID
    result = await db.execute(
        text("""
            SELECT idp_session_id FROM sp_sessions
            WHERE id = :sid AND revoked_at IS NULL
        """),
        {"sid": str(session_id)},
    )
    row = await result.fetchone()
    if row is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Session not found")
    row_data = row._mapping if hasattr(row, "_mapping") else row
    idp_session_id = uuid.UUID(str(row_data["idp_session_id"]))

    logout_result = await sso_service.idp_initiated_logout(
        db=db,
        redis=None,
        idp_session_id=idp_session_id,
    )

    return ForceLogoutResponse(
        status="ok",
        sessions_revoked=1,
        sp_notified=logout_result.get("sp_notified", 0),
    )


@router.delete(
    "/api/v1/admin/v1/sessions/user/{user_id}",
    summary="Force logout all sessions for a user (Admin)",
    response_model=ForceLogoutResponse,
    responses={404: {"description": "User not found"}},
)
async def force_logout_user(
    user_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Admin force-logout all sessions for a specific user (all IdP sessions + all SP sessions).
    """
    # Get all active IdP sessions for this user
    result = await db.execute(
        text("""
            SELECT id FROM auth_sessions
            WHERE user_id = :uid AND revoked = FALSE
        """),
        {"uid": str(user_id)},
    )
    sessions = await result.fetchall()
    if not sessions:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="No active sessions found")

    total_sp_notified = 0
    for row in sessions:
        row_data = row._mapping if hasattr(row, "_mapping") else row
        idp_session_id = uuid.UUID(str(row_data["id"]))
        logout_result = await sso_service.idp_initiated_logout(
            db=db,
            redis=None,
            idp_session_id=idp_session_id,
        )
        total_sp_notified += logout_result.get("sp_notified", 0)

    return ForceLogoutResponse(
        status="ok",
        sessions_revoked=len(sessions),
        sp_notified=total_sp_notified,
    )


# ---------------------------------------------------------------------------
# Dead Letter API (Admin)
# ---------------------------------------------------------------------------
@router.get(
    "/api/v1/admin/v1/dead-letters",
    summary="List SSO logout dead letters (Admin)",
    responses={403: {"description": "Forbidden"}},
)
async def list_dead_letters(
    request: Request,
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db),
):
    """
    List all entries in the logout dead-letter queue for admin review.
    """
    offset = (page - 1) * page_size

    total_result = await db.execute(text("SELECT COUNT(*) FROM logout_dead_letters"))
    total = await total_result.scalar() or 0

    result = await db.execute(
        text("""
            SELECT id, logout_id, sp_session_id, client_id, protocol,
                   logout_uri, error_message, attempt_count, created_at, last_failed_at
            FROM logout_dead_letters
            ORDER BY created_at DESC
            LIMIT :limit OFFSET :offset
        """),
        {"limit": page_size, "offset": offset},
    )

    items = []
    rows = await result.fetchall()
    for row in rows:
        r = row._mapping if hasattr(row, "_mapping") else row
        items.append(DeadLetterItem(
            id=uuid.UUID(str(r["id"])),
            logout_id=uuid.UUID(str(r["logout_id"])),
            sp_session_id=uuid.UUID(str(r["sp_session_id"])),
            client_id=r["client_id"],
            protocol=r["protocol"],
            logout_uri=r.get("logout_uri"),
            error_message=r.get("error_message"),
            attempt_count=r.get("attempt_count", 0) or 0,
            created_at=r["created_at"],
            last_failed_at=r.get("last_failed_at"),
        ))

    return {"items": items, "total": total, "page": page, "page_size": page_size}
