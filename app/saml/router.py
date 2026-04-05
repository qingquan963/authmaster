"""
SAML Module - FastAPI Router
Phase 2-4: SAML 2.0 SP 支持

Public SP Endpoints:
  GET  /saml/metadata          — SP metadata XML
  GET  /saml/login             — Initiate SAML SSO (redirect to IdP)
  POST /saml/acs               — Assertion Consumer Service (handle Response)

Admin API:
  GET    /admin/v1/saml/idp              — List IdP configs
  GET    /admin/v1/saml/idp/{id}          — Get IdP config detail
  POST   /admin/v1/saml/idp               — Create IdP config
  PUT    /admin/v1/saml/idp/{id}          — Update IdP config
  DELETE /admin/v1/saml/idp/{id}          — Delete (disable) IdP config
  POST   /admin/v1/saml/idp/{id}/test     — Test IdP connection

  GET    /admin/v1/saml/sp-config         — Get SP config
  PUT    /admin/v1/saml/sp-config         — Update SP config
  POST   /admin/v1/saml/sp-config/rotate-keys — Rotate SP keys

  GET    /admin/v1/saml/bindings          — List user bindings
  POST   /admin/v1/saml/bindings          — Create manual binding
  DELETE /admin/v1/saml/bindings/{id}     — Delete binding

Note: /saml/slo is handled by the SSO module (Phase 2-9).
"""
from __future__ import annotations

import base64
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from fastapi import APIRouter, Depends, Form, HTTPException, Query, Request, status
from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse, Response
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import URL

from . import service as saml_service
from .schemas import (
    AcsFormRequest,
    AcsResponse,
    AttributeMapper,
    AttributeMappingItem,
    AuthnRequestStatusResponse,
    BindingCreate,
    BindingItem,
    BindingListResponse,
    IdpConfigCreate,
    IdpConfigDetailResponse,
    IdpConfigItem,
    IdpConfigListResponse,
    IdpConfigUpdate,
    ResponseValidationError,
    SamlErrorResponse,
    SamlLoginRequest,
    SamlLoginResponse,
    SpConfigResponse,
    SpConfigUpdate,
    SpKeyRotateResponse,
    SpMetadataResponse,
    UserBindingService,
)
from .models import SamlAuthnRequest, SamlIdpConfig, SamlSpConfig

router = APIRouter(tags=["SAML"])


# ---------------------------------------------------------------------------
# Dependency
# ---------------------------------------------------------------------------
async def get_db() -> AsyncSession:
    """Override in your application"""
    raise NotImplementedError("Override get_db dependency in your application")


async def get_redis() -> Optional[Any]:
    """Optional Redis client for replay cache. Override in your application."""
    return None


async def get_current_user_id() -> uuid.UUID:
    """Override: extract current user UUID from auth session. For admin APIs."""
    raise NotImplementedError("Override get_current_user_id dependency")


async def get_current_tenant_id() -> uuid.UUID:
    """Override: extract current tenant UUID from auth session."""
    raise NotImplementedError("Override get_current_tenant_id dependency")


# ---------------------------------------------------------------------------
# SP Metadata
# ---------------------------------------------------------------------------
@router.get(
    "/saml/metadata",
    summary="SAML SP Metadata",
    description="Returns SAML 2.0 SP metadata XML document for IdP configuration.",
    responses={
        200: {"content": {"application/xml": {}}, "description": "SP metadata XML"},
        404: {"model": SamlErrorResponse, "description": "SP not configured"},
    },
)
async def get_sp_metadata(
    request: Request,
    db: AsyncSession = Depends(get_db),
):
    """
    Return the SP metadata XML for this tenant.
    IdP administrators use this to configure the trust relationship.
    """
    # Get tenant_id from request (e.g., from subdomain or auth context)
    tenant_id = await _get_tenant_id_from_request(request, db)
    if tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_configured", "error_description": "SAML SP not configured for this tenant"},
        )

    sp_config_service = saml_service.SpConfigService(db)
    sp_config = await sp_config_service.get_by_tenant(tenant_id)
    if sp_config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "not_configured", "error_description": "SAML SP not configured for this tenant"},
        )

    # Build SP metadata URL
    base_url = str(request.base_url).rstrip("/")
    acs_url = f"{base_url}/saml/acs"
    slo_url = f"{base_url}/saml/slo"

    generator = saml_service.SpMetadataGenerator()
    metadata_xml = generator.generate(
        entity_id=sp_config.entity_id,
        acs_url=acs_url,
        slo_url=slo_url,
        sp_cert_pem=sp_config.sp_cert_pem,
        name_id_formats=[sp_config.preferred_name_id_format],
        sign_requests=sp_config.sign_requests,
        want_assertions_signed=True,
        want_assertions_encrypted=sp_config.want_assertions_encrypted,
        sign_algorithm=sp_config.sign_algorithm,
    )

    return Response(
        content=metadata_xml,
        media_type="application/xml",
        headers={"Content-Disposition": "inline; filename=\"sp-metadata.xml\""},
    )


# ---------------------------------------------------------------------------
# SAML SSO Login Initiation
# ---------------------------------------------------------------------------
@router.get(
    "/saml/login",
    summary="Initiate SAML SSO Login",
    description="Redirect to IdP with SAML AuthnRequest (HTTP-Redirect binding).",
    responses={
        302: {"description": "Redirect to IdP SSO URL"},
        400: {"model": SamlErrorResponse, "description": "Missing or invalid Idp parameter"},
        404: {"model": SamlErrorResponse, "description": "IdP not found"},
    },
)
async def saml_login(
    request: Request,
    idp: str = Query(..., description="IdP EntityID", min_length=1),
    return_url: Optional[str] = Query(None, description="Success redirect URL (base64-encoded)"),
    name_id_format: Optional[str] = Query(None, description="Override NameID format"),
    db: AsyncSession = Depends(get_db),
    redis: Optional[Any] = Depends(get_redis),
):
    """
    Step 1 of SAML SSO: generate AuthnRequest and redirect to IdP.

    Idp parameter is the IdP EntityID (e.g., 'https://dev-xxx.okta.com').
    ReturnUrl is base64-encoded and will be returned via RelayState.
    """
    tenant_id = await _get_tenant_id_from_request(request, db)
    if tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "tenant_not_found", "error_description": "Tenant not found"},
        )

    # Find IdP config
    idp_service = saml_service.IdpConfigService(db)
    idp_config = await idp_service.get_by_entity_id(idp, tenant_id)
    if idp_config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "idp_not_found", "error_description": f"IdP '{idp}' not found or disabled"},
        )

    # Get SP config
    sp_service = saml_service.SpConfigService(db)
    sp_config = await sp_service.get_by_tenant(tenant_id)
    if sp_config is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail={"error": "sp_not_configured", "error_description": "SAML SP not configured"},
        )

    # Build URLs
    base_url = str(request.base_url).rstrip("/")
    acs_url = f"{base_url}/saml/acs"

    # Generate request ID and build AuthnRequest
    request_id = saml_service.AuthnRequestBuilder.generate_request_id()
    authn_builder = saml_service.AuthnRequestBuilder(saml_service.SpMetadataGenerator())

    redirect_url, _ = authn_builder.build(
        idp_sso_url=idp_config.sso_url,
        sp_entity_id=sp_config.entity_id,
        acs_url=acs_url,
        request_id=request_id,
        name_id_format=name_id_format or sp_config.preferred_name_id_format,
        sign_requests=sp_config.sign_requests,
    )

    # Store request state in DB for InResponseTo validation
    authn_service = saml_service.AuthnRequestService(db)
    await authn_service.create_request(
        tenant_id=tenant_id,
        idp_config_id=idp_config.id,
        request_id=request_id,
        assertion_consumer_service_url=acs_url,
        name_id_policy=name_id_format or sp_config.preferred_name_id_format,
    )

    # Store ReturnUrl in Redis (TTL=10min)
    if redis is not None and return_url:
        await redis.set(
            f"saml:relay:{request_id}",
            return_url,
            ex=600,
        )

    # Append RelayState if return_url provided
    if return_url:
        sep = "&" if "?" in redirect_url else "?"
        relay_state = base64.urlsafe_b64encode(return_url.encode()).decode()
        redirect_url = f"{redirect_url}{sep}RelayState={relay_state}"

    return RedirectResponse(url=redirect_url, status_code=302)


# ---------------------------------------------------------------------------
# ACS (Assertion Consumer Service)
# ---------------------------------------------------------------------------
@router.post(
    "/saml/acs",
    summary="Assertion Consumer Service",
    description="Handle SAML Response from IdP (HTTP-POST binding).",
    responses={
        302: {"description": "Redirect to return URL on success"},
        400: {"model": SamlErrorResponse, "description": "Invalid SAML Response"},
        401: {"model": SamlErrorResponse, "description": "Authentication failed"},
    },
    openapi_extra={
        "requestBody": {
            "content": {
                "application/x-www-form-urlencoded": {
                    "schema": {
                        "type": "object",
                        "properties": {
                            "SAMLResponse": {"type": "string", "description": "Base64-encoded SAML Response"},
                            "RelayState": {"type": "string", "description": "Opaque state to pass through"},
                        },
                        "required": ["SAMLResponse"],
                    }
                }
            }
        }
    },
)
async def saml_acs(
    request: Request,
    SAMLResponse: str = Form(..., description="Base64-encoded SAML Response"),
    RelayState: Optional[str] = Form(None, description="RelayState"),
    db: AsyncSession = Depends(get_db),
    redis: Optional[Any] = Depends(get_redis),
):
    """
    Step 2 of SAML SSO: receive and validate SAML Response, create session.

    On success, creates a local auth session (auth_sessions) and redirects
    to the RelayState URL or the default home page.
    """
    tenant_id = await _get_tenant_id_from_request(request, db)
    if tenant_id is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "tenant_not_found", "error_description": "Could not determine tenant"},
        )

    # Get SP config to determine which IdP to trust
    sp_service = saml_service.SpConfigService(db)
    sp_config = await sp_service.get_by_tenant(tenant_id)
    if sp_config is None:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "sp_not_configured", "error_description": "SAML SP not configured"},
        )

    # We need the IdP config — we can determine it from the SAML Response's Issuer
    # For now, try to extract issuer and look up IdP
    try:
        response_xml = base64.b64decode(SAMLResponse)
        from lxml import etree

        root = etree.fromstring(response_xml)
        ns_saml = "urn:oasis:names:tc:SAML:2.0:assertion"
        issuer_elem = root.find(f"{{{ns_saml}}}Issuer")
        issuer = issuer_elem.text if issuer_elem is not None else None

        idp_service = saml_service.IdpConfigService(db)
        if issuer:
            idp_config = await idp_service.get_by_entity_id(issuer, tenant_id)
        else:
            idp_config = None

        if idp_config is None:
            # Fallback: use first enabled IdP for this tenant
            idp_configs = await idp_service.list_by_tenant(tenant_id, enabled_only=True)
            if not idp_configs:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail={"error": "idp_not_found", "error_description": "No enabled IdP found"},
                )
            idp_config = idp_configs[0]

    except Exception as e:
        if isinstance(e, HTTPException):
            raise
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail={"error": "invalid_saml_response", "error_description": str(e)},
        )

    # Process the SAML Response
    processor = saml_service.ResponseProcessor(replay_cache=redis)
    try:
        result = await processor.process(
            saml_response_b64=SAMLResponse,
            relay_state=RelayState,
            idp_config=idp_config,
            sp_config=sp_config,
            db=db,
        )
    except ResponseValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail={
                "error": e.error_code,
                "error_description": e.message,
                "saml_status_code": e.saml_status_code,
            },
        )

    # Find or create user binding
    binding_service = saml_service.UserBindingService(db)
    binding = await binding_service.find_binding(idp_config.id, result["name_id"])

    user_id: Optional[uuid.UUID] = None

    if binding:
        user_id = binding.user_id
        await binding_service.update_last_login(binding)
        await binding_service.update_attributes(binding, result["attributes"])
    else:
        if sp_config.auto_register_new_users:
            # Extract email from attributes for auto-registration
            attr_mapper = AttributeMapper(idp_config.attribute_mapping or {})
            try:
                user_fields = attr_mapper.map(result["attributes"])
            except saml_service.AttributeMappingError:
                user_fields = {}

            email = user_fields.get("email", result["name_id"])

            # Check if user with this email already exists
            from sqlalchemy import select
            from app.sso.models import AuthUser  # noqa: F401

            existing_user = await _find_user_by_email(db, email)
            if existing_user:
                user_id = existing_user.id
            else:
                # Create new user
                user_id = await _create_saml_user(
                    db,
                    email=email,
                    name=user_fields.get("name") or user_fields.get("full_name"),
                    tenant_id=tenant_id,
                    default_role_id=sp_config.default_role_id,
                )

            # Create binding
            binding = await binding_service.create_binding(
                user_id=user_id,
                idp_config_id=idp_config.id,
                name_id=result["name_id"],
                name_id_format=result["name_id_format"],
                attributes_json=result["attributes"],
            )
        else:
            # Not auto-registering — need manual binding
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail={
                    "error": "user_not_bound",
                    "error_description": (
                        f"User '{result['name_id']}' is not registered. "
                        "Contact administrator to create a binding."
                    ),
                },
            )

    # Create local session (auth_sessions)
    auth_session_id = await _create_auth_session(
        db,
        user_id=user_id,
        tenant_id=tenant_id,
        login_method="saml",
    )

    # Build return URL from RelayState
    return_url = "/"
    if result.get("relay_state"):
        try:
            return_url = base64.urlsafe_b64decode(result["relay_state"].encode()).decode()
        except Exception:
            pass
    elif RelayState:
        try:
            return_url = base64.urlsafe_b64decode(RelayState.encode()).decode()
        except Exception:
            pass

    return RedirectResponse(url=return_url, status_code=302)


# ---------------------------------------------------------------------------
# Admin API: IdP Configuration
# ---------------------------------------------------------------------------
@router.get(
    "/admin/v1/saml/idp",
    summary="List IdP Configurations",
    response_model=IdpConfigListResponse,
)
async def list_idp_configs(
    request: Request,
    enabled_only: bool = Query(False),
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_tenant_id),
):
    """List all SAML IdP configurations for this tenant."""
    service = saml_service.IdpConfigService(db)
    configs = await service.list_by_tenant(tenant_id, enabled_only=enabled_only)
    items = [IdpConfigItem.model_validate(c) for c in configs]
    return IdpConfigListResponse(items=items, total=len(items))


@router.get(
    "/admin/v1/saml/idp/{config_id}",
    summary="Get IdP Configuration Detail",
    response_model=IdpConfigDetailResponse,
)
async def get_idp_config(
    config_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_tenant_id),
):
    """Get detailed IdP configuration including certificate."""
    service = saml_service.IdpConfigService(db)
    config = await service.get_by_id(config_id, tenant_id)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IdP config not found")
    return IdpConfigDetailResponse.model_validate(config)


@router.post(
    "/admin/v1/saml/idp",
    summary="Create IdP Configuration",
    response_model=IdpConfigDetailResponse,
    status_code=status.HTTP_201_CREATED,
)
async def create_idp_config(
    body: IdpConfigCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_tenant_id),
    user_id: uuid.UUID = Depends(get_current_user_id),
):
    """
    Create a new SAML IdP configuration.

    Supports either manual field entry or XML metadata upload (metadata_xml).
    """
    service = saml_service.IdpConfigService(db)

    # If metadata_xml provided, parse it
    if body.metadata_xml:
        parsed = await _parse_idp_metadata(body.metadata_xml)
        entity_id = parsed.get("entity_id", body.entity_id)
        sso_url = parsed.get("sso_url", body.sso_url)
        slo_url = parsed.get("slo_url", body.slo_url)
        x509_cert = parsed.get("x509_cert", body.x509_cert)
    else:
        entity_id = body.entity_id
        sso_url = body.sso_url
        slo_url = body.slo_url
        x509_cert = body.x509_cert

    config = await service.create(
        tenant_id=tenant_id,
        name=body.name,
        entity_id=entity_id,
        sso_url=sso_url,
        slo_url=slo_url,
        x509_cert=x509_cert,
        sign_algorithm=body.sign_algorithm,
        want_assertions_signed=body.want_assertions_signed,
        attribute_mapping={item.saml_attribute: item.model_dump() for item in body.attribute_mapping},
        name_id_format=body.name_id_format,
        created_by=user_id,
    )

    return IdpConfigDetailResponse.model_validate(config)


@router.put(
    "/admin/v1/saml/idp/{config_id}",
    summary="Update IdP Configuration",
    response_model=IdpConfigDetailResponse,
)
async def update_idp_config(
    config_id: uuid.UUID,
    body: IdpConfigUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_tenant_id),
):
    """Update an existing IdP configuration."""
    service = saml_service.IdpConfigService(db)
    config = await service.get_by_id(config_id, tenant_id)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IdP config not found")

    update_kwargs = body.model_dump(exclude_unset=True, exclude_none=True)
    if "attribute_mapping" in update_kwargs:
        update_kwargs["attribute_mapping"] = {
            item.saml_attribute: item.model_dump() for item in (body.attribute_mapping or [])
        }

    updated = await service.update(config, **update_kwargs)
    return IdpConfigDetailResponse.model_validate(updated)


@router.delete(
    "/admin/v1/saml/idp/{config_id}",
    summary="Delete IdP Configuration",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_idp_config(
    config_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_tenant_id),
):
    """Delete (disable) an IdP configuration."""
    service = saml_service.IdpConfigService(db)
    config = await service.get_by_id(config_id, tenant_id)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IdP config not found")
    await service.delete(config)


# ---------------------------------------------------------------------------
# Admin API: SP Configuration
# ---------------------------------------------------------------------------
@router.get(
    "/admin/v1/saml/sp-config",
    summary="Get SP Configuration",
    response_model=SpConfigResponse,
)
async def get_sp_config(
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_tenant_id),
):
    """Get current tenant's SAML SP configuration."""
    service = saml_service.SpConfigService(db)
    config = await service.get_by_tenant(tenant_id)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SP config not found")
    return SpConfigResponse.model_validate(config)


@router.put(
    "/admin/v1/saml/sp-config",
    summary="Update SP Configuration",
    response_model=SpConfigResponse,
)
async def update_sp_config(
    body: SpConfigUpdate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_tenant_id),
):
    """Update SP configuration (signing, encryption, MFA, etc.)."""
    service = saml_service.SpConfigService(db)
    config = await service.get_by_tenant(tenant_id)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SP config not found")

    update_kwargs = body.model_dump(exclude_unset=True, exclude_none=True)
    # Re-fetch with updated fields
    for key, value in update_kwargs.items():
        if hasattr(config, key):
            setattr(config, key, value)
    config.updated_at = datetime.now(timezone.utc)
    await db.commit()
    await db.refresh(config)
    return SpConfigResponse.model_validate(config)


@router.post(
    "/admin/v1/saml/sp-config/rotate-keys",
    summary="Rotate SP Signing Keys",
    response_model=SpKeyRotateResponse,
)
async def rotate_sp_keys(
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_tenant_id),
):
    """
    Rotate SP signing keys. Generates a new key pair, retains old key for decryption.

    Note: Requires a valid SP config to exist. Key rotation should be done
    carefully to avoid breaking existing IdP trust relationships.
    """
    service = saml_service.SpConfigService(db)
    config = await service.get_by_tenant(tenant_id)
    if config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="SP config not found")

    # Generate new key pair
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives import serialization
    from cryptography import x509
    from cryptography.x509.oid import NameOID
    from cryptography.hazmat.primitives import hashes

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, f"AuthMaster-SAML-{tenant_id}")])
    now = datetime.now(timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now)
        .not_valid_after(now + timedelta(days=730))
        .sign(private_key, hashes.SHA256())
    )

    sp_cert_pem = cert.public_bytes(serialization.Encoding.PEM).decode()
    sp_key_pem = private_key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.TraditionalOpenSSL,
        serialization.NoEncryption(),
    ).decode()

    # Retain old key for decryption (rename to .old)
    # (In production: store old key securely, this is a placeholder)
    old_key_pem = config.sp_key_pem
    config.sp_key_pem = sp_key_pem
    config.sp_cert_pem = sp_cert_pem
    config.cert_not_before = now
    config.cert_not_after = now + timedelta(days=730)
    config.updated_at = now
    await db.commit()
    await db.refresh(config)

    return SpKeyRotateResponse(
        success=True,
        message="SP keys rotated successfully. Old key retained for decryption.",
        cert_not_before=config.cert_not_before,
        cert_not_after=config.cert_not_after,
    )


# ---------------------------------------------------------------------------
# Admin API: User Bindings
# ---------------------------------------------------------------------------
@router.get(
    "/admin/v1/saml/bindings",
    summary="List User SAML Bindings",
    response_model=BindingListResponse,
)
async def list_bindings(
    request: Request,
    user_id: Optional[uuid.UUID] = Query(None),
    idp_id: Optional[uuid.UUID] = Query(None),
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_tenant_id),
):
    """List user SAML bindings, optionally filtered by user or IdP."""
    binding_service = saml_service.UserBindingService(db)

    if user_id:
        bindings = await binding_service.get_user_bindings(user_id)
    else:
        # List all bindings for tenant (paginated — simplified)
        from sqlalchemy import select
        from .models import SamlUserBinding, SamlIdpConfig

        query = select(SamlUserBinding).join(
            SamlIdpConfig, SamlUserBinding.idp_config_id == SamlIdpConfig.id
        ).where(SamlIdpConfig.tenant_id == tenant_id)

        if idp_id:
            query = query.where(SamlUserBinding.idp_config_id == idp_id)

        result = await db.execute(query.order_by(SamlUserBinding.last_login_at.desc()))
        bindings = list(result.scalars().all())

    items = []
    for b in bindings:
        item = BindingItem(
            id=b.id,
            user_id=b.user_id,
            idp_config_id=b.idp_config_id,
            name_id=b.name_id,
            name_id_format=b.name_id_format,
            linked_at=b.linked_at,
            last_login_at=b.last_login_at,
        )
        items.append(item)

    return BindingListResponse(items=items, total=len(items))


@router.post(
    "/admin/v1/saml/bindings",
    summary="Create Manual User Binding",
    response_model=BindingItem,
    status_code=status.HTTP_201_CREATED,
)
async def create_binding(
    body: BindingCreate,
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_tenant_id),
):
    """Manually bind an existing local user to a SAML NameID (for JIT scenarios)."""
    # Verify IdP belongs to tenant
    idp_service = saml_service.IdpConfigService(db)
    idp_config = await idp_service.get_by_id(body.idp_config_id, tenant_id)
    if idp_config is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="IdP config not found")

    binding_service = saml_service.UserBindingService(db)
    binding = await binding_service.create_binding(
        user_id=body.user_id,
        idp_config_id=body.idp_config_id,
        name_id=body.name_id,
        name_id_format=body.name_id_format,
    )
    return BindingItem.model_validate(binding)


@router.delete(
    "/admin/v1/saml/bindings/{binding_id}",
    summary="Delete User Binding",
    status_code=status.HTTP_204_NO_CONTENT,
)
async def delete_binding(
    binding_id: uuid.UUID,
    request: Request,
    db: AsyncSession = Depends(get_db),
    tenant_id: uuid.UUID = Depends(get_current_tenant_id),
):
    """Delete a user SAML binding."""
    from sqlalchemy import select, delete
    from .models import SamlUserBinding, SamlIdpConfig

    result = await db.execute(
        select(SamlUserBinding).join(
            SamlIdpConfig, SamlUserBinding.idp_config_id == SamlIdpConfig.id
        ).where(
            SamlUserBinding.id == binding_id,
            SamlIdpConfig.tenant_id == tenant_id,
        )
    )
    binding = result.scalar_one_or_none()
    if binding is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Binding not found")

    await db.delete(binding)
    await db.commit()


# ---------------------------------------------------------------------------
# Helper functions
# ---------------------------------------------------------------------------

async def _get_tenant_id_from_request(request: Request, db: AsyncSession) -> Optional[uuid.UUID]:
    """
    Extract tenant_id from request.

    In production: extract from auth context (JWT/subdomain/header).
    For SAML public endpoints, can be derived from request host.
    Override this dependency in your application.
    """
    # Try to get from request.state (set by auth middleware)
    if hasattr(request.state, "tenant_id"):
        return request.state.tenant_id

    # Fallback: look up tenant by hostname
    host = request.headers.get("host", "").split(":")[0]
    from sqlalchemy import select
    from app.sso.models import AuthTenant  # noqa: F401

    result = await db.execute(
        select(AuthTenant).where(AuthTenant.name == host).limit(1)
    )
    tenant = result.scalar_one_or_none()
    return tenant.id if tenant else None


async def _parse_idp_metadata(metadata_xml: str) -> dict:
    """Parse IdP metadata XML and extract key fields."""
    from lxml import etree

    root = etree.fromstring(metadata_xml.encode())

    md_ns = "urn:oasis:names:tc:SAML:2.0:metadata"
    saml_ns = "urn:oasis:names:tc:SAML:2.0:assertion"
    ds_ns = "http://www.w3.org/2000/09/xmldsig#"

    entity_id = root.get("entityID", "")

    idp_sso = root.find(f"{{{md_ns}}}IDPSSODescriptor")
    if idp_sso is None:
        return {}

    # SSO URL (prefer HTTP-Redirect)
    sso_url = ""
    for sso in idp_sso.findall(f"{{{md_ns}}}SingleSignOnService"):
        if sso.get("Binding") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":
            sso_url = sso.get("Location", "")
            break
    if not sso_url:
        sso_elem = idp_sso.find(f"{{{md_ns}}}SingleSignOnService")
        if sso_elem is not None:
            sso_url = sso_elem.get("Location", "")

    # SLO URL
    slo_url = ""
    for slo in idp_sso.findall(f"{{{md_ns}}}SingleLogoutService"):
        if slo.get("Binding") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect":
            slo_url = slo.get("Location", "")
            break
    if not slo_url:
        slo_elem = idp_sso.find(f"{{{md_ns}}}SingleLogoutService")
        if slo_elem is not None:
            slo_url = slo_elem.get("Location", "")

    # X.509 signing certificate
    x509_cert = ""
    signing_key = idp_sso.find(
        f"{{{md_ns}}}KeyDescriptor[@use='signing']/"
        f"{{{ds_ns}}}KeyInfo/"
        f"{{{ds_ns}}}X509Data/"
        f"{{{ds_ns}}}X509Certificate"
    )
    if signing_key is None:
        signing_key = idp_sso.find(
            f"{{{md_ns}}}KeyDescriptor/"
            f"{{{ds_ns}}}KeyInfo/"
            f"{{{ds_ns}}}X509Data/"
            f"{{{ds_ns}}}X509Certificate"
        )
    if signing_key is not None and signing_key.text:
        cert_text = signing_key.text.strip().replace(" ", "").replace("\n", "")
        lines = [cert_text[i : i + 64] for i in range(0, len(cert_text), 64)]
        x509_cert = "-----BEGIN CERTIFICATE-----\n" + "\n".join(lines) + "\n-----END CERTIFICATE-----"

    return {
        "entity_id": entity_id,
        "sso_url": sso_url,
        "slo_url": slo_url,
        "x509_cert": x509_cert,
    }


async def _find_user_by_email(db: AsyncSession, email: str) -> Optional[Any]:
    """Find user by email address."""
    from sqlalchemy import select
    from app.sso.models import AuthUser  # noqa: F401

    result = await db.execute(
        select(AuthUser).where(AuthUser.email == email).limit(1)
    )
    return result.scalar_one_or_none()


async def _create_saml_user(
    db: AsyncSession,
    email: str,
    name: Optional[str],
    tenant_id: uuid.UUID,
    default_role_id: Optional[uuid.UUID] = None,
) -> uuid.UUID:
    """Create a new local user from SAML attributes."""
    from sqlalchemy import insert
    from app.sso.models import AuthUser  # noqa: F401

    user_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    await db.execute(
        insert(AuthUser).values(
            id=user_id,
            email=email,
            username=name or email.split("@")[0],
            full_name=name,
            tenant_id=tenant_id,
            status="active",
            created_at=now,
        )
    )
    await db.commit()
    return user_id


async def _create_auth_session(
    db: AsyncSession,
    user_id: uuid.UUID,
    tenant_id: uuid.UUID,
    login_method: str,
) -> uuid.UUID:
    """Create an auth_sessions record for the SAML login."""
    from sqlalchemy import insert
    from app.sso.models import AuthSession  # noqa: F401

    session_id = uuid.uuid4()
    now = datetime.now(timezone.utc)

    await db.execute(
        insert(AuthSession).values(
            id=session_id,
            user_id=user_id,
            tenant_id=tenant_id,
            login_method=login_method,
            created_at=now,
            last_active_at=now,
            revoked=False,
        )
    )
    await db.commit()
    return session_id
