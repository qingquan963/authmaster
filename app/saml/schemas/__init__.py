"""
SAML Module - Pydantic Schemas
Phase 2-4: SAML 2.0 SP 支持
"""
from __future__ import annotations

import uuid
from datetime import datetime
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field


# ---------------------------------------------------------------------------
# SP Metadata
# ---------------------------------------------------------------------------
class SpMetadataResponse(BaseModel):
    """SP metadata XML response"""
    entity_id: str
    metadata_xml: str = Field(..., description="SAML 2.0 SP metadata XML")


# ---------------------------------------------------------------------------
# SAML Login Initiation
# ---------------------------------------------------------------------------
class SamlLoginRequest(BaseModel):
    """Query params for GET /saml/login"""
    model_config = ConfigDict(strict=True)

    idp: str = Field(..., description="IdP EntityID", min_length=1, max_length=1024)
    return_url: Optional[str] = Field(None, max_length=2048, description="Login success redirect URL (base64)")
    name_id_format: Optional[str] = Field(None, max_length=100, description="Override default NameID format")


class SamlLoginResponse(BaseModel):
    """SAML login initiation response"""
    redirect_url: str = Field(..., description="Redirect URL to IdP SSO endpoint")
    request_id: str = Field(..., description="SAML AuthnRequest ID (_xxx)")
    relay_state: Optional[str] = Field(None, description="RelayState to preserve across redirect")


# ---------------------------------------------------------------------------
# ACS (Assertion Consumer Service)
# ---------------------------------------------------------------------------
class AcsFormRequest(BaseModel):
    """POST /saml/acs form data"""
    model_config = ConfigDict(strict=True)

    saml_response: str = Field(..., alias="SAMLResponse", description="Base64-encoded SAML Response")
    relay_state: Optional[str] = Field(None, alias="RelayState")


class AcsResponse(BaseModel):
    """ACS processing result"""
    success: bool
    user_id: Optional[uuid.UUID] = None
    return_url: str = Field(default="/", description="Redirect URL after processing")
    error: Optional[str] = Field(None, description="Error message if failed")
    error_code: Optional[str] = Field(None, description="Error code for debugging")


# ---------------------------------------------------------------------------
# IdP Configuration (Admin API)
# ---------------------------------------------------------------------------
class AttributeMappingItem(BaseModel):
    """Single attribute mapping rule"""
    saml_attribute: str
    user_field: str
    required: bool = False
    default: Optional[str] = None


class IdpConfigCreate(BaseModel):
    """POST /admin/v1/saml/idp — create IdP config"""
    model_config = ConfigDict(strict=True)

    name: str = Field(..., min_length=1, max_length=255)
    entity_id: str = Field(..., min_length=1, max_length=1024)
    sso_url: str = Field(..., min_length=1, max_length=1024)
    slo_url: Optional[str] = Field(None, max_length=1024)
    x509_cert: str = Field(..., min_length=1)
    sign_algorithm: str = Field(default="RSA-SHA256")
    want_assertions_signed: bool = Field(default=True)
    attribute_mapping: list[AttributeMappingItem] = Field(default_factory=list)
    name_id_format: str = Field(default="emailAddress")
    acs_url: Optional[str] = Field(None, max_length=1024)
    metadata_xml: Optional[str] = Field(None)
    metadata_url: Optional[str] = Field(None, max_length=1024)


class IdpConfigUpdate(BaseModel):
    """PUT /admin/v1/saml/idp/{id} — update IdP config"""
    model_config = ConfigDict(strict=True)

    name: Optional[str] = Field(None, min_length=1, max_length=255)
    entity_id: Optional[str] = Field(None, min_length=1, max_length=1024)
    sso_url: Optional[str] = Field(None, min_length=1, max_length=1024)
    slo_url: Optional[str] = Field(None, max_length=1024)
    x509_cert: Optional[str] = Field(None, min_length=1)
    sign_algorithm: Optional[str] = Field(None)
    want_assertions_signed: Optional[bool] = None
    enabled: Optional[bool] = None
    attribute_mapping: Optional[list[AttributeMappingItem]] = None
    name_id_format: Optional[str] = None


class IdpConfigItem(BaseModel):
    """Single IdP config in list response"""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    name: str
    entity_id: str
    sso_url: str
    slo_url: Optional[str] = None
    enabled: bool
    want_assertions_signed: bool
    sign_algorithm: str
    created_at: datetime

    # Exclude sensitive fields
    x509_cert: Optional[str] = Field(None, exclude=True)
    metadata_xml: Optional[str] = Field(None, exclude=True)


class IdpConfigListResponse(BaseModel):
    """GET /admin/v1/saml/idp response"""
    items: list[IdpConfigItem]
    total: int


class IdpConfigDetailResponse(IdpConfigItem):
    """GET /admin/v1/saml/idp/{id} — includes sensitive fields"""
    model_config = ConfigDict(from_attributes=True)

    x509_cert: Optional[str] = None
    attribute_mapping: Any = Field(default_factory=dict)
    metadata_xml: Optional[str] = None
    metadata_url: Optional[str] = None
    updated_at: datetime
    created_by: Optional[uuid.UUID] = None


# ---------------------------------------------------------------------------
# SP Configuration (Admin API)
# ---------------------------------------------------------------------------
class SpConfigUpdate(BaseModel):
    """PUT /admin/v1/saml/sp-config"""
    model_config = ConfigDict(strict=True)

    auto_register_new_users: Optional[bool] = None
    allow_idp_initiated: Optional[bool] = None
    require_mfa_for_saml: Optional[bool] = None
    preferred_name_id_format: Optional[str] = None
    want_assertions_encrypted: Optional[bool] = None
    sign_requests: Optional[bool] = None


class SpConfigResponse(BaseModel):
    """GET /admin/v1/saml/sp-config response"""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    tenant_id: uuid.UUID
    entity_id: str
    auto_register_new_users: bool
    allow_idp_initiated: bool
    require_mfa_for_saml: bool
    preferred_name_id_format: str
    want_assertions_encrypted: bool
    sign_requests: bool
    sign_algorithm: str
    encryption_algorithm: str
    cert_not_before: Optional[datetime] = None
    cert_not_after: Optional[datetime] = None
    created_at: datetime
    updated_at: datetime


class SpKeyRotateResponse(BaseModel):
    """POST /admin/v1/saml/sp-config/rotate-keys response"""
    success: bool
    message: str
    cert_not_before: datetime
    cert_not_after: datetime


# ---------------------------------------------------------------------------
# User Bindings (Admin API)
# ---------------------------------------------------------------------------
class BindingCreate(BaseModel):
    """POST /admin/v1/saml/bindings"""
    model_config = ConfigDict(strict=True)

    user_id: uuid.UUID
    idp_config_id: uuid.UUID
    name_id: str = Field(..., min_length=1, max_length=1024)
    name_id_format: str = Field(default="emailAddress")


class BindingItem(BaseModel):
    """Single binding in list"""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    user_id: uuid.UUID
    idp_config_id: uuid.UUID
    name_id: str
    name_id_format: str
    linked_at: datetime
    last_login_at: datetime
    idp_name: Optional[str] = Field(None, description="IdP display name")


class BindingListResponse(BaseModel):
    """GET /admin/v1/saml/bindings response"""
    items: list[BindingItem]
    total: int


# ---------------------------------------------------------------------------
# SAML AuthnRequest Status (Internal)
# ---------------------------------------------------------------------------
class AuthnRequestStatusResponse(BaseModel):
    """GET /admin/v1/saml/authn-requests/{id}"""
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    request_id: str
    in_response_to: Optional[str] = None
    status: str
    created_at: datetime
    expires_at: datetime
    used_at: Optional[datetime] = None
    idp_config_id: uuid.UUID
    assertion_consumer_service_url: Optional[str] = None


# ---------------------------------------------------------------------------
# Error Response
# ---------------------------------------------------------------------------
class SamlErrorResponse(BaseModel):
    """Standard SAML error response"""
    error: str = Field(..., description="Error code")
    error_description: str = Field(..., description="Human-readable description")
    saml_status_code: Optional[str] = Field(None, description="SAML-specific status code")
    request_id: Optional[str] = Field(None, description="Associated AuthnRequest ID")
