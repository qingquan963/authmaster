"""
SAML Module - SQLAlchemy Async Models
Phase 2-4: SAML 2.0 SP 支持
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import (
    Boolean, CheckConstraint, Column, DateTime, Enum as SAEnum,
    ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


class AuthnRequestStatus(str, Enum):
    PENDING = "pending"
    USED = "used"
    EXPIRED = "expired"
    CANCELLED = "cancelled"


class SignAlgorithm(str, Enum):
    RSA_SHA256 = "RSA-SHA256"
    RSA_SHA512 = "RSA-SHA512"


class EncryptionAlgorithm(str, Enum):
    AES_256_CBC = "AES-256-CBC"
    AES_128_CBC = "AES-128-CBC"


# ---------------------------------------------------------------------------
# SAML IdP Configuration
# ---------------------------------------------------------------------------
class SamlIdpConfig(Base):
    __tablename__ = "saml_idp_config"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("auth_tenants.id", ondelete="CASCADE"), nullable=False)
    name = Column(String(255), nullable=False)
    entity_id = Column(String(1024), nullable=False)
    sso_url = Column(String(1024), nullable=False)
    slo_url = Column(String(1024))
    x509_cert = Column(Text, nullable=False)
    sign_algorithm = Column(String(20), nullable=False, default=SignAlgorithm.RSA_SHA256.value)
    want_assertions_signed = Column(Boolean, nullable=False, default=True)
    enabled = Column(Boolean, nullable=False, default=True)

    # Attribute mapping (JSONB)
    attribute_mapping = Column(JSONB, nullable=False, default=dict)

    # Advanced config
    name_id_format = Column(String(100), default="emailAddress")
    acs_url = Column(String(1024))
    metadata_xml = Column(Text)
    metadata_url = Column(String(1024))

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    created_by = Column(UUID(as_uuid=True), ForeignKey("auth_users.id"))

    user_bindings = relationship("SamlUserBinding", back_populates="idp_config", cascade="all, delete-orphan")
    authn_requests = relationship("SamlAuthnRequest", back_populates="idp_config", cascade="all, delete-orphan")

    __table_args__ = (
        UniqueConstraint("tenant_id", "entity_id", name="uq_tenant_idp_entity_id"),
        Index("ix_saml_idp_config_tenant", "tenant_id", "enabled"),
        Index("ix_saml_idp_config_entity_id", "entity_id"),
        CheckConstraint("sign_algorithm IN ('RSA-SHA256', 'RSA-SHA512')", name="ck_idp_sign_algorithm"),
    )


# ---------------------------------------------------------------------------
# SAML SP Configuration (per tenant)
# ---------------------------------------------------------------------------
class SamlSpConfig(Base):
    __tablename__ = "saml_sp_config"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("auth_tenants.id", ondelete="CASCADE"), unique=True, nullable=False)

    entity_id = Column(String(1024), nullable=False)

    # SP certificate/key pair
    sp_cert_pem = Column(Text, nullable=False)
    sp_key_pem = Column(Text, nullable=False)
    cert_not_before = Column(DateTime(timezone=True))
    cert_not_after = Column(DateTime(timezone=True))

    # Assertion encryption (optional)
    want_assertions_encrypted = Column(Boolean, nullable=False, default=False)
    encryption_algorithm = Column(String(30), nullable=False, default=EncryptionAlgorithm.AES_256_CBC.value)

    # SSO behavior
    auto_register_new_users = Column(Boolean, nullable=False, default=True)
    default_role_id = Column(UUID(as_uuid=True), ForeignKey("auth_roles.id"))

    # IdP-initiated login
    allow_idp_initiated = Column(Boolean, nullable=False, default=False)

    # Signing
    sign_requests = Column(Boolean, nullable=False, default=True)
    sign_algorithm = Column(String(20), nullable=False, default=SignAlgorithm.RSA_SHA256.value)

    # MFA requirement
    require_mfa_for_saml = Column(Boolean, nullable=False, default=False)

    # NameID format preference
    preferred_name_id_format = Column(String(100), default="emailAddress")

    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    updated_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    __table_args__ = (
        CheckConstraint("sign_algorithm IN ('RSA-SHA256', 'RSA-SHA512')", name="ck_sp_sign_algorithm"),
        CheckConstraint("encryption_algorithm IN ('AES-256-CBC', 'AES-128-CBC')", name="ck_sp_encryption_algorithm"),
    )


# ---------------------------------------------------------------------------
# SAML Authentication Request State
# ---------------------------------------------------------------------------
class SamlAuthnRequest(Base):
    __tablename__ = "saml_authn_requests"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    tenant_id = Column(UUID(as_uuid=True), ForeignKey("auth_tenants.id", ondelete="CASCADE"), nullable=False)
    idp_config_id = Column(UUID(as_uuid=True), ForeignKey("saml_idp_config.id", ondelete="CASCADE"), nullable=False)

    # SAML AuthnRequest ID (_xxx) and expected InResponseTo
    request_id = Column(String(256), nullable=False)
    in_response_to = Column(String(256))

    # Snapshot of request params
    name_id_policy = Column(String(100))
    assertion_consumer_service_url = Column(String(1024))
    protocol_binding = Column(String(100))

    # Status
    status = Column(String(20), nullable=False, default=AuthnRequestStatus.PENDING.value)
    created_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    used_at = Column(DateTime(timezone=True))

    idp_config = relationship("SamlIdpConfig", back_populates="authn_requests")

    __table_args__ = (
        UniqueConstraint("request_id", name="uq_saml_request_id"),
        Index("ix_authn_requests_expiry", "expires_at", postgresql_where=(Column("status") == AuthnRequestStatus.PENDING.value)),
        Index("ix_authn_requests_in_response", "in_response_to", postgresql_where=(Column("status") == AuthnRequestStatus.PENDING.value)),
        Index("ix_authn_requests_idp", "idp_config_id", "status"),
    )


# ---------------------------------------------------------------------------
# SAML User Bindings (NameID -> local user mapping)
# ---------------------------------------------------------------------------
class SamlUserBinding(Base):
    __tablename__ = "saml_user_bindings"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("auth_users.id", ondelete="CASCADE"), nullable=False)
    idp_config_id = Column(UUID(as_uuid=True), ForeignKey("saml_idp_config.id", ondelete="CASCADE"), nullable=False)
    name_id = Column(String(1024), nullable=False)
    name_id_format = Column(String(100), nullable=False)
    attributes_json = Column(JSONB, nullable=False, default=dict)
    linked_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))
    last_login_at = Column(DateTime(timezone=True), nullable=False, default=lambda: datetime.now(timezone.utc))

    idp_config = relationship("SamlIdpConfig", back_populates="user_bindings")

    __table_args__ = (
        UniqueConstraint("user_id", "idp_config_id", "name_id", name="uq_user_idp_nameid"),
        Index("ix_saml_bindings_user", "user_id"),
        Index("ix_saml_bindings_idp_nameid", "idp_config_id", "name_id"),
        Index("ix_saml_bindings_user_idp", "user_id", "idp_config_id"),
    )
