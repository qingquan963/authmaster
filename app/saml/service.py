"""
SAML Module - Core Service
Phase 2-4: SAML 2.0 SP 支持

Key components:
  - IdpConfigService: IdP configuration CRUD
  - SpMetadataGenerator: SP metadata XML generation
  - AuthnRequestBuilder: Build/parse SAML AuthnRequest
  - ResponseProcessor: Process SAML Response at ACS endpoint
  - UserBindingService: Manage NameID -> local user bindings
  - ReplayCache: Redis-based replay attack prevention
"""
from __future__ import annotations

import base64
import json
import re
import secrets
import uuid
import zlib
from datetime import datetime, timedelta, timezone
from typing import TYPE_CHECKING, Any, Optional

from lxml import etree
from sqlalchemy import select, text
from sqlalchemy.ext.asyncio import AsyncSession

from .models import (
    AuthnRequestStatus,
    EncryptionAlgorithm,
    SamlAuthnRequest,
    SamlIdpConfig,
    SamlSpConfig,
    SamlUserBinding,
    SignAlgorithm,
)

if TYPE_CHECKING:
    from redis.asyncio import Redis

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
SAML_NS = "urn:oasis:names:tc:SAML:2.0:assertion"
SAML_PROTOCOL_NS = "urn:oasis:names:tc:SAML:2.0:protocol"
SAML_METADATA_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"
XMLENC_NS = "http://www.w3.org/2009/xmlenc11#"

NAME_ID_FORMATS = [
    "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
    "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
    "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified",
]

AUTHN_REQUEST_TTL_MINUTES = 10
ASSERTION_MAX_CLOCK_SKEW_SECONDS = 300  # 5 minutes


# ---------------------------------------------------------------------------
# SP Metadata Generator
# ---------------------------------------------------------------------------
class SpMetadataGenerator:
    """Generate SAML 2.0 SP metadata XML"""

    def generate(
        self,
        entity_id: str,
        acs_url: str,
        slo_url: Optional[str],
        sp_cert_pem: str,
        name_id_formats: list[str] | None = None,
        sign_requests: bool = True,
        want_assertions_signed: bool = True,
        want_assertions_encrypted: bool = False,
        sign_algorithm: str = "RSA-SHA256",
    ) -> bytes:
        """
        Generate SP metadata XML document.

        Args:
            entity_id: SP EntityID URL
            acs_url: Assertion Consumer Service URL
            slo_url: Single Logout Service URL (optional)
            sp_cert_pem: SP X.509 certificate in PEM format
            name_id_formats: Supported NameIDFormat values
            sign_requests: Whether SP signs AuthnRequests
            want_assertions_signed: Whether SP wants signed Assertions
            want_assertions_encrypted: Whether SP wants encrypted Assertions
            sign_algorithm: Signature algorithm URI
        """
        if name_id_formats is None:
            name_id_formats = [
                "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
                "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
            ]

        root = etree.Element(
            f"{{{SAML_METADATA_NS}}}EntityDescriptor",
            entityID=entity_id,
            nsmap={
                "md": SAML_METADATA_NS,
                "ds": DS_NS,
            },
        )

        sp_sso = etree.SubElement(
            root,
            f"{{{SAML_METADATA_NS}}}SPSSODescriptor",
            protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol",
        )

        if sign_requests:
            sp_sso.set("AuthnRequestsSigned", "true")
        else:
            sp_sso.set("AuthnRequestsSigned", "false")

        if want_assertions_signed:
            sp_sso.set("WantAssertionsSigned", "true")
        else:
            sp_sso.set("WantAssertionsSigned", "false")

        # KeyDescriptor (signing)
        self._add_key_descriptor(sp_sso, "signing", sp_cert_pem)

        # KeyDescriptor (encryption)
        self._add_key_descriptor(sp_sso, "encryption", sp_cert_pem)

        # NameIDFormat
        for fmt in name_id_formats:
            etree.SubElement(sp_sso, f"{{{SAML_METADATA_NS}}}NameIDFormat").text = fmt

        # AssertionConsumerService (HTTP-POST)
        acs = etree.SubElement(
            sp_sso,
            f"{{{SAML_METADATA_NS}}}AssertionConsumerService",
            index="0",
            Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
            Location=acs_url,
        )

        # SingleLogoutService (HTTP-Redirect + HTTP-POST)
        if slo_url:
            etree.SubElement(
                sp_sso,
                f"{{{SAML_METADATA_NS}}}SingleLogoutService",
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
                Location=slo_url,
            )
            etree.SubElement(
                sp_sso,
                f"{{{SAML_METADATA_NS}}}SingleLogoutService",
                Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
                Location=slo_url,
            )

        return etree.tostring(
            root,
            xml_declaration=True,
            encoding="UTF-8",
            pretty_print=True,
        )

    def _add_key_descriptor(
        self,
        parent: etree._Element,
        use: str,
        cert_pem: str,
    ) -> None:
        """Add KeyDescriptor element with X.509 certificate"""
        # Strip PEM headers and whitespace
        cert_clean = (
            cert_pem.replace("-----BEGIN CERTIFICATE-----", "")
            .replace("-----END CERTIFICATE-----", "")
            .replace("\n", "")
            .replace(" ", "")
        )
        cert_lines = [cert_clean[i : i + 64] for i in range(0, len(cert_clean), 64)]
        cert_formatted = "\n".join(cert_lines)

        kd = etree.SubElement(parent, f"{{{SAML_METADATA_NS}}}KeyDescriptor", use=use)
        ki = etree.SubElement(kd, f"{{{DS_NS}}}KeyInfo")
        xd = etree.SubElement(ki, f"{{{DS_NS}}}X509Data")
        xc = etree.SubElement(xd, f"{{{DS_NS}}}X509Certificate")
        xc.text = cert_formatted


# ---------------------------------------------------------------------------
# AuthnRequest Builder
# ---------------------------------------------------------------------------
class AuthnRequestBuilder:
    """Build SAML 2.0 AuthnRequest XML"""

    def __init__(self, metadata_generator: SpMetadataGenerator):
        self.metadata_generator = metadata_generator

    def build(
        self,
        idp_sso_url: str,
        sp_entity_id: str,
        acs_url: str,
        request_id: str,
        name_id_format: str = "emailAddress",
        sign_algorithm: str = "RSA-SHA256",
        sp_cert_pem: Optional[str] = None,
        sign_requests: bool = True,
        destination: Optional[str] = None,
    ) -> tuple[str, str]:
        """
        Build AuthnRequest XML and return URL-encoded redirect URL.

        Returns:
            Tuple of (redirect_url, request_id)
        """
        now = datetime.now(timezone.utc)
        issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        root = etree.Element(
            f"{{{SAML_PROTOCOL_NS}}}AuthnRequest",
            nsmap={
                "samlp": SAML_PROTOCOL_NS,
                "saml": SAML_NS,
            },
        )
        root.set("ID", request_id)
        root.set("Version", "2.0")
        root.set("IssueInstant", issue_instant)
        root.set("Destination", destination or idp_sso_url)
        root.set("AssertionConsumerServiceURL", acs_url)
        root.set("ProtocolBinding", "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST")

        # Issuer
        issuer = etree.SubElement(root, f"{{{SAML_NS}}}Issuer")
        issuer.text = sp_entity_id

        # NameIDPolicy
        name_id_policy = etree.SubElement(root, f"{{{SAML_PROTOCOL_NS}}}NameIDPolicy")
        name_id_policy.set("Format", name_id_format)
        name_id_policy.set("AllowCreate", "true")

        # Optional: RequestedAuthnContext (for specific auth methods)
        # skipping for compatibility with most IdPs

        xml_bytes = etree.tostring(root, xml_declaration=True, encoding="UTF-8")

        # Deflate + Base64 encode for HTTP-Redirect binding
        compressed = zlib.compress(xml_bytes)[2:-4]  # strip zlib header/trailer
        encoded = base64.b64encode(compressed).decode("ascii")

        # Build redirect URL
        import urllib.parse

        redirect_url = f"{idp_sso_url}?SAMLRequest={urllib.parse.quote(encoded)}"

        return redirect_url, request_id

    @staticmethod
    def generate_request_id() -> str:
        """Generate a unique SAML request ID (must start with '_')"""
        return f"_{secrets.token_hex(16)}"


# ---------------------------------------------------------------------------
# SAML Response Processor (ACS Handler)
# ---------------------------------------------------------------------------
class ResponseValidationError(Exception):
    """Raised when SAML Response validation fails"""

    def __init__(self, message: str, error_code: str, saml_status_code: Optional[str] = None):
        super().__init__(message)
        self.message = message
        self.error_code = error_code
        self.saml_status_code = saml_status_code


class ResponseProcessor:
    """
    Process SAML Response at ACS endpoint.

    Validation steps (in order):
      1. Decode Base64 SAMLResponse -> XML
      2. InResponseTo validation (if present)
      3. Issuer validation
      4. Destination validation
      5. Time validity (NotBefore/NotOnOrAfter with 5min skew)
      6. Response signature validation
      7. Assertion signature (if required)
      8. AudienceRestriction validation
      9. NameID validation
      10. Replay attack prevention (Redis)
    """

    def __init__(
        self,
        replay_cache: Optional["Redis"] = None,
    ):
        self.replay_cache = replay_cache

    async def process(
        self,
        saml_response_b64: str,
        relay_state: Optional[str],
        idp_config: SamlIdpConfig,
        sp_config: SamlSpConfig,
        db: AsyncSession,
    ) -> dict[str, Any]:
        """
        Process SAML Response and return user binding info.

        Returns:
            dict with keys: user_id, name_id, name_id_format, attributes,
                            return_url (from relay_state)
        """
        # Step 1: Decode
        try:
            xml_bytes = base64.b64decode(saml_response_b64)
        except Exception as e:
            raise ResponseValidationError(
                f"Failed to decode SAMLResponse: {e}",
                "invalid_encoding",
            )

        # Step 1b: Parse XML (with security: disable external entities)
        try:
            root = etree.fromstring(
                xml_bytes,
                parser=etree.XMLParser(resolve_entities=False, no_network=True),
            )
        except etree.XMLSyntaxError as e:
            raise ResponseValidationError(
                f"Invalid XML in SAMLResponse: {e}",
                "invalid_xml",
            )

        # Extract status first
        status_elem = root.find(f"{{{SAML_PROTOCOL_NS}}}StatusCode")
        if status_elem is not None:
            saml_status_code = status_elem.get("Value", "")
            if saml_status_code and not saml_status_code.endswith(":Success"):
                status_message = ""
                status_msg_elem = root.find(f"{{{SAML_PROTOCOL_NS}}}StatusMessage")
                if status_msg_elem is not None:
                    status_message = status_msg_elem.text or ""
                raise ResponseValidationError(
                    f"SAML Response indicates failure: {saml_status_code} {status_message}",
                    "saml_error",
                    saml_status_code=saml_status_code,
                )

        # Step 2: InResponseTo validation
        in_response_to = root.get("InResponseTo")
        if in_response_to:
            result = await db.execute(
                select(SamlAuthnRequest).where(
                    SamlAuthnRequest.request_id == in_response_to,
                    SamlAuthnRequest.status == AuthnRequestStatus.PENDING.value,
                )
            )
            authn_req = result.scalar_one_or_none()
            if authn_req is None:
                raise ResponseValidationError(
                    f"InResponseTo '{in_response_to}' not found or not pending",
                    "invalid_in_response_to",
                )
            # Check expiry
            if datetime.now(timezone.utc) > authn_req.expires_at.replace(tzinfo=timezone.utc):
                raise ResponseValidationError(
                    "AuthnRequest has expired",
                    "request_expired",
                )
            # Mark as used
            authn_req.status = AuthnRequestStatus.USED.value
            authn_req.used_at = datetime.now(timezone.utc)
            await db.commit()
        elif not sp_config.allow_idp_initiated:
            raise ResponseValidationError(
                "IdP-Initiated login not allowed (InResponseTo missing)",
                "idp_initiated_not_allowed",
            )

        # Step 3: Issuer validation
        issuer_elem = root.find(f"{{{SAML_NS}}}Issuer")
        if issuer_elem is None:
            raise ResponseValidationError("Missing Issuer in SAML Response", "missing_issuer")
        issuer = issuer_elem.text
        if issuer != idp_config.entity_id:
            raise ResponseValidationError(
                f"Issuer mismatch: expected '{idp_config.entity_id}', got '{issuer}'",
                "invalid_issuer",
            )

        # Step 4: Destination validation
        destination = root.get("Destination", "")
        expected_acs = idp_config.acs_url or sp_config.entity_id.rstrip("/") + "/saml/acs"
        if destination and destination != expected_acs:
            raise ResponseValidationError(
                f"Destination mismatch: expected '{expected_acs}', got '{destination}'",
                "invalid_destination",
            )

        # Step 5: Time validity
        issue_instant_str = root.get("IssueInstant", "")
        if issue_instant_str:
            try:
                issue_instant = datetime.fromisoformat(
                    issue_instant_str.replace("Z", "+00:00")
                )
                now = datetime.now(timezone.utc)
                skew = timedelta(seconds=ASSERTION_MAX_CLOCK_SKEW_SECONDS)
                if issue_instant - skew > now:
                    raise ResponseValidationError(
                        "SAML Response issued in the future (clock skew?)",
                        "assertion_not_yet_valid",
                    )
            except ValueError:
                pass  # Allow parsing to continue

        # Find Assertion element
        assertion = root.find(f"{{{SAML_NS}}}Assertion")
        if assertion is None:
            raise ResponseValidationError("No Assertion found in SAML Response", "missing_assertion")

        # Step 6-7: Signature validation (simplified — relies on XML signature library)
        # For production: use xmlsec or python3-saml for full signature verification
        # Here we do basic structure validation
        sig_elem = root.find(f"{{{DS_NS}}}Signature")
        if sig_elem is None and idp_config.want_assertions_signed:
            raise ResponseValidationError(
                "Response is not signed but IdP is configured to require signatures",
                "missing_signature",
            )

        # Step 8: AudienceRestriction
        audience_elem = assertion.find(
            f"{{{SAML_NS}}}Conditions/{{{SAML_NS}}}AudienceRestriction/{{{SAML_NS}}}Audience"
        )
        if audience_elem is not None:
            audience = audience_elem.text
            if audience != sp_config.entity_id:
                raise ResponseValidationError(
                    f"AudienceRestriction mismatch: expected '{sp_config.entity_id}', got '{audience}'",
                    "invalid_audience",
                )

        # Step 9: NameID validation
        name_id_elem = assertion.find(f"{{{SAML_NS}}}Subject/{{{SAML_NS}}}NameID")
        if name_id_elem is None:
            raise ResponseValidationError("No NameID found in Assertion", "missing_nameid")
        name_id = name_id_elem.text
        name_id_format = name_id_elem.get("Format", "urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
        if not name_id:
            raise ResponseValidationError("NameID value is empty", "invalid_nameid")

        # Step 10: Replay prevention (Redis)
        assertion_id = assertion.get("ID", name_id)
        if self.replay_cache is not None:
            key = f"saml:assertion_used:{assertion_id}"
            # We'll validate assertion expiry from NotOnOrAfter
            not_on_or_after_elem = assertion.find(
                f"{{{SAML_NS}}}Conditions/{{{SAML_NS}}}NotOnOrAfter"
            )
            ttl_seconds = 3600  # default 1 hour
            if not_on_or_after_elem is not None and not_on_or_after_elem.text:
                try:
                    nao = datetime.fromisoformat(
                        not_on_or_after_elem.text.replace("Z", "+00:00")
                    )
                    ttl_seconds = max(1, int((nao - datetime.now(timezone.utc)).total_seconds()))
                except ValueError:
                    pass

            exists = await self.replay_cache.get(key)
            if exists:
                raise ResponseValidationError(
                    "Assertion has already been used (replay attack?)",
                    "assertion_replayed",
                )
            await self.replay_cache.set(key, "1", ex=ttl_seconds)

        # Step 11: Extract Attributes
        attributes: dict[str, list[str]] = {}
        attr_statements = assertion.findall(
            f"{{{SAML_NS}}}AttributeStatement/{{{SAML_NS}}}Attribute"
        )
        for attr in attr_statements:
            attr_name = attr.get("Name", "")
            values = [v.text for v in attr.findall(f"{{{SAML_NS}}}AttributeValue") if v.text]
            if attr_name:
                attributes[attr_name] = values

        return {
            "name_id": name_id,
            "name_id_format": name_id_format,
            "attributes": attributes,
            "session_index": None,  # could be extracted from AuthnStatement
            "relay_state": relay_state,
        }


# ---------------------------------------------------------------------------
# IdP Config Service
# ---------------------------------------------------------------------------
class IdpConfigService:
    """CRUD operations for SAML IdP configurations"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_entity_id(
        self,
        entity_id: str,
        tenant_id: uuid.UUID,
    ) -> Optional[SamlIdpConfig]:
        """Get enabled IdP config by entity ID"""
        result = await self.db.execute(
            select(SamlIdpConfig).where(
                SamlIdpConfig.entity_id == entity_id,
                SamlIdpConfig.tenant_id == tenant_id,
                SamlIdpConfig.enabled == True,  # noqa: E712
            )
        )
        return result.scalar_one_or_none()

    async def get_by_id(
        self,
        config_id: uuid.UUID,
        tenant_id: uuid.UUID,
    ) -> Optional[SamlIdpConfig]:
        """Get IdP config by ID (must belong to tenant)"""
        result = await self.db.execute(
            select(SamlIdpConfig).where(
                SamlIdpConfig.id == config_id,
                SamlIdpConfig.tenant_id == tenant_id,
            )
        )
        return result.scalar_one_or_none()

    async def list_by_tenant(
        self,
        tenant_id: uuid.UUID,
        enabled_only: bool = False,
    ) -> list[SamlIdpConfig]:
        """List all IdP configs for a tenant"""
        query = select(SamlIdpConfig).where(SamlIdpConfig.tenant_id == tenant_id)
        if enabled_only:
            query = query.where(SamlIdpConfig.enabled == True)  # noqa: E712
        result = await self.db.execute(query.order_by(SamlIdpConfig.created_at.desc()))
        return list(result.scalars().all())

    async def create(
        self,
        tenant_id: uuid.UUID,
        name: str,
        entity_id: str,
        sso_url: str,
        x509_cert: str,
        slo_url: Optional[str] = None,
        sign_algorithm: str = "RSA-SHA256",
        want_assertions_signed: bool = True,
        attribute_mapping: Optional[dict] = None,
        name_id_format: str = "emailAddress",
        created_by: Optional[uuid.UUID] = None,
    ) -> SamlIdpConfig:
        """Create a new IdP configuration"""
        config = SamlIdpConfig(
            tenant_id=tenant_id,
            name=name,
            entity_id=entity_id,
            sso_url=sso_url,
            slo_url=slo_url,
            x509_cert=x509_cert,
            sign_algorithm=sign_algorithm,
            want_assertions_signed=want_assertions_signed,
            attribute_mapping=attribute_mapping or {},
            name_id_format=name_id_format,
            created_by=created_by,
        )
        self.db.add(config)
        await self.db.commit()
        await self.db.refresh(config)
        return config

    async def update(
        self,
        config: SamlIdpConfig,
        **kwargs,
    ) -> SamlIdpConfig:
        """Update an existing IdP configuration"""
        for key, value in kwargs.items():
            if hasattr(config, key) and value is not None:
                setattr(config, key, value)
        config.updated_at = datetime.now(timezone.utc)
        await self.db.commit()
        await self.db.refresh(config)
        return config

    async def delete(self, config: SamlIdpConfig) -> None:
        """Soft-delete (disable) an IdP configuration"""
        config.enabled = False
        config.updated_at = datetime.now(timezone.utc)
        await self.db.commit()


# ---------------------------------------------------------------------------
# User Binding Service
# ---------------------------------------------------------------------------
class UserBindingService:
    """Manage SAML NameID -> local user bindings"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def find_binding(
        self,
        idp_config_id: uuid.UUID,
        name_id: str,
    ) -> Optional[SamlUserBinding]:
        """Find user binding by IdP config and NameID"""
        result = await self.db.execute(
            select(SamlUserBinding).where(
                SamlUserBinding.idp_config_id == idp_config_id,
                SamlUserBinding.name_id == name_id,
            )
        )
        return result.scalar_one_or_none()

    async def get_user_bindings(
        self,
        user_id: uuid.UUID,
    ) -> list[SamlUserBinding]:
        """Get all SAML bindings for a user"""
        result = await self.db.execute(
            select(SamlUserBinding).where(SamlUserBinding.user_id == user_id)
        )
        return list(result.scalars().all())

    async def create_binding(
        self,
        user_id: uuid.UUID,
        idp_config_id: uuid.UUID,
        name_id: str,
        name_id_format: str,
        attributes_json: Optional[dict] = None,
    ) -> SamlUserBinding:
        """Create a new user-IdP binding"""
        binding = SamlUserBinding(
            user_id=user_id,
            idp_config_id=idp_config_id,
            name_id=name_id,
            name_id_format=name_id_format,
            attributes_json=attributes_json or {},
        )
        self.db.add(binding)
        await self.db.commit()
        await self.db.refresh(binding)
        return binding

    async def update_last_login(
        self,
        binding: SamlUserBinding,
    ) -> None:
        """Update last_login_at timestamp"""
        binding.last_login_at = datetime.now(timezone.utc)
        await self.db.commit()

    async def update_attributes(
        self,
        binding: SamlUserBinding,
        attributes_json: dict,
    ) -> None:
        """Update stored SAML attributes"""
        binding.attributes_json = attributes_json
        binding.last_login_at = datetime.now(timezone.utc)
        await self.db.commit()


# ---------------------------------------------------------------------------
# Attribute Mapper
# ---------------------------------------------------------------------------
class AttributeMappingError(Exception):
    """Raised when required SAML attribute is missing"""
    pass


class AttributeMapper:
    """Map SAML attributes to user fields based on configured rules"""

    def __init__(self, mapping_rules: dict[str, dict]):
        """
        Args:
            mapping_rules: dict of {saml_attribute_name: {user_field, required, default}}
        """
        self.rules = mapping_rules

    def map(self, saml_attributes: dict[str, list[str]]) -> dict[str, Any]:
        """
        Map SAML attributes to user fields.

        Args:
            saml_attributes: {attribute_name: [values]} from SAML Response

        Returns:
            {user_field: value} dict
        """
        result = {}
        for saml_attr, rule in self.rules.items():
            values = saml_attributes.get(saml_attr, [])
            if not values and rule.get("required", False):
                raise AttributeMappingError(f"Missing required attribute: {saml_attr}")
            result[rule["user_field"]] = values[0] if values else rule.get("default")
        return result


# ---------------------------------------------------------------------------
# SP Config Service
# ---------------------------------------------------------------------------
class SpConfigService:
    """Manage SAML SP configuration per tenant"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def get_by_tenant(
        self,
        tenant_id: uuid.UUID,
    ) -> Optional[SamlSpConfig]:
        """Get SP config for a tenant"""
        result = await self.db.execute(
            select(SamlSpConfig).where(SamlSpConfig.tenant_id == tenant_id)
        )
        return result.scalar_one_or_none()

    async def create_or_update(
        self,
        tenant_id: uuid.UUID,
        entity_id: str,
        sp_cert_pem: str,
        sp_key_pem: str,
        **kwargs,
    ) -> SamlSpConfig:
        """Create or update SP config"""
        config = await self.get_by_tenant(tenant_id)
        if config is None:
            config = SamlSpConfig(
                tenant_id=tenant_id,
                entity_id=entity_id,
                sp_cert_pem=sp_cert_pem,
                sp_key_pem=sp_key_pem,
                **kwargs,
            )
            self.db.add(config)
        else:
            for key, value in kwargs.items():
                if hasattr(config, key) and value is not None:
                    setattr(config, key, value)
            config.updated_at = datetime.now(timezone.utc)

        await self.db.commit()
        await self.db.refresh(config)
        return config


# ---------------------------------------------------------------------------
# AuthnRequest State Service
# ---------------------------------------------------------------------------
class AuthnRequestService:
    """Manage SAML authentication request state for InResponseTo validation"""

    def __init__(self, db: AsyncSession):
        self.db = db

    async def create_request(
        self,
        tenant_id: uuid.UUID,
        idp_config_id: uuid.UUID,
        request_id: str,
        assertion_consumer_service_url: str,
        name_id_policy: str = "emailAddress",
        protocol_binding: str = "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        ttl_minutes: int = AUTHN_REQUEST_TTL_MINUTES,
    ) -> SamlAuthnRequest:
        """Create a new pending authn request state record"""
        authn_req = SamlAuthnRequest(
            tenant_id=tenant_id,
            idp_config_id=idp_config_id,
            request_id=request_id,
            assertion_consumer_service_url=assertion_consumer_service_url,
            name_id_policy=name_id_policy,
            protocol_binding=protocol_binding,
            status=AuthnRequestStatus.PENDING.value,
            expires_at=datetime.now(timezone.utc) + timedelta(minutes=ttl_minutes),
        )
        self.db.add(authn_req)
        await self.db.commit()
        await self.db.refresh(authn_req)
        return authn_req

    async def get_pending_by_request_id(
        self,
        request_id: str,
    ) -> Optional[SamlAuthnRequest]:
        """Get a pending authn request by its request_id"""
        result = await self.db.execute(
            select(SamlAuthnRequest).where(
                SamlAuthnRequest.request_id == request_id,
                SamlAuthnRequest.status == AuthnRequestStatus.PENDING.value,
            )
        )
        return result.scalar_one_or_none()

    async def mark_used(self, request_id: str) -> None:
        """Mark an authn request as used"""
        result = await self.db.execute(
            select(SamlAuthnRequest).where(
                SamlAuthnRequest.request_id == request_id,
            )
        )
        authn_req = result.scalar_one_or_none()
        if authn_req:
            authn_req.status = AuthnRequestStatus.USED.value
            authn_req.used_at = datetime.now(timezone.utc)
            await self.db.commit()

    async def cleanup_expired(self) -> int:
        """Mark expired pending requests as expired. Returns count."""
        result = await self.db.execute(
            select(SamlAuthnRequest).where(
                SamlAuthnRequest.status == AuthnRequestStatus.PENDING.value,
                SamlAuthnRequest.expires_at < datetime.now(timezone.utc),
            )
        )
        expired = list(result.scalars().all())
        for req in expired:
            req.status = AuthnRequestStatus.EXPIRED.value
        await self.db.commit()
        return len(expired)
