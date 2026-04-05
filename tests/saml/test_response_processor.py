"""
Tests for SAML Response Processor (ACS handler).
Phase 2-4: SAML 2.0 SP 支持
"""
import base64
import uuid
from datetime import datetime, timedelta, timezone
from unittest.mock import AsyncMock, MagicMock

import pytest
from lxml import etree

from app.saml.service import ResponseProcessor, ResponseValidationError


def build_saml_response(
    issuer: str,
    name_id: str,
    name_id_format: str = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    destination: str = "https://sp.example.com/saml/acs",
    assertion_id: str = None,
    not_before: datetime = None,
    not_on_or_after: datetime = None,
    in_response_to: str = None,
    audience: str = "https://sp.example.com/saml",
    sign: bool = False,
    attributes: dict = None,
) -> str:
    """
    Build a minimal SAML Response XML for testing.

    This creates a structurally valid Response for unit testing without
    actual cryptographic signatures.
    """
    now = datetime.now(timezone.utc)
    issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")

    if assertion_id is None:
        assertion_id = f"_{uuid.uuid4().hex[:16]}"

    if not_before is None:
        not_before = now - timedelta(minutes=5)
    if not_on_or_after is None:
        not_on_or_after = now + timedelta(hours=1)

    in_response_to_attr = f' InResponseTo="{in_response_to}"' if in_response_to else ""

    root = etree.Element(
        "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
        nsmap={
            "samlp": "urn:oasis:names:tc:SAML:2.0:protocol",
            "saml": "urn:oasis:names:tc:SAML:2.0:assertion",
        },
    )
    root.set("ID", f"_{uuid.uuid4().hex[:16]}")
    root.set("InResponseTo", in_response_to or "")
    root.set("Version", "2.0")
    root.set("IssueInstant", issue_instant)
    root.set("Destination", destination)

    # Issuer
    issuer_elem = etree.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
    issuer_elem.text = issuer

    # Status
    status = etree.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")
    status.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

    # Assertion
    assertion = etree.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
    assertion.set("ID", assertion_id)
    assertion.set("Version", "2.0")
    assertion.set("IssueInstant", issue_instant)

    # Assertion Subject
    subject = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Subject")
    name_id_elem = etree.SubElement(subject, "{urn:oasis:names:tc:SAML:2.0:assertion}NameID")
    name_id_elem.set("Format", name_id_format)
    name_id_elem.text = name_id

    # Assertion Conditions
    conditions = etree.SubElement(assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}Conditions")
    conditions.set("NotBefore", not_before.strftime("%Y-%m-%dT%H:%M:%SZ"))
    conditions.set("NotOnOrAfter", not_on_or_after.strftime("%Y-%m-%dT%H:%M:%SZ"))

    audience_restriction = etree.SubElement(
        conditions, "{urn:oasis:names:tc:SAML:2.0:assertion}AudienceRestriction"
    )
    audience_elem = etree.SubElement(
        audience_restriction, "{urn:oasis:names:tc:SAML:2.0:assertion}Audience"
    )
    audience_elem.text = audience

    # AttributeStatement
    if attributes:
        attr_statement = etree.SubElement(
            assertion, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeStatement"
        )
        for attr_name, values in attributes.items():
            attr = etree.SubElement(
                attr_statement, "{urn:oasis:names:tc:SAML:2.0:assertion}Attribute"
            )
            attr.set("Name", attr_name)
            for val in values:
                av = etree.SubElement(
                    attr, "{urn:oasis:names:tc:SAML:2.0:assertion}AttributeValue"
                )
                av.text = val

    xml_bytes = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
    return base64.b64encode(xml_bytes).decode("ascii")


class MockSamlIdpConfig:
    """Mock IdP config for testing"""

    def __init__(
        self,
        entity_id: str = "https://idp.example.com",
        sso_url: str = "https://idp.example.com/sso",
        x509_cert: str = "dummy_cert",
        want_assertions_signed: bool = True,
        attribute_mapping: dict = None,
        allow_idp_initiated: bool = False,
    ):
        self.id = uuid.uuid4()
        self.tenant_id = uuid.uuid4()
        self.entity_id = entity_id
        self.sso_url = sso_url
        self.x509_cert = x509_cert
        self.want_assertions_signed = want_assertions_signed
        self.attribute_mapping = attribute_mapping or {}
        self.allow_idp_initiated = allow_idp_initiated
        self.acs_url = None  # Not used in tests with InResponseTo, but required by service


class MockSamlSpConfig:
    """Mock SP config for testing"""

    def __init__(
        self,
        entity_id: str = "https://sp.example.com",
        allow_idp_initiated: bool = False,
        want_assertions_encrypted: bool = False,
    ):
        self.id = uuid.uuid4()
        self.tenant_id = uuid.uuid4()
        self.entity_id = entity_id
        self.allow_idp_initiated = allow_idp_initiated
        self.want_assertions_encrypted = want_assertions_encrypted


class MockAsyncSession:
    """Minimal async mock for DB session"""

    def __init__(self, pending_request_id: str = None):
        self.committed = False
        self._pending_request_id = pending_request_id

    async def commit(self):
        self.committed = True

    async def execute(self, query):
        """Mock execute that returns a result with scalar_one_or_none for authn request lookups."""
        return MockExecuteResult(request_id=self._pending_request_id)


class MockExecuteResult:
    """Mock result from db.execute()"""

    def __init__(self, request_id: str = None):
        self._request_id = request_id

    def scalar_one_or_none(self):
        """Return a mock authn request for InResponseTo validation"""
        if self._request_id:
            mock_req = MagicMock()
            mock_req.request_id = self._request_id
            mock_req.expires_at = datetime.now(timezone.utc) + timedelta(hours=1)
            mock_req.status = "pending"
            return mock_req
        return None


class TestResponseProcessor:
    """Test SAML Response processing and validation"""

    def setup_method(self):
        self.processor = ResponseProcessor(replay_cache=None)

    def _make_mock_db(self, pending_request_id: str = None):
        return MockAsyncSession(pending_request_id=pending_request_id)

    @pytest.mark.asyncio
    async def test_process_valid_response(self):
        """Test processing a structurally valid SAML Response"""
        # Disable signature requirement for test (test responses are not signed)
        idp_config = MockSamlIdpConfig(want_assertions_signed=False)
        sp_config = MockSamlSpConfig()
        request_id = "_test_request_123"

        saml_response = build_saml_response(
            issuer=idp_config.entity_id,
            name_id="user@example.com",
            audience=sp_config.entity_id,
            in_response_to=request_id,
        )

        result = await self.processor.process(
            saml_response_b64=saml_response,
            relay_state=None,
            idp_config=idp_config,
            sp_config=sp_config,
            db=self._make_mock_db(pending_request_id=request_id),
        )

        assert result["name_id"] == "user@example.com"
        assert result["name_id_format"] == "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
        assert result["attributes"] == {}

    @pytest.mark.asyncio
    async def test_process_extracts_attributes(self):
        """Test that SAML attributes are extracted from Response"""
        idp_config = MockSamlIdpConfig(want_assertions_signed=False)
        sp_config = MockSamlSpConfig()
        request_id = "_test_request_456"

        saml_response = build_saml_response(
            issuer=idp_config.entity_id,
            name_id="john.doe@example.com",
            audience=sp_config.entity_id,
            in_response_to=request_id,
            attributes={
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": [
                    "john.doe@example.com"
                ],
                "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": ["John"],
                "department": ["Engineering"],
            },
        )

        result = await self.processor.process(
            saml_response_b64=saml_response,
            relay_state=None,
            idp_config=idp_config,
            sp_config=sp_config,
            db=self._make_mock_db(pending_request_id=request_id),
        )

        assert result["name_id"] == "john.doe@example.com"
        assert "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress" in result["attributes"]
        assert result["attributes"]["http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"] == [
            "john.doe@example.com"
        ]

    @pytest.mark.asyncio
    async def test_invalid_base64_raises_error(self):
        """Test that invalid base64 encoding raises ResponseValidationError"""
        processor = ResponseProcessor(replay_cache=None)
        idp_config = MockSamlIdpConfig()
        sp_config = MockSamlSpConfig()

        with pytest.raises(ResponseValidationError) as exc_info:
            await processor.process(
                saml_response_b64="not_valid_base64!!!",
                relay_state=None,
                idp_config=idp_config,
                sp_config=sp_config,
                db=self._make_mock_db(),
            )
        assert exc_info.value.error_code == "invalid_encoding"

    @pytest.mark.asyncio
    async def test_invalid_xml_raises_error(self):
        """Test that non-XML content raises ResponseValidationError"""
        processor = ResponseProcessor(replay_cache=None)
        idp_config = MockSamlIdpConfig()
        sp_config = MockSamlSpConfig()

        # Valid base64 but not XML
        invalid_xml_b64 = base64.b64encode(b"<not-valid-xml").decode()

        with pytest.raises(ResponseValidationError) as exc_info:
            await processor.process(
                saml_response_b64=invalid_xml_b64,
                relay_state=None,
                idp_config=idp_config,
                sp_config=sp_config,
                db=self._make_mock_db(),
            )
        assert exc_info.value.error_code == "invalid_xml"

    @pytest.mark.asyncio
    async def test_issuer_mismatch_raises_error(self):
        """Test that mismatched issuer raises ResponseValidationError"""
        processor = ResponseProcessor(replay_cache=None)
        idp_config = MockSamlIdpConfig(entity_id="https://expected-idp.example.com")
        sp_config = MockSamlSpConfig()
        request_id = "_test_request_789"

        # Response with wrong issuer
        saml_response = build_saml_response(
            issuer="https://wrong-idp.example.com",  # Wrong issuer
            name_id="user@example.com",
            audience=sp_config.entity_id,
            in_response_to=request_id,
        )

        with pytest.raises(ResponseValidationError) as exc_info:
            await processor.process(
                saml_response_b64=saml_response,
                relay_state=None,
                idp_config=idp_config,
                sp_config=sp_config,
                db=self._make_mock_db(pending_request_id=request_id),
            )
        assert exc_info.value.error_code == "invalid_issuer"
        assert "wrong-idp.example.com" in exc_info.value.message

    @pytest.mark.asyncio
    async def test_audience_mismatch_raises_error(self):
        """Test that mismatched audience restriction raises error"""
        processor = ResponseProcessor(replay_cache=None)
        idp_config = MockSamlIdpConfig(want_assertions_signed=False)
        sp_config = MockSamlSpConfig()  # entity_id="https://sp.example.com"
        request_id = "_test_request_abc"

        saml_response = build_saml_response(
            issuer=idp_config.entity_id,
            name_id="user@example.com",
            audience="https://wrong-sp.example.com",  # Wrong audience
            in_response_to=request_id,
        )

        with pytest.raises(ResponseValidationError) as exc_info:
            await processor.process(
                saml_response_b64=saml_response,
                relay_state=None,
                idp_config=idp_config,
                sp_config=sp_config,
                db=self._make_mock_db(pending_request_id=request_id),
            )
        assert exc_info.value.error_code == "invalid_audience"

    @pytest.mark.asyncio
    async def test_missing_nameid_raises_error(self):
        """Test that missing NameID raises ResponseValidationError"""
        processor = ResponseProcessor(replay_cache=None)
        idp_config = MockSamlIdpConfig(want_assertions_signed=False)
        sp_config = MockSamlSpConfig()
        request_id = "_test_request_def"

        # Build response without NameID
        from lxml import etree
        import base64

        now = datetime.now(timezone.utc)
        issue_instant = now.strftime("%Y-%m-%dT%H:%M:%SZ")

        root = etree.Element(
            "{urn:oasis:names:tc:SAML:2.0:protocol}Response",
        )
        root.set("ID", f"_{uuid.uuid4().hex[:16]}")
        root.set("InResponseTo", request_id)
        root.set("Version", "2.0")
        root.set("IssueInstant", issue_instant)
        root.set("Destination", "https://sp.example.com/saml/acs")

        issuer_elem = etree.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:assertion}Issuer")
        issuer_elem.text = idp_config.entity_id

        status = etree.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:protocol}StatusCode")
        status.set("Value", "urn:oasis:names:tc:SAML:2.0:status:Success")

        # Assertion without NameID
        assertion = etree.SubElement(root, "{urn:oasis:names:tc:SAML:2.0:assertion}Assertion")
        assertion.set("ID", f"_{uuid.uuid4().hex[:16]}")
        assertion.set("Version", "2.0")
        assertion.set("IssueInstant", issue_instant)

        xml_bytes = etree.tostring(root, xml_declaration=True, encoding="UTF-8")
        saml_response = base64.b64encode(xml_bytes).decode()

        with pytest.raises(ResponseValidationError) as exc_info:
            await processor.process(
                saml_response_b64=saml_response,
                relay_state=None,
                idp_config=idp_config,
                sp_config=sp_config,
                db=self._make_mock_db(pending_request_id=request_id),
            )
        assert exc_info.value.error_code == "missing_nameid"

    @pytest.mark.asyncio
    async def test_relay_state_passed_through(self):
        """Test that RelayState is passed through in result"""
        processor = ResponseProcessor(replay_cache=None)
        idp_config = MockSamlIdpConfig(want_assertions_signed=False)
        sp_config = MockSamlSpConfig()
        request_id = "_test_request_ghi"

        saml_response = build_saml_response(
            issuer=idp_config.entity_id,
            name_id="user@example.com",
            audience=sp_config.entity_id,
            in_response_to=request_id,
        )

        result = await processor.process(
            saml_response_b64=saml_response,
            relay_state="https://app.example.com/dashboard",
            idp_config=idp_config,
            sp_config=sp_config,
            db=self._make_mock_db(pending_request_id=request_id),
        )

        assert result["relay_state"] == "https://app.example.com/dashboard"

    @pytest.mark.asyncio
    async def test_name_id_format_preserved(self):
        """Test that NameID Format is preserved from Response"""
        processor = ResponseProcessor(replay_cache=None)
        idp_config = MockSamlIdpConfig(want_assertions_signed=False)
        sp_config = MockSamlSpConfig()
        request_id = "_test_request_jkl"

        saml_response = build_saml_response(
            issuer=idp_config.entity_id,
            name_id="persistent_id_12345",
            name_id_format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            audience=sp_config.entity_id,
            in_response_to=request_id,
        )

        result = await processor.process(
            saml_response_b64=saml_response,
            relay_state=None,
            idp_config=idp_config,
            sp_config=sp_config,
            db=self._make_mock_db(pending_request_id=request_id),
        )

        assert result["name_id_format"] == "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
        assert result["name_id"] == "persistent_id_12345"
