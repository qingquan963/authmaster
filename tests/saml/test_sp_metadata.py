"""
Tests for SAML SP Metadata generation.
Phase 2-4: SAML 2.0 SP 支持
"""
import pytest
from lxml import etree

from app.saml.service import SpMetadataGenerator, SpMetadataGenerator


SAML_METADATA_NS = "urn:oasis:names:tc:SAML:2.0:metadata"
DS_NS = "http://www.w3.org/2000/09/xmldsig#"


class TestSpMetadataGenerator:
    """Test SP metadata XML generation"""

    def setup_method(self):
        self.generator = SpMetadataGenerator()
        self.entity_id = "https://authmaster.example.com/saml/metadata"
        self.acs_url = "https://authmaster.example.com/saml/acs"
        self.slo_url = "https://authmaster.example.com/saml/slo"
        self.sp_cert_pem = """-----BEGIN CERTIFICATE-----
MIIBkTCB+wIJAKbO3gkpCNFaMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVt
YnJva3kxFTATBgNVBAoMDFRlc3QgT3JnYW5pemF0aW9uMB4XDTI0MDEwMTAwMDAw
MFoXDTI1MTIzMTIzNTk1OVowETEPMA0GA1UEAwwGdW1icm9reTEVMBMGA1UECgwM
VGVzdCBPcmdhbml6YXRpb24wXDANBgkqhkiG9w0BAQEFAAM=
-----END CERTIFICATE-----"""

    def test_generate_basic_metadata(self):
        """Test basic metadata XML generation with required elements"""
        xml_bytes = self.generator.generate(
            entity_id=self.entity_id,
            acs_url=self.acs_url,
            slo_url=self.slo_url,
            sp_cert_pem=self.sp_cert_pem,
        )

        # Check XML declaration is present (lxml uses single quotes)
        assert b"<?xml version=" in xml_bytes
        root = etree.fromstring(xml_bytes)
        assert root.tag == f"{{{SAML_METADATA_NS}}}EntityDescriptor"
        assert root.get("entityID") == self.entity_id

    def test_sp_sso_descriptor_present(self):
        """Test SPSSODescriptor is present with correct attributes"""
        xml_bytes = self.generator.generate(
            entity_id=self.entity_id,
            acs_url=self.acs_url,
            slo_url=self.slo_url,
            sp_cert_pem=self.sp_cert_pem,
            sign_requests=True,
            want_assertions_signed=True,
        )

        root = etree.fromstring(xml_bytes)
        sp_sso = root.find(f"{{{SAML_METADATA_NS}}}SPSSODescriptor")
        assert sp_sso is not None
        assert sp_sso.get("AuthnRequestsSigned") == "true"
        assert sp_sso.get("WantAssertionsSigned") == "true"
        assert "urn:oasis:names:tc:SAML:2.0:protocol" in sp_sso.get("protocolSupportEnumeration")

    def test_key_descriptor_signing(self):
        """Test KeyDescriptor for signing contains X.509 certificate"""
        xml_bytes = self.generator.generate(
            entity_id=self.entity_id,
            acs_url=self.acs_url,
            slo_url=self.slo_url,
            sp_cert_pem=self.sp_cert_pem,
        )

        root = etree.fromstring(xml_bytes)
        signing_kd = root.find(
            f"{{{SAML_METADATA_NS}}}SPSSODescriptor/"
            f"{{{SAML_METADATA_NS}}}KeyDescriptor[@use='signing']"
        )
        assert signing_kd is not None
        cert_elem = signing_kd.find(f"{{{DS_NS}}}KeyInfo/{{{DS_NS}}}X509Data/{{{DS_NS}}}X509Certificate")
        assert cert_elem is not None
        assert "MIIBkTCB" in cert_elem.text  # start of our test cert

    def test_assertion_consumer_service(self):
        """Test AssertionConsumerService element has correct binding and location"""
        xml_bytes = self.generator.generate(
            entity_id=self.entity_id,
            acs_url=self.acs_url,
            slo_url=self.slo_url,
            sp_cert_pem=self.sp_cert_pem,
        )

        root = etree.fromstring(xml_bytes)
        acs = root.find(
            f"{{{SAML_METADATA_NS}}}SPSSODescriptor/"
            f"{{{SAML_METADATA_NS}}}AssertionConsumerService"
        )
        assert acs is not None
        assert acs.get("Binding") == "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST"
        assert acs.get("Location") == self.acs_url
        assert acs.get("index") == "0"

    def test_single_logout_services(self):
        """Test SingleLogoutService elements for both HTTP-Redirect and HTTP-POST bindings"""
        xml_bytes = self.generator.generate(
            entity_id=self.entity_id,
            acs_url=self.acs_url,
            slo_url=self.slo_url,
            sp_cert_pem=self.sp_cert_pem,
        )

        root = etree.fromstring(xml_bytes)
        slo_services = root.findall(
            f"{{{SAML_METADATA_NS}}}SPSSODescriptor/"
            f"{{{SAML_METADATA_NS}}}SingleLogoutService"
        )
        assert len(slo_services) == 2
        bindings = {s.get("Binding") for s in slo_services}
        assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" in bindings
        assert "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" in bindings
        for slo in slo_services:
            assert slo.get("Location") == self.slo_url

    def test_name_id_formats(self):
        """Test NameIDFormat elements are present"""
        xml_bytes = self.generator.generate(
            entity_id=self.entity_id,
            acs_url=self.acs_url,
            slo_url=self.slo_url,
            sp_cert_pem=self.sp_cert_pem,
        )

        root = etree.fromstring(xml_bytes)
        formats = root.findall(
            f"{{{SAML_METADATA_NS}}}SPSSODescriptor/"
            f"{{{SAML_METADATA_NS}}}NameIDFormat"
        )
        assert len(formats) >= 1
        format_values = {f.text for f in formats}
        assert "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress" in format_values

    def test_custom_name_id_formats(self):
        """Test custom NameIDFormat values are used"""
        custom_formats = [
            "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
            "urn:oasis:names:tc:SAML:2.0:nameid-format:transient",
        ]
        xml_bytes = self.generator.generate(
            entity_id=self.entity_id,
            acs_url=self.acs_url,
            slo_url=self.slo_url,
            sp_cert_pem=self.sp_cert_pem,
            name_id_formats=custom_formats,
        )

        root = etree.fromstring(xml_bytes)
        formats = root.findall(
            f"{{{SAML_METADATA_NS}}}SPSSODescriptor/"
            f"{{{SAML_METADATA_NS}}}NameIDFormat"
        )
        format_values = {f.text for f in formats}
        assert "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" in format_values
        assert "urn:oasis:names:tc:SAML:2.0:nameid-format:transient" in format_values

    def test_no_slo_when_url_empty(self):
        """Test SingleLogoutService is not generated when slo_url is None"""
        xml_bytes = self.generator.generate(
            entity_id=self.entity_id,
            acs_url=self.acs_url,
            slo_url=None,
            sp_cert_pem=self.sp_cert_pem,
        )

        root = etree.fromstring(xml_bytes)
        slo_services = root.findall(
            f"{{{SAML_METADATA_NS}}}SPSSODescriptor/"
            f"{{{SAML_METADATA_NS}}}SingleLogoutService"
        )
        assert len(slo_services) == 0

    def test_want_assertions_signed_false(self):
        """Test WantAssertionsSigned=false is correctly set"""
        xml_bytes = self.generator.generate(
            entity_id=self.entity_id,
            acs_url=self.acs_url,
            slo_url=self.slo_url,
            sp_cert_pem=self.sp_cert_pem,
            want_assertions_signed=False,
        )

        root = etree.fromstring(xml_bytes)
        sp_sso = root.find(f"{{{SAML_METADATA_NS}}}SPSSODescriptor")
        assert sp_sso.get("WantAssertionsSigned") == "false"


class TestAuthnRequestBuilder:
    """Test SAML AuthnRequest building"""

    def setup_method(self):
        self.metadata_gen = SpMetadataGenerator()
        from app.saml.service import AuthnRequestBuilder

        self.builder = AuthnRequestBuilder(self.metadata_gen)

    def test_generate_request_id_format(self):
        """Test generated request ID starts with '_'"""
        from app.saml.service import AuthnRequestBuilder

        req_id = AuthnRequestBuilder.generate_request_id()
        assert req_id.startswith("_")
        assert len(req_id) == 33  # "_" + 32 hex chars

    def test_build_authnrequest_url(self):
        """Test AuthnRequest URL is built correctly"""
        idp_sso = "https://idp.example.com/sso"
        sp_entity_id = "https://authmaster.example.com/saml"
        acs_url = "https://authmaster.example.com/saml/acs"
        request_id = "_abc123"

        redirect_url, returned_req_id = self.builder.build(
            idp_sso_url=idp_sso,
            sp_entity_id=sp_entity_id,
            acs_url=acs_url,
            request_id=request_id,
            name_id_format="emailAddress",
        )

        assert returned_req_id == request_id
        assert redirect_url.startswith(idp_sso_url := idp_sso + "?SAMLRequest=")
        # SAMLRequest param should be present
        assert "SAMLRequest=" in redirect_url

    def test_build_includes_samlrequest_param(self):
        """Test redirect URL contains SAMLRequest parameter"""
        redirect_url, _ = self.builder.build(
            idp_sso_url="https://idp.example.com/sso",
            sp_entity_id="https://sp.example.com/saml",
            acs_url="https://sp.example.com/saml/acs",
            request_id="_test123",
        )

        import urllib.parse

        parsed = urllib.parse.urlparse(redirect_url)
        params = urllib.parse.parse_qs(parsed.query)
        assert "SAMLRequest" in params
        # Should be base64 encoded + deflated
        import base64, zlib

        decoded = base64.b64decode(params["SAMLRequest"][0])
        # Deflate stream — try decompressing
        try:
            decompressed = zlib.decompress(decoded, -zlib.MAX_WBITS)
        except Exception:
            # Might need to handle different zlib window bits
            decompressed = zlib.decompress(decoded)
        assert b"AuthnRequest" in decompressed
