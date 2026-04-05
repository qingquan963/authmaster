"""
Pytest configuration for AuthMaster tests.
"""
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio


# Use default event loop from pytest-asyncio


@pytest.fixture
def sample_tenant_id():
    return uuid.UUID("12345678-1234-5678-1234-567812345678")


@pytest.fixture
def sample_user_id():
    return uuid.UUID("87654321-4321-8765-4321-876543218765")


@pytest.fixture
def sample_idp_config():
    """Sample IdP configuration for testing."""
    return {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "name": "Test IdP",
        "entity_id": "https://test-idp.example.com",
        "sso_url": "https://test-idp.example.com/sso",
        "slo_url": "https://test-idp.example.com/slo",
        "x509_cert": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKbO3gkpCNFaMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVt\nYnJva3kxFTATBgNVBAoMDFRlc3QgT3JnYW5pemF0aW9uMB4XDTI0MDEwMTAwMDAw\nMFoXDTI1MTIzMTIzNTk1OVowETEPMA0GA1UEAwwGdW1icm9reTEVMBMGA1UECgwM\nVGVzdCBPcmdhbml6YXRpb24wXDANBgkqhkiG9w0BAQEFAAM=\n-----END CERTIFICATE-----",
        "sign_algorithm": "RSA-SHA256",
        "want_assertions_signed": True,
        "enabled": True,
        "attribute_mapping": {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {
                "user_field": "email",
                "required": True,
            }
        },
        "name_id_format": "emailAddress",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }


@pytest.fixture
def sample_sp_config():
    """Sample SP configuration for testing."""
    return {
        "id": uuid.uuid4(),
        "tenant_id": uuid.uuid4(),
        "entity_id": "https://authmaster.example.com/saml",
        "sp_cert_pem": "-----BEGIN CERTIFICATE-----\nMIIBkTCB+wIJAKbO3gkpCNFaMA0GCSqGSIb3DQEBCwUAMBExDzANBgNVBAMMBnVt\nYnJva3kxFTATBgNVBAoMDFRlc3QgT3JnYW5pemF0aW9uMB4XDTI0MDEwMTAwMDAw\nMFoXDTI1MTIzMTIzNTk1OVowETEPMA0GA1UEAwwGdW1icm9reTEVMBMGA1UECgwM\nVGVzdCBPcmdhbml6YXRpb24wXDANBgkqhkiG9w0BAQEFAAM=\n-----END CERTIFICATE-----",
        "sp_key_pem": "-----BEGIN RSA PRIVATE KEY-----\nMIIBQgBJJkgBAj5D3H1UJHg2q8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8\nq6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6\ns8q6s8q6s8q6s8q6s8q6s8q6s8q6s8q6s=\n-----END RSA PRIVATE KEY-----",
        "auto_register_new_users": True,
        "allow_idp_initiated": False,
        "require_mfa_for_saml": False,
        "preferred_name_id_format": "emailAddress",
        "want_assertions_encrypted": False,
        "sign_requests": True,
        "sign_algorithm": "RSA-SHA256",
        "encryption_algorithm": "AES-256-CBC",
        "created_at": datetime.now(timezone.utc),
        "updated_at": datetime.now(timezone.utc),
    }
