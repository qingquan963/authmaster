"""
Tests for SAML Attribute Mapper.
Phase 2-4: SAML 2.0 SP 支持
"""
import pytest

from app.saml.service import AttributeMapper, AttributeMappingError


class TestAttributeMapper:
    """Test SAML attribute to user field mapping"""

    def test_map_basic_attributes(self):
        """Test basic attribute mapping"""
        rules = {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {
                "user_field": "email",
                "required": True,
            },
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": {
                "user_field": "name",
                "required": False,
                "default": "Unknown",
            },
        }
        mapper = AttributeMapper(rules)

        saml_attrs = {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": ["user@example.com"],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": ["John"],
        }

        result = mapper.map(saml_attrs)
        assert result["email"] == "user@example.com"
        assert result["name"] == "John"

    def test_map_missing_required_attribute(self):
        """Test AttributeMappingError raised when required attribute is missing"""
        rules = {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {
                "user_field": "email",
                "required": True,
            },
        }
        mapper = AttributeMapper(rules)

        saml_attrs = {}  # missing required email

        with pytest.raises(AttributeMappingError) as exc_info:
            mapper.map(saml_attrs)
        assert "emailaddress" in str(exc_info.value)

    def test_map_optional_attribute_with_default(self):
        """Test optional attribute uses default when missing"""
        rules = {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/department": {
                "user_field": "department",
                "required": False,
                "default": "General",
            },
        }
        mapper = AttributeMapper(rules)

        result = mapper.map({})
        assert result["department"] == "General"

    def test_map_multiple_values_takes_first(self):
        """Test that when attribute has multiple values, first is used"""
        rules = {
            "groups": {
                "user_field": "groups",
                "required": False,
            },
        }
        mapper = AttributeMapper(rules)

        saml_attrs = {"groups": ["group1", "group2", "group3"]}
        result = mapper.map(saml_attrs)
        assert result["groups"] == "group1"

    def test_map_empty_value_no_default(self):
        """Test empty value list for non-required attribute returns None"""
        rules = {
            "optional_attr": {
                "user_field": "optional",
                "required": False,
            },
        }
        mapper = AttributeMapper(rules)

        result = mapper.map({})
        assert result["optional"] is None

    def test_map_complex_rules(self):
        """Test complex attribute mapping with multiple fields"""
        rules = {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": {
                "user_field": "email",
                "required": True,
            },
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": {
                "user_field": "first_name",
                "required": False,
            },
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": {
                "user_field": "last_name",
                "required": False,
            },
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name": {
                "user_field": "full_name",
                "required": False,
            },
            "department": {
                "user_field": "department",
                "required": False,
            },
        }
        mapper = AttributeMapper(rules)

        saml_attrs = {
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress": ["john.doe@example.com"],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/givenname": ["John"],
            "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/surname": ["Doe"],
            "department": ["Engineering"],
        }

        result = mapper.map(saml_attrs)
        assert result["email"] == "john.doe@example.com"
        assert result["first_name"] == "John"
        assert result["last_name"] == "Doe"
        assert result["full_name"] is None  # not in input
        assert result["department"] == "Engineering"
