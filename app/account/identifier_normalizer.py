"""
Account Module - Identifier Normalizer
Phase 2-5: 账号合并/解绑

[Fix6] Normalize identifiers before computing SHA256 hash:
  - phone: strip non-digits, remove +86 country code prefix
  - email: lowercase
  - others: use raw value unchanged
"""
from __future__ import annotations

import hashlib
import re


class IdentifierNormalizer:
    """
    [Fix6] Normalize raw identifiers to ensure consistent hashing.

    The same physical credential (e.g., phone number) may be entered in
    different formats:
      "+86-138-0000-0000" vs "861380000000" vs "138-0000-0000"

    Normalization rules:
      - phone: strip all non-digit characters, then remove leading +86 if present
      - email: lowercase
      - other types: returned as-is
    """

    @staticmethod
    def normalize(identifier: str, cred_type: str) -> str:
        """
        Normalize an identifier based on its credential type.

        Args:
            identifier: Raw identifier string
            cred_type: One of 'phone', 'email', 'wechat', 'alipay', 'saml',
                       'github', 'google', 'oidc'

        Returns:
            Normalized identifier string
        """
        if cred_type == "phone":
            # Remove all non-digit characters
            digits = re.sub(r"\D", "", identifier)
            # Strip leading +86 country code if present
            if digits.startswith("86") and len(digits) > 10:
                digits = digits[2:]
            return digits
        elif cred_type == "email":
            return identifier.lower()
        else:
            # Other credential types: return unchanged
            return identifier

    @staticmethod
    def compute_hash(identifier: str, cred_type: str) -> str:
        """
        Compute SHA256 hash of the normalized identifier.

        This hash is stored in `identifier_hash` column and used for
        uniqueness constraints and conflict detection.

        Args:
            identifier: Raw identifier string
            cred_type: Credential type

        Returns:
            64-character hex string (SHA256)
        """
        normalized = IdentifierNormalizer.normalize(identifier, cred_type)
        return hashlib.sha256(normalized.encode("utf-8")).hexdigest()

    @staticmethod
    def mask(identifier: str, cred_type: str) -> str:
        """
        Return a masked version of the identifier for display (privacy).

        Examples:
          phone:  "13800000000"  → "138****0000"
          email:  "user@example.com" → "u***@example.com"
        """
        if cred_type == "phone":
            # Show first 3 and last 4 digits
            if len(identifier) >= 7:
                return identifier[:3] + "****" + identifier[-4:]
            return "***"
        elif cred_type == "email":
            parts = identifier.split("@")
            if len(parts) == 2 and len(parts[0]) > 1:
                return parts[0][0] + "***@" + parts[1]
            return "***@" + parts[1] if len(parts) == 2 else "***"
        else:
            # Third-party: just return a generic placeholder
            return f"[{cred_type} user]"
