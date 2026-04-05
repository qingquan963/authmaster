"""
SAML Module - AuthMaster as SAML 2.0 Service Provider (SP)
Phase 2-4: SAML 协议支持

Endpoints:
  GET  /saml/metadata     — SP metadata XML
  GET  /saml/login        — Initiate SAML SSO (AuthnRequest)
  POST /saml/acs          — Assertion Consumer Service (handle SAML Response)

Admin API (Phase 2-4):
  (IdP config and binding management is Phase 3 scope, covered by /admin/v1/saml/* routes)

Note: /saml/slo (Single Logout) is handled by the SSO module (Phase 2-9).
"""
