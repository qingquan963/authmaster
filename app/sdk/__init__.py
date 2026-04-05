"""
SDK Module - AuthMaster External API SDK
Phase 2-6: Auth SDK (对外 API SDK)

Provides standardized authentication/authorization APIs for third-party
applications, integrators, and ISVs.

Structure:
  app/sdk/
    models.py       — SQLAlchemy models (api_keys, api_call_logs)
    errors.py       — Unified error codes
    schemas.py      — Pydantic request/response schemas
    service.py      — Core business logic
    middleware.py   — API Key authentication middleware
    router.py       — FastAPI routes
"""
