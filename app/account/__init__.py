"""
Account Module - Credential Management & Account Merge/Unbind
Phase 2-5: 账号合并/解绑

Core capabilities:
  - 主账号-绑定凭证模型 (Primary Account - Credential Model)
  - 账号合并流程 (Account Merge Flow)
  - 账号解绑/换绑 (Account Unbind / Credential Change)
  - 并发安全: sorted lock + lock timeout (排序加锁 + 锁超时)
  - 幂等性设计 (Idempotency)
  - MFA/密码二次验证 (Secondary Verification)
  - 审计日志 (Audit Log)
"""
from __future__ import annotations

# Re-export public types
from .models import (
    AuthUser,
    UserCredential,
    AccountMergeRequest,
    AccountChangeLog,
    CredentialType,
    CredentialStatus,
    MergeStatus,
    MergeEventType,
)
from .schemas import (
    CredentialItem,
    CredentialListResponse,
    AddCredentialRequest,
    AddCredentialResponse,
    CredentialConflictError,
    UnbindRequest,
    ChangePhoneRequest,
    MergeInitiateRequest,
    MergeInitiateResponse,
    MergeConfirmRequest,
    MergeConfirmResponse,
    MergeCancelRequest,
    MergeStateMachine,
)
from .service import CredentialService, MergeService
from .identifier_normalizer import IdentifierNormalizer
from .retry_scheduler import MergeRetryScheduler
from .events import AuditEventType, log_audit_event

__all__ = [
    # Models
    "AuthUser",
    "UserCredential",
    "AccountMergeRequest",
    "AccountChangeLog",
    "CredentialType",
    "CredentialStatus",
    "MergeStatus",
    "MergeEventType",
    # Schemas
    "CredentialItem",
    "CredentialListResponse",
    "AddCredentialRequest",
    "AddCredentialResponse",
    "CredentialConflictError",
    "UnbindRequest",
    "ChangePhoneRequest",
    "MergeInitiateRequest",
    "MergeInitiateResponse",
    "MergeConfirmRequest",
    "MergeConfirmResponse",
    "MergeCancelRequest",
    "MergeStateMachine",
    # Services
    "CredentialService",
    "MergeService",
    "IdentifierNormalizer",
    "MergeRetryScheduler",
    # Events
    "AuditEventType",
    "log_audit_event",
]
