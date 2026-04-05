"""
Rate Limiting Schemas
Phase 2-7: 百万级 QOS 高并发架构

Pydantic schemas for request/response validation.
"""
from __future__ import annotations

from datetime import datetime
from typing import Optional
from pydantic import BaseModel, Field


# ---------------------------------------------------------------------------
# Rate Limit Rule Schemas
# ---------------------------------------------------------------------------

class RateLimitRuleBase(BaseModel):
    endpoint_pattern: str = Field(..., max_length=128, description="URL pattern, supports * wildcard")
    key_type: str = Field(default="ip", description="ip | user | api_key | tenant | global")
    rate: int = Field(..., gt=0, description="Max requests per window")
    window: int = Field(..., gt=0, description="Window size in seconds")
    burst: Optional[int] = Field(None, gt=0, description="Burst capacity (for token bucket)")
    enabled: bool = Field(default=True)
    priority: int = Field(default=0, description="Higher priority rules match first")
    extra_config: dict = Field(default_factory=dict)


class RateLimitRuleCreate(RateLimitRuleBase):
    tenant_id: Optional[str] = Field(None, description="NULL = global rule applies to all tenants")


class RateLimitRuleUpdate(BaseModel):
    rate: Optional[int] = Field(None, gt=0)
    window: Optional[int] = Field(None, gt=0)
    burst: Optional[int] = Field(None, gt=0)
    enabled: Optional[bool] = None
    priority: Optional[int] = None
    extra_config: Optional[dict] = None


class RateLimitRuleResponse(RateLimitRuleBase):
    id: str
    tenant_id: Optional[str]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


# ---------------------------------------------------------------------------
# Rate Limit Check Result
# ---------------------------------------------------------------------------

class RateLimitDecision(BaseModel):
    """
    Result of a rate limit check.
    Returned by middleware to the client via headers.
    """
    allowed: bool = Field(..., description="True if request is allowed")
    reason: str = Field(..., description="allowed | local_limited | global_limited | circuit_open")
    limit: int = Field(..., description="Rate limit (requests per window)")
    remaining: int = Field(..., description="Remaining requests in current window")
    reset_at: Optional[datetime] = Field(None, description="When the window resets (ISO 8601)")
    retry_after: Optional[int] = Field(None, description="Seconds until client can retry (429 only)")


# ---------------------------------------------------------------------------
# Circuit Breaker Stats
# ---------------------------------------------------------------------------

class CircuitBreakerStats(BaseModel):
    name: str
    state: str  # closed | open | half_open
    failure_count: int
    success_count: int
    half_open_calls: int
    last_failure_time: Optional[str]


# ---------------------------------------------------------------------------
# Cache Stats
# ---------------------------------------------------------------------------

class CacheStats(BaseModel):
    l1_size: int
    l1_max_size: int
    l1_expired_pending: int
