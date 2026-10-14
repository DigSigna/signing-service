"""Request context utilities for correlation IDs and metadata."""

from __future__ import annotations

import uuid
from dataclasses import dataclass
from typing import Optional
import contextvars

correlation_id_var = contextvars.ContextVar("correlation_id", default="")
session_id_var = contextvars.ContextVar("session_id", default="")
ip_address_var = contextvars.ContextVar("ip_address", default="")
user_agent_var = contextvars.ContextVar("user_agent", default="")
request_id_var = contextvars.ContextVar("request_id", default="")
actor_var = contextvars.ContextVar("actor", default="")
duration_ms_var = contextvars.ContextVar("duration_ms", default=None)
tenant_id_var = contextvars.ContextVar("tenant_id", default=None)

HEADER_X_FORWARDED_FOR = "X-Forwarded-For"
HEADER_X_REAL_IP = "X-Real-IP"
HEADER_USER_AGENT = "User-Agent"
HEADER_X_REQUEST_ID = "X-Request-ID"
HEADER_X_API_KEY = "X-API-Key"
HEADER_X_CORRELATION_ID = "X-Correlation-ID"
HEADER_X_SESSION_ID = "X-Session-ID"


@dataclass
class ContextValues:
    correlation_id: str
    session_id: str
    ip_address: str
    user_agent: str
    request_id: str
    actor: str
    duration_ms: Optional[int] = None
    tenant_id: Optional[str] = None


def generate_request_id() -> str:
    return str(uuid.uuid4())


def set_context_values(values: ContextValues) -> None:
    correlation_id_var.set(values.correlation_id)
    session_id_var.set(values.session_id)
    ip_address_var.set(values.ip_address)
    user_agent_var.set(values.user_agent)
    request_id_var.set(values.request_id)
    actor_var.set(values.actor)
    duration_ms_var.set(values.duration_ms)
    tenant_id_var.set(values.tenant_id)


def get_context_values() -> ContextValues:
    return ContextValues(
        correlation_id=correlation_id_var.get(),
        session_id=session_id_var.get(),
        ip_address=ip_address_var.get(),
        user_agent=user_agent_var.get(),
        request_id=request_id_var.get(),
        actor=actor_var.get(),
    )
