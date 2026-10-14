"""Shared FastAPI route-composition helpers.

Pulls infrastructure singletons (HSM client, audit dispatcher) off
`request.app.state` and the caller's forwarded bearer token off
`request.state` — the same three lookups every route module that talks to
hsm-service or audits needs, so they're defined once here instead of being
redefined per route file.
"""

from __future__ import annotations

from typing import Optional

from fastapi import HTTPException, Request
from starlette.status import HTTP_400_BAD_REQUEST, HTTP_500_INTERNAL_SERVER_ERROR

from app.domain.ports.output.AuditEventDispatcher import AuditEventDispatcher
from app.domain.ports.output.HSMClient import HSMClient


def get_bearer_token(request: Request) -> str:
    # Servicios stateless: se reenvía el JWT del caller original, sin token
    # de servicio fijo (ver AuthMiddleware / RemoteHSMClient).
    token = getattr(request.state, "bearer_token", None)
    if not token:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST, detail="bearer_token missing"
        )
    return token


def get_hsm_client(request: Request) -> HSMClient:
    hsm_client = getattr(request.app.state, "hsm_client", None)
    if hsm_client is None:
        raise HTTPException(
            status_code=HTTP_500_INTERNAL_SERVER_ERROR,
            detail="HSM client not initialized",
        )
    return hsm_client


def get_audit_dispatcher(request: Request) -> Optional[AuditEventDispatcher]:
    """None when AUDIT_ENABLED=false — callers treat it as optional (see
    IdempotentAuditedIssuance), unlike hsm.py's own stricter requirement."""
    return getattr(request.app.state, "audit_worker", None)
