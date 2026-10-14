"""FastAPI middleware for JWT validation."""

from __future__ import annotations

from typing import Callable

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response
from starlette.status import HTTP_401_UNAUTHORIZED

from app.domain.ports.output.JWTValidator import JWTValidator
from app.domain.valueobjects.IdentityContext import IdentityContext
from app.domain.valueobjects.OwnerType import OwnerType


class AuthMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, validator: JWTValidator | None = None):
        super().__init__(app)
        self._validator = validator

    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        if request.url.path in {"/api/v1/health", "/docs", "/redoc", "/openapi.json"}:
            return await call_next(request)

        auth_header = request.headers.get("Authorization")
        if not auth_header or not auth_header.startswith("Bearer "):
            return Response(status_code=HTTP_401_UNAUTHORIZED)

        token = auth_header.replace("Bearer ", "", 1)
        try:
            validator = self._validator or getattr(
                request.app.state, "jwt_validator", None
            )
            if validator is None:
                return Response(status_code=HTTP_401_UNAUTHORIZED)
            claims = validator.validate_token(token)
        except Exception:
            return Response(status_code=HTTP_401_UNAUTHORIZED)

        identity_context = IdentityContext(
            tenant_id=claims.tenant_id,
            owner_type=OwnerType(claims.owner_type),
            owner_id=claims.owner_id,
            user_id=claims.user_id,
            cert_level=claims.cert_level,
            max_cert_level=claims.max_cert_level,
            can_certify=claims.can_certify,
            certification_path=claims.certification_path,
            permissions=claims.permissions,
            organization_id=claims.organization_id,
            parent_key_id=claims.parent_key_id,
        )
        request.state.identity_context = identity_context
        # Servicios stateless: sin token de servicio fijo para llamar a
        # hsm-service — se reenvía el JWT original del caller (ver
        # RemoteHSMClient / routes/hsm.py).
        request.state.bearer_token = token
        return await call_next(request)
