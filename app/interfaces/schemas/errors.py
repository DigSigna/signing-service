"""Reusable OpenAPI error-response shape.

Matches what ErrorHandlingMiddleware actually sends for any DomainError
(see DomainError.to_dict() / app/interfaces/middleware/error_handling.py):
{"error": {"code": ..., "message": ..., "details": {...}}}. Declared once
here and reused via `responses={...}` on routes, so Swagger/Bruno shows the
real error contract instead of FastAPI's generic default.
"""

from __future__ import annotations

from typing import Any, Dict

from pydantic import BaseModel, Field


class ErrorBody(BaseModel):
    code: str = Field(..., description="Código de error estable (ver domain_errors.py)")
    message: str
    details: Dict[str, Any] = Field(default_factory=dict)


class ErrorResponse(BaseModel):
    error: ErrorBody
