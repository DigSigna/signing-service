"""FastAPI middleware that extracts request metadata into context vars."""

from __future__ import annotations

from typing import Callable
import uuid

from fastapi import Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response

from app.core.request_context import (
    HEADER_USER_AGENT,
    HEADER_X_API_KEY,
    HEADER_X_CORRELATION_ID,
    HEADER_X_FORWARDED_FOR,
    HEADER_X_REAL_IP,
    HEADER_X_REQUEST_ID,
    HEADER_X_SESSION_ID,
    ContextValues,
    generate_request_id,
    set_context_values,
)


def _extract_client_ip(request: Request) -> str:
    forwarded = request.headers.get(HEADER_X_FORWARDED_FOR)
    if forwarded:
        return forwarded.split(",")[0].strip()
    real_ip = request.headers.get(HEADER_X_REAL_IP)
    if real_ip:
        return real_ip
    if request.client:
        return request.client.host
    return ""


def _extract_actor(request: Request) -> str:
    api_key = request.headers.get(HEADER_X_API_KEY)
    if api_key:
        return f"api-key:{_mask(api_key)}"

    auth_header = request.headers.get("Authorization")
    if auth_header and auth_header.startswith("Bearer "):
        token = auth_header.replace("Bearer ", "", 1)
        return f"jwt:{_mask(token)}"

    token = request.query_params.get("token")
    if token:
        return f"jwt-query:{_mask(token)}"

    return "anonymous"


def _mask(value: str) -> str:
    if len(value) <= 8:
        return "***"
    return f"{value[:4]}...{value[-4:]}"


class RequestContextMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next: Callable) -> Response:
        correlation_id = request.headers.get(HEADER_X_CORRELATION_ID) or str(
            uuid.uuid4()
        )
        request_id = request.headers.get(HEADER_X_REQUEST_ID) or generate_request_id()
        session_id = request.headers.get(HEADER_X_SESSION_ID, "")

        values = ContextValues(
            correlation_id=correlation_id,
            session_id=session_id,
            ip_address=_extract_client_ip(request),
            user_agent=request.headers.get(HEADER_USER_AGENT, ""),
            request_id=request_id,
            actor=_extract_actor(request),
        )
        set_context_values(values)

        response = await call_next(request)
        response.headers.setdefault(HEADER_X_REQUEST_ID, request_id)
        response.headers.setdefault(HEADER_X_CORRELATION_ID, correlation_id)
        return response
