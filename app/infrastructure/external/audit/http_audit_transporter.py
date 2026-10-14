from __future__ import annotations

from typing import Any, Dict

import requests

from app.core.request_context import HEADER_X_CORRELATION_ID, get_context_values
from app.domain.entities.AuditEvent import AuditEvent
from app.domain.ports.output.AuditTransporter import AuditTransporter


class HttpAuditTransporter(AuditTransporter):
    """Cliente HTTP para enviar eventos de auditoría a audit-service."""

    def __init__(self, base_url: str, timeout: int = 10):
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {
                "User-Agent": "signing-service/1.0",
                "Content-Type": "application/json",
            }
        )

    def send(self, ctx: Any, event: AuditEvent) -> None:
        correlation_id = _resolve_correlation_id(ctx)
        headers: Dict[str, str] = {}
        if correlation_id:
            headers[HEADER_X_CORRELATION_ID] = correlation_id

        payload = _serialize_event(event)
        url = f"{self.base_url}/api/v1/events"

        try:
            response = self.session.post(
                url, json=payload, headers=headers, timeout=self.timeout
            )
            response.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(f"Error enviando evento de auditoría: {exc}")

    def health_check(self, ctx: Any) -> None:
        url = f"{self.base_url}/health"
        try:
            response = self.session.get(url, timeout=self.timeout)
            response.raise_for_status()
        except requests.RequestException as exc:
            raise RuntimeError(f"Error en health check: {exc}")


def _serialize_event(event: AuditEvent) -> Dict[str, Any]:
    if hasattr(event, "dict") and callable(event.dict):
        return event.dict()
    if hasattr(event, "model_dump") and callable(event.model_dump):
        return event.model_dump()
    return event.__dict__


def _resolve_correlation_id(ctx: Any) -> str:
    if ctx is not None:
        if hasattr(ctx, "correlation_id"):
            return getattr(ctx, "correlation_id")
        if isinstance(ctx, dict):
            return str(ctx.get("correlation_id", ""))

    return get_context_values().correlation_id
