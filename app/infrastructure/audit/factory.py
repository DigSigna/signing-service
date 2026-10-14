"""Factory helpers for building audit recorders based on strategy."""

from __future__ import annotations

from typing import Optional

from app.domain.entities.AuditEvent import AuditEvent
from app.domain.ports.input.AuditRecorder import AuditRecorder
from app.domain.ports.output.AuditStorage import AuditStorage
from app.domain.ports.output.AuditTransporter import AuditTransporter
from app.domain.valueobjects.AuditStrategy import AuditStrategy
from app.infrastructure.audit.hybrid_processor import HybridProcessor
from app.infrastructure.external.audit.http_audit_transporter import (
    HttpAuditTransporter,
)


def new_audit_recorder(
    strategy: AuditStrategy,
    storage: AuditStorage,
    http_base_url: Optional[str],
) -> AuditRecorder:
    db_storage = storage

    http_transporter: Optional[AuditTransporter] = None
    if http_base_url and http_base_url != "mock":
        http_transporter = HttpAuditTransporter(http_base_url)

    if http_transporter is None and strategy in {
        AuditStrategy.HTTP,
        AuditStrategy.HYBRID,
    }:
        strategy = AuditStrategy.DATABASE

    if strategy == AuditStrategy.DATABASE:
        return _DatabaseRecorder(db_storage)
    if strategy == AuditStrategy.HTTP:
        return _HttpRecorder(http_transporter)
    if strategy == AuditStrategy.HYBRID:
        return HybridProcessor(strategy, http_transporter, db_storage)
    if strategy == AuditStrategy.MOCK:
        return _MockRecorder()

    return _DatabaseRecorder(db_storage)


class _DatabaseRecorder(AuditRecorder):
    def __init__(self, storage: AuditStorage):
        self._storage = storage

    async def record_event(self, ctx, event: AuditEvent) -> None:
        result = self._storage.store_audit_record(event)
        if hasattr(result, "__await__"):
            await result


class _HttpRecorder(AuditRecorder):
    def __init__(self, transporter: AuditTransporter):
        self._transporter = transporter

    async def record_event(self, ctx, event: AuditEvent) -> None:
        result = self._transporter.send(ctx, event)
        if hasattr(result, "__await__"):
            await result


class _MockRecorder(AuditRecorder):
    async def record_event(self, ctx, event: AuditEvent) -> None:
        return None
