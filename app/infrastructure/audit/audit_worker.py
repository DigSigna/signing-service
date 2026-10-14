"""Async audit worker that dispatches events using an AuditRecorder."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import Any, Optional
from uuid import UUID, uuid4

from app.core.logger import get_logger
from app.core.request_context import get_context_values
from app.domain.entities.AuditEvent import AuditEvent
from app.domain.ports.input.AuditRecorder import AuditRecorder
from app.domain.ports.output.AuditEventDispatcher import AuditEventDispatcher
from app.domain.valueobjects.ActorType import ActorType
from app.domain.valueobjects.AuditData import AuditData
from app.domain.valueobjects.IdentityContext import IdentityContext

_DEFAULT_BUFFER_SIZE = 1000
_DEFAULT_WORKERS = 3
_DEFAULT_TIMEOUT = 5.0

logger = get_logger("audit-worker")


@dataclass
class WorkerConfig:
    worker_count: int = _DEFAULT_WORKERS
    buffer_size: int = _DEFAULT_BUFFER_SIZE
    flush_timeout: float = _DEFAULT_TIMEOUT


@dataclass
class AuditWorker(AuditEventDispatcher):
    audit_client: Optional[AuditRecorder]
    config: WorkerConfig = field(default_factory=WorkerConfig)
    _queue: asyncio.Queue[AuditEvent] = field(init=False)
    _tasks: list[asyncio.Task] = field(default_factory=list, init=False)
    _closing: bool = field(default=False, init=False)

    def __post_init__(self) -> None:
        self._queue = asyncio.Queue(maxsize=self.config.buffer_size)
        if self.audit_client:
            self._start_workers()

    def _start_workers(self) -> None:
        for _ in range(self.config.worker_count):
            self._tasks.append(asyncio.create_task(self._worker_loop()))

    async def _worker_loop(self) -> None:
        while True:
            item = await self._queue.get()
            if item is None:  # type: ignore[comparison-overlap]
                self._queue.task_done()
                return
            try:
                ctx, event = item
                await asyncio.wait_for(
                    self.audit_client.record_event(ctx, event),
                    timeout=self.config.flush_timeout,
                )
                logger.info(
                    "Audit event stored",
                    action="audit_store",
                    event_type=event.event_type,
                    event_action=event.event_action,
                    resource_id=str(event.resource_id) if event.resource_id else None,
                    success=event.success,
                )
            except Exception as exc:
                logger.error(
                    "Audit event failed",
                    action="audit_error",
                    error=str(exc),
                    event_type=getattr(event, "event_type", None),
                    event_action=getattr(event, "event_action", None),
                )
            finally:
                self._queue.task_done()

    async def send_event(self, ctx: Any, event: AuditEvent) -> None:
        if not self.audit_client or self._closing:
            return
        try:
            await asyncio.wait_for(self._queue.put((ctx, event)), timeout=0.1)
        except asyncio.TimeoutError:
            logger.warning(
                "Audit queue full",
                action="audit_queue_full",
                event_type=event.event_type,
                event_action=event.event_action,
            )
            return

    async def audit_operation(
        self, ctx: Any, data: AuditData, identity_context: Optional[IdentityContext]
    ) -> None:
        if not self.audit_client:
            return
        context_values = get_context_values()
        event = _build_event(data, identity_context, context_values)
        await self.send_event(ctx, event)

    async def close(self) -> None:
        if not self.audit_client:
            return
        self._closing = True
        for _ in self._tasks:
            await self._queue.put(None)  # type: ignore[arg-type]
        await asyncio.gather(*self._tasks, return_exceptions=True)
        self._tasks.clear()


def _build_event(
    data: AuditData,
    identity_context: Optional[IdentityContext],
    context_values,
) -> AuditEvent:
    organization_id = identity_context.organization_id if identity_context else None
    user_id = identity_context.user_id if identity_context else None
    tenant_id = identity_context.tenant_id if identity_context else None
    return AuditEvent(
        id=uuid4(),
        correlation_id=_coerce_uuid(context_values.correlation_id),
        session_id=_coerce_uuid(context_values.session_id),
        request_id=_coerce_uuid(context_values.request_id),
        service_name=data.service_name,
        event_type=data.event_type,
        event_action=data.operation,
        organization_id=_coerce_uuid(organization_id),
        user_id=_require_uuid(user_id),
        tenant_id=_require_uuid(tenant_id),
        resource_id=_coerce_uuid(data.resource_id),
        resource_type=data.resource_type,
        actor_type=_coerce_actor_type(data.actor_type),
        actor_id=_coerce_uuid(context_values.actor),
        success=data.success,
        status_code=data.status_code,
        error_message=data.err_msg,
        duration_ms=data.duration_ms,
        ip_address=context_values.ip_address,
        user_agent=context_values.user_agent,
        metadata=data.metadata,
    )


def _coerce_actor_type(value: Optional[str]) -> Optional[ActorType]:
    if not value:
        return None
    try:
        return ActorType(value)
    except ValueError:
        return None


def _coerce_uuid(value: Optional[str]) -> Optional[UUID]:
    if not value:
        return None
    if isinstance(value, UUID):
        return value
    try:
        return UUID(str(value))
    except ValueError:
        return None


def _require_uuid(value: Optional[str]) -> UUID:
    parsed = _coerce_uuid(value)
    return parsed or uuid4()
