import json
from uuid import UUID

from sqlalchemy import insert
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.logger import get_logger
from app.domain.ports.output.AuditStorage import AuditStorage
from app.infrastructure.database.models.audit_event import AuditEvent

logger = get_logger("audit-repository")


class SQLAlchemyAuditRepository(AuditStorage):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def store_audit_record(self, record: AuditEvent) -> None:
        stmt = insert(AuditEvent).values(
            id=str(record.id),
            correlation_id=_to_str(record.correlation_id),
            session_id=_to_str(record.session_id),
            request_id=_to_str(record.request_id),
            service_name=record.service_name,
            event_type=record.event_type,
            event_action=record.event_action,
            tenant_id=_to_str(record.tenant_id),
            organization_id=_to_str(record.organization_id),
            user_id=_to_str(record.user_id),
            resource_id=_to_str(record.resource_id),
            resource_type=record.resource_type,
            actor_type=getattr(record.actor_type, "value", record.actor_type),
            actor_id=_to_str(record.actor_id),
            success=record.success,
            status_code=record.status_code,
            error_message=record.error_message,
            duration_ms=record.duration_ms,
            ip_address=record.ip_address,
            user_agent=record.user_agent,
            metadata_json=json.dumps(record.metadata or {}),
        )
        try:
            await self._session.execute(stmt)
            await self._session.commit()
            logger.info(
                "Audit record inserted",
                action="audit_insert",
                event_type=record.event_type,
                event_action=record.event_action,
                record_id=str(record.id),
            )
        except Exception as exc:
            await self._session.rollback()
            logger.error(
                "Audit record insert failed",
                action="audit_insert_error",
                error=str(exc),
                record_id=str(record.id),
            )
            raise


def _to_str(value: UUID | str | None) -> str | None:
    if value is None:
        return None
    if isinstance(value, UUID):
        return str(value)
    return str(value)
