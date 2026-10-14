"""Audit-logging decorator for TenantRepository.

Hexagonal pattern: secondary adapter that wraps another TenantRepository
and reports every operation via AuditEventDispatcher. Equivalente a
hsm-service's AuditedTenantRepository
(internal/infrastructure/storage/adapters/audited_tenant_repository.go).
"""

from __future__ import annotations

import time
from typing import Optional
from uuid import UUID

from app.domain.entities.Tenant import Tenant
from app.domain.exceptions.domain_errors import get_error_code
from app.domain.ports.output.AuditEventDispatcher import AuditEventDispatcher
from app.domain.ports.output.TenantRepository import TenantRepository
from app.domain.valueobjects.ActorType import ActorType
from app.domain.valueobjects.AuditData import AuditData

_SERVICE_NAME = "repository-adapter"


class AuditedTenantRepository(TenantRepository):
    def __init__(
        self,
        repository: TenantRepository,
        audit_dispatcher: Optional[AuditEventDispatcher],
    ):
        self._repository = repository
        self._audit_dispatcher = audit_dispatcher

    async def find_by_id(self, tenant_id: UUID) -> Optional[Tenant]:
        return await self._audited_call(
            "FIND_BY_ID", str(tenant_id), self._repository.find_by_id, tenant_id
        )

    async def exists(self, tenant_id: UUID) -> bool:
        return await self._audited_call(
            "EXISTS", str(tenant_id), self._repository.exists, tenant_id
        )

    async def find_by_hsm_slot(self, slot: str) -> Optional[Tenant]:
        return await self._audited_call(
            "FIND_BY_HSM_SLOT", slot, self._repository.find_by_hsm_slot, slot
        )

    async def update_hsm_slot(self, tenant_id: UUID, slot_id: str) -> None:
        return await self._audited_call(
            "UPDATE_HSM_SLOT",
            str(tenant_id),
            self._repository.update_hsm_slot,
            tenant_id,
            slot_id,
        )

    async def _audited_call(self, operation: str, resource_id: str, fn, *args):
        start = time.monotonic()
        error: Optional[BaseException] = None
        try:
            return await fn(*args)
        except BaseException as exc:
            error = exc
            raise
        finally:
            await self._audit_operation(
                operation=operation,
                resource_id=resource_id,
                duration_ms=int((time.monotonic() - start) * 1000),
                error=error,
            )

    async def _audit_operation(
        self,
        operation: str,
        resource_id: str,
        duration_ms: int,
        error: Optional[BaseException],
    ) -> None:
        if self._audit_dispatcher is None:
            return

        data = AuditData(
            service_name=_SERVICE_NAME,
            event_type="REPOSITORY_OPERATION",
            operation=f"TENANT_{operation}",
            resource_id=resource_id,
            resource_type="tenant",
            actor_type=ActorType.SYSTEM.value,
            success=error is None,
            status_code=get_error_code(error),
            err_msg=str(error) if error else "",
            duration_ms=duration_ms,
            metadata={},
        )
        await self._audit_dispatcher.audit_operation(None, data, None)
