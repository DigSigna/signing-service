"""Equivalente a hsm-service's output.TenantRepository, usado por
AuditedTenantRepository (storage/adapters/audited_tenant_repository.go)."""

from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID

from app.domain.entities.Tenant import Tenant


class TenantRepository(ABC):
    @abstractmethod
    async def find_by_id(self, tenant_id: UUID) -> Optional[Tenant]:
        raise NotImplementedError

    @abstractmethod
    async def exists(self, tenant_id: UUID) -> bool:
        raise NotImplementedError

    @abstractmethod
    async def find_by_hsm_slot(self, slot: str) -> Optional[Tenant]:
        raise NotImplementedError

    @abstractmethod
    async def update_hsm_slot(self, tenant_id: UUID, slot_id: str) -> None:
        raise NotImplementedError
