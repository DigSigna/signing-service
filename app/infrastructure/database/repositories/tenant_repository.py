from typing import Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.Tenant import Tenant as TenantEntity
from app.domain.ports.output.TenantRepository import TenantRepository
from app.domain.valueobjects.TenantMode import TenantMode
from app.infrastructure.database.models.tenant import Tenant as TenantModel


class SQLAlchemyTenantRepository(TenantRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def find_by_id(self, tenant_id: UUID) -> Optional[TenantEntity]:
        stmt = select(TenantModel).where(TenantModel.id == str(tenant_id))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _to_entity(row)

    async def exists(self, tenant_id: UUID) -> bool:
        stmt = select(TenantModel.id).where(TenantModel.id == str(tenant_id))
        result = await self._session.execute(stmt)
        return result.scalar_one_or_none() is not None

    async def find_by_hsm_slot(self, slot: str) -> Optional[TenantEntity]:
        stmt = select(TenantModel).where(TenantModel.hsm_slot_id == slot)
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _to_entity(row)

    async def update_hsm_slot(self, tenant_id: UUID, slot_id: str) -> None:
        stmt = (
            update(TenantModel)
            .where(TenantModel.id == str(tenant_id))
            .values(hsm_slot_id=slot_id)
        )
        try:
            await self._session.execute(stmt)
            await self._session.commit()
        except Exception:
            await self._session.rollback()
            raise


def _to_entity(row: TenantModel) -> TenantEntity:
    mode = TenantMode(row.mode) if row.mode else TenantMode.MANAGED
    return TenantEntity(
        id=UUID(row.id), name=row.name, mode=mode, hsm_slot_id=row.hsm_slot_id
    )
