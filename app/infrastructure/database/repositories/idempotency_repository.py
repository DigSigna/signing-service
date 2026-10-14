"""SQLAlchemy adapter for IdempotencyRepository.

Equivalente a hsm-service's MySQLIdempotencyStorage
(internal/infrastructure/storage/mysql/idempotency_storage.go), sobre la
misma tabla compartida `idempotency_keys` (migración 019 del repo
`migrations`, misma base `digsigna` que usa hsm-service).
"""

from __future__ import annotations

import uuid
from typing import Optional

from sqlalchemy import delete, insert, select, update
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.IdempotencyRecord import IdempotencyRecord
from app.domain.ports.output.IdempotencyRepository import (
    IdempotencyKeyExistsError,
    IdempotencyRepository,
)
from app.infrastructure.database.models.idempotency_key import IdempotencyKey

_MYSQL_DUPLICATE_ENTRY = 1062


class SQLAlchemyIdempotencyRepository(IdempotencyRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def claim(self, tenant_id: str, request_id: str, operation: str) -> None:
        stmt = insert(IdempotencyKey).values(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            request_id=request_id,
            operation=operation,
        )
        try:
            await self._session.execute(stmt)
            await self._session.commit()
        except IntegrityError as exc:
            await self._session.rollback()
            if _is_duplicate_entry(exc):
                raise IdempotencyKeyExistsError() from exc
            raise

    async def find_by_request_id(
        self, tenant_id: str, request_id: str
    ) -> Optional[IdempotencyRecord]:
        stmt = select(IdempotencyKey).where(
            IdempotencyKey.tenant_id == tenant_id,
            IdempotencyKey.request_id == request_id,
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return IdempotencyRecord(
            id=row.id,
            tenant_id=row.tenant_id,
            request_id=row.request_id,
            operation=row.operation,
            resource_id=row.resource_id,
        )

    async def complete(self, tenant_id: str, request_id: str, resource_id: str) -> None:
        stmt = (
            update(IdempotencyKey)
            .where(
                IdempotencyKey.tenant_id == tenant_id,
                IdempotencyKey.request_id == request_id,
            )
            .values(resource_id=resource_id)
        )
        try:
            await self._session.execute(stmt)
            await self._session.commit()
        except Exception:
            await self._session.rollback()
            raise

    async def release(self, tenant_id: str, request_id: str) -> None:
        stmt = delete(IdempotencyKey).where(
            IdempotencyKey.tenant_id == tenant_id,
            IdempotencyKey.request_id == request_id,
        )
        try:
            await self._session.execute(stmt)
            await self._session.commit()
        except Exception:
            await self._session.rollback()
            raise


def _is_duplicate_entry(exc: IntegrityError) -> bool:
    orig = exc.orig
    args = getattr(orig, "args", None)
    if args and args[0] == _MYSQL_DUPLICATE_ENTRY:
        return True
    return "Duplicate entry" in str(exc)
