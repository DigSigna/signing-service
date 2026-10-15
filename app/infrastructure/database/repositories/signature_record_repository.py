"""SQLAlchemy adapter for SignatureRecordRepository, over the
`signing_requests`/`signatures` tables (migration 003 of the
`migrations` repo, same shared `digsigna` schema). Writes both rows in
one transaction — this service only ever records a signature after
hsm-service already produced it, so there is no PENDING state to model
yet (see SignatureRecord's docstring)."""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.SignatureRecord import SignatureRecord
from app.domain.ports.output.SignatureRecordRepository import (
    SignatureRecordRepository,
)
from app.infrastructure.database.models.signature import Signature
from app.infrastructure.database.models.signing_request import SigningRequest


class SQLAlchemySignatureRecordRepository(SignatureRecordRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def create(self, record: SignatureRecord) -> None:
        self._session.add(
            SigningRequest(
                id=str(record.id),
                tenant_id=str(record.tenant_id),
                organization_id=str(record.organization_id)
                if record.organization_id
                else None,
                user_id=str(record.user_id) if record.user_id else None,
                key_id=str(record.key_id),
                document_hash=record.document_hash,
                document_name=record.document_name,
                hash_algorithm=record.hash_algorithm,
                status="SIGNED",
                created_at=record.signing_time,
            )
        )
        # Neither model declares a SQLAlchemy ForeignKey (matching this
        # codebase's existing plain-column convention — see Tenant/
        # AuditEvent/IdempotencyKey) so the unit of work has no
        # dependency info between them; without this explicit flush,
        # autoflush ordering put the `signatures` INSERT first and the
        # DB's own FK constraint (signing_requests.id) rejected it.
        await self._session.flush()
        self._session.add(
            Signature(
                id=str(record.signature_id),
                signing_request_id=str(record.id),
                key_id=str(record.key_id),
                certificate_id=str(record.certificate_id),
                signature_value=record.signature_value,
                signature_format=record.signature_format,
                signing_time=record.signing_time,
            )
        )
        try:
            await self._session.commit()
        except Exception:
            await self._session.rollback()
            raise

    async def find_by_id(self, signing_request_id: UUID) -> Optional[SignatureRecord]:
        stmt = select(SigningRequest).where(
            SigningRequest.id == str(signing_request_id)
        )
        result = await self._session.execute(stmt)
        request_row = result.scalar_one_or_none()
        if request_row is None:
            return None

        stmt = select(Signature).where(
            Signature.signing_request_id == str(signing_request_id)
        )
        result = await self._session.execute(stmt)
        signature_row = result.scalar_one_or_none()
        if signature_row is None:
            return None

        return SignatureRecord(
            id=UUID(request_row.id),
            tenant_id=UUID(request_row.tenant_id),
            key_id=UUID(request_row.key_id),
            certificate_id=UUID(signature_row.certificate_id),
            document_hash=request_row.document_hash,
            hash_algorithm=request_row.hash_algorithm,
            signature_id=UUID(signature_row.id),
            signature_value=signature_row.signature_value,
            signature_format=signature_row.signature_format,
            signing_time=signature_row.signing_time,
            document_name=request_row.document_name,
            user_id=UUID(request_row.user_id) if request_row.user_id else None,
            organization_id=(
                UUID(request_row.organization_id)
                if request_row.organization_id
                else None
            ),
        )
