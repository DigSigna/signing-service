"""SQLAlchemy adapter for SigningRequestRepository, over the
`signing_requests`/`signatures` tables (migrations 003 + 026 of the
`migrations` repo, same shared `digsigna` schema). Replaces
SQLAlchemySignatureRecordRepository now that a signing_request can own
more than one signature (signing-plan.md point 4)."""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.Signature import Signature
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.ports.output.SigningRequestRepository import (
    SigningRequestRepository,
)
from app.domain.valueobjects.SigningRequestStatus import SigningRequestStatus
from app.infrastructure.database.models.signature import Signature as SignatureModel
from app.infrastructure.database.models.signing_request import (
    SigningRequest as SigningRequestModel,
)


class SQLAlchemySigningRequestRepository(SigningRequestRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def create(self, request: SigningRequest) -> None:
        self._session.add(
            SigningRequestModel(
                id=str(request.id),
                tenant_id=str(request.tenant_id),
                organization_id=str(request.organization_id)
                if request.organization_id
                else None,
                user_id=str(request.user_id) if request.user_id else None,
                key_id=None,
                document_hash=request.document_hash,
                document_name=request.document_name,
                hash_algorithm=request.hash_algorithm,
                status=request.status.value,
                created_at=request.created_at,
                signers_number=request.signers_number,
                signatures_count=request.signatures_count,
                document_blob=request.document_blob,
                completed_at=request.completed_at,
                version=request.version,
            )
        )
        try:
            await self._session.commit()
        except Exception:
            await self._session.rollback()
            raise

    async def find_by_id(self, signing_request_id: UUID) -> Optional[SigningRequest]:
        stmt = select(SigningRequestModel).where(
            SigningRequestModel.id == str(signing_request_id)
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _to_entity(row)

    async def find_signature_by_id(self, signature_id: UUID) -> Optional[Signature]:
        stmt = select(SignatureModel).where(SignatureModel.id == str(signature_id))
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return Signature(
            id=UUID(row.id),
            signing_request_id=UUID(row.signing_request_id),
            key_id=UUID(row.key_id),
            certificate_id=UUID(row.certificate_id) if row.certificate_id else None,
            signature_value=row.signature_value,
            signature_format=row.signature_format,
            signing_time=row.signing_time,
            tsa_provider=row.tsa_provider,
            tsa_token=row.tsa_token,
            tsa_sealed_at=row.tsa_sealed_at,
        )

    async def append_signature(
        self,
        signing_request_id: UUID,
        expected_version: int,
        new_document_blob: bytes,
        new_status: SigningRequestStatus,
        completed_at,
        signature: Signature,
    ) -> bool:
        # Optimistic concurrency: the UPDATE only takes effect if
        # `version` still matches what the caller last read. A
        # concurrent /sign call on the same signing_request_id that
        # committed first will have already bumped version, so this
        # UPDATE affects zero rows — checked via rowcount, never via a
        # second SELECT (which could itself race).
        stmt = (
            update(SigningRequestModel)
            .where(
                SigningRequestModel.id == str(signing_request_id),
                SigningRequestModel.version == expected_version,
            )
            .values(
                document_blob=new_document_blob,
                signatures_count=SigningRequestModel.signatures_count + 1,
                status=new_status.value,
                completed_at=completed_at,
                version=SigningRequestModel.version + 1,
            )
        )
        try:
            result = await self._session.execute(stmt)
            if result.rowcount == 0:
                await self._session.rollback()
                return False

            self._session.add(
                SignatureModel(
                    id=str(signature.id),
                    signing_request_id=str(signature.signing_request_id),
                    key_id=str(signature.key_id),
                    certificate_id=str(signature.certificate_id),
                    signature_value=signature.signature_value,
                    signature_format=signature.signature_format,
                    signing_time=signature.signing_time,
                    tsa_token=signature.tsa_token,
                    tsa_provider=signature.tsa_provider,
                    tsa_sealed_at=signature.tsa_sealed_at,
                )
            )
            await self._session.commit()
            return True
        except Exception:
            await self._session.rollback()
            raise


def _to_entity(row: SigningRequestModel) -> SigningRequest:
    return SigningRequest(
        id=UUID(row.id),
        tenant_id=UUID(row.tenant_id),
        document_name=row.document_name,
        document_hash=row.document_hash,
        hash_algorithm=row.hash_algorithm,
        signers_number=row.signers_number,
        signatures_count=row.signatures_count,
        status=SigningRequestStatus(row.status),
        document_blob=row.document_blob,
        user_id=UUID(row.user_id) if row.user_id else None,
        organization_id=UUID(row.organization_id) if row.organization_id else None,
        created_at=row.created_at,
        completed_at=row.completed_at,
        version=row.version,
    )
