"""SQLAlchemy adapter for SigningSessionRepository, over the
`signing_pin_sessions` table (migration 023 of the `migrations` repo,
same shared `digsigna` schema hsm-service/certificate-service use)."""

from __future__ import annotations

from typing import Optional
from uuid import UUID

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from app.domain.entities.SigningSession import SigningSession
from app.domain.ports.output.SigningSessionRepository import SigningSessionRepository
from app.infrastructure.database.models.signing_pin_session import SigningPinSession


class SQLAlchemySigningSessionRepository(SigningSessionRepository):
    def __init__(self, session: AsyncSession):
        self._session = session

    async def create(self, session: SigningSession) -> None:
        row = SigningPinSession(
            id=str(session.id),
            tenant_id=str(session.tenant_id),
            certificate_id=str(session.certificate_id),
            session_token_hash=session.session_token_hash,
            issued_at=session.issued_at,
            expires_at=session.expires_at,
            max_signatures=session.max_signatures,
            signature_count=session.signature_count,
        )
        self._session.add(row)
        try:
            await self._session.commit()
        except Exception:
            await self._session.rollback()
            raise

    async def find_by_token_hash(self, token_hash: str) -> Optional[SigningSession]:
        stmt = select(SigningPinSession).where(
            SigningPinSession.session_token_hash == token_hash
        )
        result = await self._session.execute(stmt)
        row = result.scalar_one_or_none()
        if row is None:
            return None
        return _to_entity(row)

    async def increment_signature_count(self, session_id: UUID) -> int:
        """Atomic UPDATE, not a find-then-update round trip — a plain
        read-modify-write would race under concurrent signing calls on
        the same session, same reasoning as certificate-service's
        increment_failed_pin_attempts."""
        stmt = (
            update(SigningPinSession)
            .where(SigningPinSession.id == str(session_id))
            .values(signature_count=SigningPinSession.signature_count + 1)
        )
        try:
            await self._session.execute(stmt)
            await self._session.commit()
        except Exception:
            await self._session.rollback()
            raise

        result = await self._session.execute(
            select(SigningPinSession.signature_count).where(
                SigningPinSession.id == str(session_id)
            )
        )
        return result.scalar_one()


def _to_entity(row: SigningPinSession) -> SigningSession:
    return SigningSession(
        id=UUID(row.id),
        tenant_id=UUID(row.tenant_id),
        certificate_id=UUID(row.certificate_id),
        session_token_hash=row.session_token_hash,
        issued_at=row.issued_at,
        expires_at=row.expires_at,
        max_signatures=row.max_signatures,
        signature_count=row.signature_count,
    )
