from datetime import datetime
from typing import Optional

from sqlalchemy import Integer, LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base


class SigningRequest(Base):
    """migrations/003_signing_workflow.up.sql + 026 (signers_number/
    signatures_count/document_blob/completed_at/version — signing-plan.
    md point 4, N-signer support). Pre-dates the Owner(type, id)
    polymorphic pattern `certificates`/`crypto_keys` use — user_id/
    organization_id are real FKs to `users`/`organizations`, not a loose
    owner_type/owner_id pair. Only ever populated for a USER- or
    ORGANIZATION-owned certificate (the only owner types that hold a
    signing PIN); see SQLAlchemySigningRequestRepository.

    key_id is legacy (pre-026): a multi-signer request has a different
    certificate/key per signer, recorded on each `signatures` row
    instead, so new rows always write key_id=NULL here.

    superseded_by_signing_request_id/voided_at/void_reason are migration
    031 (Caso 3, Opción B) — a self-referencing FK, matching the real
    FK convention already on organization_id/user_id/key_id in this same
    table (all ON DELETE SET NULL)."""

    __tablename__ = "signing_requests"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    organization_id: Mapped[str] = mapped_column(String(36), nullable=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=True)
    key_id: Mapped[str] = mapped_column(String(36), nullable=True)
    document_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    document_name: Mapped[str] = mapped_column(String(255), nullable=True)
    hash_algorithm: Mapped[str] = mapped_column(String(10), nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False)
    created_at: Mapped[datetime] = mapped_column(nullable=True)
    signers_number: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    signatures_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    document_blob: Mapped[Optional[bytes]] = mapped_column(LargeBinary, nullable=True)
    completed_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    version: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    superseded_by_signing_request_id: Mapped[Optional[str]] = mapped_column(
        String(36), nullable=True
    )
    voided_at: Mapped[Optional[datetime]] = mapped_column(nullable=True)
    void_reason: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
