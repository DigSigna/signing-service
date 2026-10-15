from datetime import datetime

from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base


class SigningRequest(Base):
    """migrations/003_signing_workflow.up.sql. Pre-dates the Owner(type,
    id) polymorphic pattern `certificates`/`crypto_keys` use — user_id/
    organization_id are real FKs to `users`/`organizations`, not a loose
    owner_type/owner_id pair. Only ever populated for a USER- or
    ORGANIZATION-owned certificate (the only owner types that hold a
    signing PIN); see SQLAlchemySignatureRecordRepository."""

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
