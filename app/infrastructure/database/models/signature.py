from datetime import datetime

from sqlalchemy import LargeBinary, String
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base


class Signature(Base):
    """migrations/003_signing_workflow.up.sql + 016 (tsa_* columns,
    ADR-002/signing-plan.md point 3) + 025 (signature_format widened
    for PAdES-B/PAdES-T — the original migration-003 ENUM only had
    PKCS7/CMS/RAW/JWS)."""

    __tablename__ = "signatures"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    signing_request_id: Mapped[str] = mapped_column(String(36), nullable=False)
    key_id: Mapped[str] = mapped_column(String(36), nullable=False)
    certificate_id: Mapped[str] = mapped_column(String(36), nullable=True)
    signature_value: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    signature_format: Mapped[str] = mapped_column(String(10), nullable=False)
    signing_time: Mapped[datetime] = mapped_column(nullable=False)
    tsa_token: Mapped[bytes] = mapped_column(LargeBinary, nullable=True)
    tsa_provider: Mapped[str] = mapped_column(String(50), nullable=True)
    tsa_sealed_at: Mapped[datetime] = mapped_column(nullable=True)
