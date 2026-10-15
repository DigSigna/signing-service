from datetime import datetime

from sqlalchemy import DateTime, Integer, String
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base


class SigningPinSession(Base):
    __tablename__ = "signing_pin_sessions"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    certificate_id: Mapped[str] = mapped_column(String(36), nullable=False)
    session_token_hash: Mapped[str] = mapped_column(String(64), nullable=False)
    issued_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=False)
    max_signatures: Mapped[int] = mapped_column(Integer, nullable=True)
    signature_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
