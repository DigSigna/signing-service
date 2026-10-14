from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    mode: Mapped[str] = mapped_column(String(20), nullable=True)
    hsm_slot_id: Mapped[str] = mapped_column(String(36), nullable=True)
