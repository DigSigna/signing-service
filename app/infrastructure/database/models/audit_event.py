from sqlalchemy import String
from sqlalchemy.orm import Mapped, mapped_column
from .base import Base


class AuditEvent(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    correlation_id: Mapped[str] = mapped_column(String(36), nullable=True)
    session_id: Mapped[str] = mapped_column(String(36), nullable=True)
    request_id: Mapped[str] = mapped_column(String(36), nullable=True)

    service_name: Mapped[str] = mapped_column(String(255), nullable=False)
    event_type: Mapped[str] = mapped_column(String(255), nullable=False)
    event_action: Mapped[str] = mapped_column(String(255), nullable=False)

    organization_id: Mapped[str] = mapped_column(String(36), nullable=True)
    user_id: Mapped[str] = mapped_column(String(36), nullable=False)
    tenant_id: Mapped[str] = mapped_column(String(36), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(36), nullable=True)
    resource_type: Mapped[str] = mapped_column(String(255), nullable=True)

    actor_type: Mapped[str] = mapped_column(String(50), nullable=True)
    actor_id: Mapped[str] = mapped_column(String(36), nullable=True)

    success: Mapped[bool] = mapped_column(nullable=False)
    status_code: Mapped[str] = mapped_column(String(50), nullable=True)
    error_message: Mapped[str] = mapped_column(String(1024), nullable=True)

    duration_ms: Mapped[int] = mapped_column(nullable=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[str] = mapped_column(String(512), nullable=True)

    metadata_json: Mapped[str] = mapped_column("metadata", String(2048), nullable=True)
