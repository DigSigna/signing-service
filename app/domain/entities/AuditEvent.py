from dataclasses import dataclass
from uuid import UUID
from typing import Optional

from ..valueobjects.ActorType import ActorType


@dataclass
class AuditEvent:
    user_id: UUID
    tenant_id: UUID
    id: UUID
    correlation_id: Optional[UUID] = None
    session_id: Optional[UUID] = None
    request_id: Optional[UUID] = None

    service_name: str = ""
    event_type: str = ""
    event_action: str = ""

    organization_id: Optional[UUID] = None
    resource_id: Optional[UUID] = None
    resource_type: Optional[str] = None

    actor_type: Optional[ActorType] = None
    actor_id: Optional[UUID] = None

    success: bool = True
    status_code: Optional[str] = None
    error_message: Optional[str] = None

    duration_ms: Optional[int] = None
    ip_address: Optional[str] = None
    user_agent: Optional[str] = None

    metadata: Optional[dict] = None
