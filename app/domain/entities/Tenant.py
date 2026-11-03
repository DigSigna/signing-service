from dataclasses import dataclass, field
from uuid import UUID
from datetime import datetime
from typing import Optional

from ..valueobjects.TenantMode import TenantMode


@dataclass
class Tenant:
    id: UUID
    name: str
    mode: TenantMode = TenantMode.MANAGED
    hsm_slot_id: Optional[str] = None
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
