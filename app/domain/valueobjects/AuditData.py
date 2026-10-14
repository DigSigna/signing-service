from dataclasses import dataclass
from typing import Any, Dict


@dataclass(frozen=True)
class AuditData:
    service_name: str
    event_type: str
    operation: str
    resource_id: str
    resource_type: str
    actor_type: str
    success: bool
    status_code: str
    err_msg: str
    duration_ms: int
    metadata: Dict[str, Any]
