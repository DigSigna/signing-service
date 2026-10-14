"""Equivalente a hsm-service's entities.IdempotencyRecord
(internal/domain/entities/idempotency_record.go)."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional


@dataclass
class IdempotencyRecord:
    """Tracks a claimed (tenant_id, request_id) pair for a mutating
    operation. resource_id is None while the original request is still
    being processed, and set once it completes successfully."""

    id: str
    tenant_id: str
    request_id: str
    operation: str
    resource_id: Optional[str] = None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None
