from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

from py_common.auth.identity_context import IdentityContext


@dataclass
class GetSigningRequestResult:
    signing_request_id: UUID
    status: str
    signers_number: int
    signatures_count: int
    created_at: datetime
    completed_at: Optional[datetime]
    # Only set when status == COMPLETED (signing-plan.md point 4.2) —
    # the sole supported way to retrieve the signed document (point 5).
    document: Optional[bytes]
    # Caso 3, Opción B (migration 031) — always surfaced regardless of
    # status, never gated like `document`: these three are only ever
    # populated once VoidSigningRequestUseCase has run, independent of
    # whether the caller can also read the signed document.
    superseded_by_signing_request_id: Optional[UUID] = None
    voided_at: Optional[datetime] = None
    void_reason: Optional[str] = None


class GetSigningRequestUseCase(ABC):
    @abstractmethod
    async def execute(
        self,
        signing_request_id: UUID,
        identity_context: IdentityContext,
    ) -> GetSigningRequestResult:
        """Read-only, no side effects. Raises NotFoundError for a bad
        id or one belonging to another tenant."""
        raise NotImplementedError
