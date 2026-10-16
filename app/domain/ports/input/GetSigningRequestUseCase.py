from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

from app.domain.valueobjects.IdentityContext import IdentityContext


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
