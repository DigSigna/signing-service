from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

from app.domain.valueobjects.IdentityContext import IdentityContext


@dataclass
class CreateSigningRequestCommand:
    document: bytes
    document_name: Optional[str]
    signers_number: int


@dataclass
class CreateSigningRequestResult:
    signing_request_id: UUID
    status: str
    signers_number: int
    signatures_count: int
    created_at: datetime


class CreateSigningRequestUseCase(ABC):
    @abstractmethod
    async def execute(
        self,
        command: CreateSigningRequestCommand,
        identity_context: IdentityContext,
        bearer_token: str,
    ) -> CreateSigningRequestResult:
        """Validates `document` is a PDF (signing-plan.md point 2),
        stores it as the signing_request's initial document_blob, and
        returns its id. Raises ValidationError (field="document_b64")
        if the content isn't a well-formed PDF, DuplicateRequestError on
        a concurrent retry of the same idempotency key still in
        flight."""
        raise NotImplementedError
