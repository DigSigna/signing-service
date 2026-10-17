from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

from py_common.auth.identity_context import IdentityContext


@dataclass
class SignIncrementCommand:
    signing_request_id: UUID
    certificate_id: UUID
    pin: Optional[str] = None
    session_token: Optional[str] = None


@dataclass
class SignIncrementResult:
    signing_request_id: UUID
    signature_id: UUID
    certificate_id: UUID
    status: str
    signers_number: int
    signatures_count: int
    signature_format: str
    signing_time: datetime
    tsa_provider: Optional[str]
    tsa_sealed_at: Optional[datetime]
    session_token: Optional[str]
    session_expires_at: Optional[datetime]


class SignIncrementUseCase(ABC):
    @abstractmethod
    async def execute(
        self,
        command: SignIncrementCommand,
        identity_context: IdentityContext,
        bearer_token: str,
    ) -> SignIncrementResult:
        """Appends one incremental signature to an existing
        signing_request (signing-plan.md point 4) — reads its current
        document_blob, signs over it, and advances signatures_count.
        When this call completes the request (signatures_count reaches
        signers_number), it also attempts TSA sealing in the same
        request and marks status COMPLETED. Raises NotFoundError (bad
        id or wrong tenant), SigningRequestNotPendingError (already
        COMPLETED/CANCELLED/EXPIRED/FAILED),
        SigningRequestConflictError (lost a concurrency race — retry),
        or any of the certificate/PIN/HSM errors SignDocumentUseCase
        documents."""
        raise NotImplementedError
