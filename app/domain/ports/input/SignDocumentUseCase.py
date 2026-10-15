from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

from app.domain.valueobjects.IdentityContext import IdentityContext


@dataclass
class SignDocumentCommand:
    certificate_id: UUID
    document: bytes
    document_name: Optional[str] = None
    pin: Optional[str] = None
    session_token: Optional[str] = None


@dataclass
class SignDocumentResult:
    signing_request_id: UUID
    signature_id: UUID
    certificate_id: UUID
    document_hash: str
    signature_value: bytes
    signature_format: str
    signing_time: datetime
    # None on an idempotency replay (see SignDocumentUseCaseImpl): the
    # session token isn't persisted anywhere this service can look it
    # back up by signing_request_id, only its hash, keyed by the token
    # itself.
    session_token: Optional[str]
    session_expires_at: Optional[datetime]


class SignDocumentUseCase(ABC):
    @abstractmethod
    async def execute(
        self,
        command: SignDocumentCommand,
        identity_context: IdentityContext,
        bearer_token: str,
    ) -> SignDocumentResult:
        """Hashes the document, fetches and validates the signer's
        certificate via certificate-service, resolves a signing-PIN
        session (reusing a valid one or verifying the PIN to start a new
        one — ADR-005), asks hsm-service to sign, and records the result.
        Raises NotFoundError/CertificateChainInvalidError/
        CertificateServiceUnavailableError, SigningPinInvalidError/
        SigningPinLockedError/SigningPinNotSetError/
        SigningPinNotApplicableError, or HsmError, depending on where it
        fails — a failure in any of these never reaches hsm-service's
        actual signing call."""
        raise NotImplementedError
