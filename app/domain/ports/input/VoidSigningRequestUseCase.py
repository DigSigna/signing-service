from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID

from py_common.auth.identity_context import IdentityContext


@dataclass
class VoidSigningRequestCommand:
    signing_request_id: UUID  # the OLD, already-signed request
    superseded_by_signing_request_id: UUID  # the NEW one that replaces it
    reason: str


@dataclass
class VoidSigningRequestResult:
    signing_request_id: UUID
    status: str
    superseded_by_signing_request_id: UUID
    voided_at: datetime
    void_reason: Optional[str]


class VoidSigningRequestUseCase(ABC):
    @abstractmethod
    async def execute(
        self,
        command: VoidSigningRequestCommand,
        identity_context: IdentityContext,
    ) -> VoidSigningRequestResult:
        """Marks a COMPLETED signing_request as superseded by a newer one
        (Caso 3, Opción B) — a purely business-level annotation. The
        cryptographic signature already applied to the OLD document is
        never invalidated (that's a real property of the signature, not
        a bug), certificate-service is never touched, and `status` never
        changes (stays COMPLETED).

        Deliberately does NOT verify that
        command.superseded_by_signing_request_id actually exists yet —
        the client may fix and sign the replacement first and void the
        old one after, or the other way around; either order is
        supported.

        Raises NotFoundError (bad id or wrong tenant),
        SigningRequestNotCompletedError (the OLD request never reached
        COMPLETED — a still-PENDING request should be cancelled instead,
        via CancelSigningRequestUseCase), AuthorizationError (caller is
        neither the request's own user_id nor a tenant/organization
        admin for it), or SigningRequestConflictError (lost the
        optimistic-concurrency race — retry)."""
        raise NotImplementedError
