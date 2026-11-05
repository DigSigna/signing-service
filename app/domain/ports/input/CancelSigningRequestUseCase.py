from abc import ABC, abstractmethod
from dataclasses import dataclass
from uuid import UUID

from py_common.auth.identity_context import IdentityContext


@dataclass
class CancelSigningRequestCommand:
    signing_request_id: UUID


@dataclass
class CancelSigningRequestResult:
    signing_request_id: UUID
    status: str


class CancelSigningRequestUseCase(ABC):
    @abstractmethod
    async def execute(
        self,
        command: CancelSigningRequestCommand,
        identity_context: IdentityContext,
    ) -> CancelSigningRequestResult:
        """Cancels a single-signer (signers_number == 1) signing_request
        while it is still PENDING (no signature applied yet — once the
        sole signer signs, a signers_number=1 request goes straight to
        COMPLETED, so there is no partially-signed window to cancel out
        of). Only the caller identified by signing_requests.user_id may
        cancel their own request.

        Raises NotFoundError (bad id or wrong tenant),
        SigningRequestNotCancellableError (signers_number > 1, or
        user_id IS NULL — ORGANIZATION-owned requests have no single
        identifiable owner and are out of scope for this MVP slice),
        AuthorizationError (caller isn't the request's own user_id),
        SigningRequestNotPendingError (already
        COMPLETED/CANCELLED/EXPIRED/FAILED), or SigningRequestConflictError
        (lost the optimistic-concurrency race — retry)."""
        raise NotImplementedError
