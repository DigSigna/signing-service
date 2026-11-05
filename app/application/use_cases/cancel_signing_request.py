"""POST /signing-requests/{id}/cancel use case (Caso 2 de negocio): lets
the sole signer of a single-signer (signers_number == 1) signing_request
abandon it before signing, transitioning PENDING -> CANCELLED.

Deliberately narrow MVP scope (business decision, not an oversight):
- Only signers_number == 1 requests are cancellable here. A multi-signer
  request would need to know which of the N signers already signed
  (today's `signatures` rows aren't easily queryable that way) — left as
  a future extension, not built here.
- Only the request's own user_id may cancel it. ORGANIZATION-owned
  requests (user_id IS NULL) have no single identifiable owner and are
  out of scope — rejected explicitly, never resolved via organization_id.

Idempotent via the same claim/replay helper used throughout this
service: request_id comes from the client's X-Request-ID header.
resource_id is the signing_request id itself — cancel never creates a
new resource.
"""

from __future__ import annotations

import time
from typing import Optional
from uuid import UUID

from app.application.services.audit_helpers import build_audit_data
from py_common.idempotency import (
    claim_idempotency_key,
    finish_idempotency_claim,
)
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.exceptions.domain_errors import (
    AuthorizationError,
    NotFoundError,
    SigningRequestConflictError,
    SigningRequestNotCancellableError,
    SigningRequestNotPendingError,
)
from app.domain.ports.input.CancelSigningRequestUseCase import (
    CancelSigningRequestCommand,
    CancelSigningRequestResult,
    CancelSigningRequestUseCase,
)
from app.domain.ports.output.SigningRequestRepository import (
    SigningRequestRepository,
)
from app.domain.valueobjects.SigningRequestStatus import SigningRequestStatus
from py_common.audit import AuditEventDispatcher
from py_common.auth.identity_context import IdentityContext
from py_common.core.request_context import get_context_values

_SERVICE_NAME = "signing-service"
_RESOURCE_TYPE = "signing_request"
_OPERATION = "CANCEL_SIGNING_REQUEST"


class CancelSigningRequestUseCaseImpl(CancelSigningRequestUseCase):
    def __init__(
        self,
        signing_request_repo: SigningRequestRepository,
        idempotency_repo=None,
        audit_dispatcher: Optional[AuditEventDispatcher] = None,
    ):
        self._signing_request_repo = signing_request_repo
        self._idempotency_repo = idempotency_repo
        self._audit_dispatcher = audit_dispatcher

    async def execute(
        self,
        command: CancelSigningRequestCommand,
        identity_context: IdentityContext,
    ) -> CancelSigningRequestResult:
        tenant_id = UUID(identity_context.tenant_id)
        request_id = get_context_values().request_id
        start = time.monotonic()
        request: Optional[SigningRequest] = None
        error: Optional[BaseException] = None
        claimed = False

        try:
            claim = await claim_idempotency_key(
                self._idempotency_repo, str(tenant_id), request_id, _OPERATION
            )
            claimed = claim.claimed
            if claim.existing_resource_id:
                existing = await self._signing_request_repo.find_by_id(
                    UUID(claim.existing_resource_id)
                )
                if existing is not None:
                    return _to_result(existing)

            request = await self._cancel(
                command.signing_request_id, tenant_id, identity_context
            )
            return _to_result(request)
        except BaseException as exc:
            error = exc
            raise
        finally:
            resource_id = (
                str(request.id) if request else str(command.signing_request_id)
            )
            if claimed:
                await finish_idempotency_claim(
                    self._idempotency_repo,
                    str(tenant_id),
                    request_id,
                    resource_id,
                    error,
                )
            await self._audit(identity_context, resource_id, start, error)

    async def _cancel(
        self,
        signing_request_id: UUID,
        tenant_id: UUID,
        identity_context: IdentityContext,
    ) -> SigningRequest:
        signing_request = await self._signing_request_repo.find_by_id(
            signing_request_id
        )
        if signing_request is None or signing_request.tenant_id != tenant_id:
            # Same NotFoundError for "doesn't exist" and "belongs to
            # another tenant" — never leak existence across tenants.
            raise NotFoundError(
                "Signing request not found",
                entity="SigningRequest",
                entity_id=str(signing_request_id),
            )

        if signing_request.signers_number != 1:
            raise SigningRequestNotCancellableError(
                "Only single-signer (signers_number == 1) signing requests "
                "can be cancelled through this endpoint",
                signing_request_id=str(signing_request_id),
            )

        if signing_request.user_id is None:
            raise SigningRequestNotCancellableError(
                "This signing request has no single identifiable owner "
                "(organization-owned) — cancellation is out of scope",
                signing_request_id=str(signing_request_id),
            )

        if str(signing_request.user_id) != identity_context.user_id:
            raise AuthorizationError(
                "Only the signing request's own signer may cancel it",
                details={"signing_request_id": str(signing_request_id)},
            )

        if signing_request.status != SigningRequestStatus.PENDING:
            raise SigningRequestNotPendingError(
                "Signing request is not pending a signature",
                current_status=signing_request.status.value,
            )

        ok = await self._signing_request_repo.cancel(
            signing_request_id=signing_request_id,
            expected_version=signing_request.version,
        )
        if not ok:
            raise SigningRequestConflictError(
                "The signing request changed concurrently — retry the request"
            )

        signing_request.status = SigningRequestStatus.CANCELLED
        signing_request.version += 1
        return signing_request

    async def _audit(self, identity_context, resource_id, start, error) -> None:
        if self._audit_dispatcher is None:
            return
        data = build_audit_data(
            service_name=_SERVICE_NAME,
            resource_type=_RESOURCE_TYPE,
            operation=_OPERATION,
            resource_id=resource_id,
            identity_context=identity_context,
            start=start,
            error=error,
        )
        await self._audit_dispatcher.audit_operation(None, data, identity_context)


def _to_result(request: SigningRequest) -> CancelSigningRequestResult:
    return CancelSigningRequestResult(
        signing_request_id=request.id,
        status=request.status.value,
    )
