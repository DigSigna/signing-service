"""POST /signing-requests/{id}/void use case (Caso 3, Opción B): marks a
COMPLETED signing_request as superseded by a newer one. A purely
business-level annotation — the OLD document's signature was real and
stays cryptographically valid; this only records "not current anymore,
replaced by <superseded_by_signing_request_id>". Never touches
certificate-service, never revokes anything, never changes `status`
(stays COMPLETED).

Idempotent via the same claim/replay helper used throughout this
service: request_id comes from the client's X-Request-ID header.
resource_id is the OLD signing_request's id — void never creates a new
resource.
"""

from __future__ import annotations

import time
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID

from app.application.services.audit_helpers import build_audit_data
from app.application.services.signing_request_access import is_authorized_to_void
from py_common.idempotency import (
    claim_idempotency_key,
    finish_idempotency_claim,
)
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.exceptions.domain_errors import (
    AuthorizationError,
    NotFoundError,
    SigningRequestConflictError,
    SigningRequestNotCompletedError,
)
from app.domain.ports.input.VoidSigningRequestUseCase import (
    VoidSigningRequestCommand,
    VoidSigningRequestResult,
    VoidSigningRequestUseCase,
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
_OPERATION = "VOID_SIGNING_REQUEST"


class VoidSigningRequestUseCaseImpl(VoidSigningRequestUseCase):
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
        command: VoidSigningRequestCommand,
        identity_context: IdentityContext,
    ) -> VoidSigningRequestResult:
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

            request = await self._void(command, tenant_id, identity_context)
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

    async def _void(
        self,
        command: VoidSigningRequestCommand,
        tenant_id: UUID,
        identity_context: IdentityContext,
    ) -> SigningRequest:
        signing_request = await self._signing_request_repo.find_by_id(
            command.signing_request_id
        )
        if signing_request is None or signing_request.tenant_id != tenant_id:
            raise NotFoundError(
                "Signing request not found",
                entity="SigningRequest",
                entity_id=str(command.signing_request_id),
            )

        if signing_request.status != SigningRequestStatus.COMPLETED:
            raise SigningRequestNotCompletedError(
                "Only a COMPLETED signing request can be marked superseded",
                current_status=signing_request.status.value,
            )

        if not is_authorized_to_void(identity_context, signing_request):
            raise AuthorizationError(
                "Only the signing request's own signer or a tenant/"
                "organization admin may void it",
                details={"signing_request_id": str(command.signing_request_id)},
            )

        voided_at = datetime.now(timezone.utc)
        ok = await self._signing_request_repo.void(
            signing_request_id=command.signing_request_id,
            expected_version=signing_request.version,
            superseded_by_signing_request_id=command.superseded_by_signing_request_id,
            void_reason=command.reason,
            voided_at=voided_at,
        )
        if not ok:
            raise SigningRequestConflictError(
                "The signing request changed concurrently — retry the request"
            )

        signing_request.superseded_by_signing_request_id = (
            command.superseded_by_signing_request_id
        )
        signing_request.voided_at = voided_at
        signing_request.void_reason = command.reason
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


def _to_result(request: SigningRequest) -> VoidSigningRequestResult:
    return VoidSigningRequestResult(
        signing_request_id=request.id,
        status=request.status.value,
        superseded_by_signing_request_id=request.superseded_by_signing_request_id,
        voided_at=request.voided_at,
        void_reason=request.void_reason,
    )
