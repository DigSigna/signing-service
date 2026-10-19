"""POST /api/v1/signing-requests use case (signing-plan.md point 4.2).

Idempotent via the same claim/replay helper SignDocumentUseCaseImpl
uses: request_id comes from the client's X-Request-ID header. Exactly
one claim for this whole call — see signing_core's module docstring for
why composing more than one claim per client request is unsafe here.
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
from app.application.services.signing_core import create_signing_request_row
from py_common.core.request_context import get_context_values
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.ports.input.CreateSigningRequestUseCase import (
    CreateSigningRequestCommand,
    CreateSigningRequestResult,
    CreateSigningRequestUseCase,
)
from py_common.audit import AuditEventDispatcher
from app.domain.ports.output.SigningRequestRepository import (
    SigningRequestRepository,
)
from py_common.auth.identity_context import IdentityContext

_SERVICE_NAME = "signing-service"
_RESOURCE_TYPE = "signing_request"
_OPERATION = "CREATE_SIGNING_REQUEST"


class CreateSigningRequestUseCaseImpl(CreateSigningRequestUseCase):
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
        command: CreateSigningRequestCommand,
        identity_context: IdentityContext,
        bearer_token: str,
    ) -> CreateSigningRequestResult:
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

            request = await create_signing_request_row(
                self._signing_request_repo,
                tenant_id=tenant_id,
                document=command.document,
                document_name=command.document_name,
                signers_number=command.signers_number,
                identity_context=identity_context,
            )
            return _to_result(request)
        except BaseException as exc:
            error = exc
            raise
        finally:
            resource_id = str(request.id) if request else None
            if claimed:
                await finish_idempotency_claim(
                    self._idempotency_repo,
                    str(tenant_id),
                    request_id,
                    resource_id,
                    error,
                )
            await self._audit(identity_context, resource_id, start, error)

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


def _to_result(request: SigningRequest) -> CreateSigningRequestResult:
    return CreateSigningRequestResult(
        signing_request_id=request.id,
        status=request.status.value,
        signers_number=request.signers_number,
        signatures_count=request.signatures_count,
        created_at=request.created_at,
    )
