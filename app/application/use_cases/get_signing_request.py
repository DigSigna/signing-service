"""GET /signing-requests/{id} use case (signing-plan.md point 4.2) —
read-only, no side effects, never triggered by anything but the
client's own call. The signed document is only returned once the
request is COMPLETED; it is read straight from document_blob, never
reconstructed from `signatures` (point 5)."""

from __future__ import annotations

from uuid import UUID

from app.domain.exceptions.domain_errors import NotFoundError
from app.domain.ports.input.GetSigningRequestUseCase import (
    GetSigningRequestResult,
    GetSigningRequestUseCase,
)
from app.domain.ports.output.SigningRequestRepository import (
    SigningRequestRepository,
)
from py_common.auth.identity_context import IdentityContext
from app.domain.valueobjects.SigningRequestStatus import SigningRequestStatus


class GetSigningRequestUseCaseImpl(GetSigningRequestUseCase):
    def __init__(self, signing_request_repo: SigningRequestRepository):
        self._signing_request_repo = signing_request_repo

    async def execute(
        self,
        signing_request_id: UUID,
        identity_context: IdentityContext,
    ) -> GetSigningRequestResult:
        tenant_id = UUID(identity_context.tenant_id)
        request = await self._signing_request_repo.find_by_id(signing_request_id)
        if request is None or request.tenant_id != tenant_id:
            raise NotFoundError(
                "Signing request not found",
                entity="SigningRequest",
                entity_id=str(signing_request_id),
            )

        is_completed = request.status == SigningRequestStatus.COMPLETED
        return GetSigningRequestResult(
            signing_request_id=request.id,
            status=request.status.value,
            signers_number=request.signers_number,
            signatures_count=request.signatures_count,
            created_at=request.created_at,
            completed_at=request.completed_at,
            document=request.document_blob if is_completed else None,
            superseded_by_signing_request_id=request.superseded_by_signing_request_id,
            voided_at=request.voided_at,
            void_reason=request.void_reason,
        )
