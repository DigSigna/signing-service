"""POST /signing-requests/{id}/sign use case (signing-plan.md point
4.2) — replaces the single-shot /sign endpoint's exclusivity: a
signing_request can now take more than one of these calls, one per
signer, before it's COMPLETED.

Idempotent via the same claim/replay helper used throughout this
service: request_id comes from the client's X-Request-ID header.
resource_id is the *signature* id, not the signing_request id — a
signing_request can own more than one signature since migration 026,
so the signing_request id alone can't identify which signature a
replay should return.
"""

from __future__ import annotations

import time
from typing import Optional
from uuid import UUID

from app.application.services.audit_helpers import build_audit_data
from app.application.services.idempotency import (
    claim_idempotency_key,
    finish_idempotency_claim,
)
from app.application.services.signing_core import perform_signature_step
from app.domain.entities.Signature import Signature
from app.domain.ports.input.SignIncrementUseCase import (
    SignIncrementCommand,
    SignIncrementResult,
    SignIncrementUseCase,
)
from app.domain.ports.output.AuditEventDispatcher import AuditEventDispatcher
from app.domain.ports.output.CertificateClient import CertificateClient
from app.domain.ports.output.HSMClient import HSMClient
from app.domain.ports.output.PAdESSigner import PAdESSigner
from app.domain.ports.output.SigningPinVerifier import SigningPinVerifier
from app.domain.ports.output.SigningRequestRepository import (
    SigningRequestRepository,
)
from app.domain.ports.output.SigningSessionRepository import SigningSessionRepository
from app.domain.valueobjects.IdentityContext import IdentityContext
from app.infrastructure.external.certificate.intermediate_cache import (
    IntermediateCertificateCache,
)
from app.core.request_context import get_context_values

_SERVICE_NAME = "signing-service"
_RESOURCE_TYPE = "signature"
_OPERATION = "SIGN_INCREMENT"


class SignIncrementUseCaseImpl(SignIncrementUseCase):
    def __init__(
        self,
        signing_request_repo: SigningRequestRepository,
        certificate_client: CertificateClient,
        pin_verifier: SigningPinVerifier,
        session_repo: SigningSessionRepository,
        hsm_client: HSMClient,
        pades_signer: PAdESSigner,
        intermediate_cache: IntermediateCertificateCache,
        idempotency_repo=None,
        audit_dispatcher: Optional[AuditEventDispatcher] = None,
        *,
        session_ttl_minutes: int = 20,
        session_max_signatures: int = 0,
    ):
        self._signing_request_repo = signing_request_repo
        self._certificate_client = certificate_client
        self._pin_verifier = pin_verifier
        self._session_repo = session_repo
        self._hsm_client = hsm_client
        self._pades_signer = pades_signer
        self._intermediate_cache = intermediate_cache
        self._idempotency_repo = idempotency_repo
        self._audit_dispatcher = audit_dispatcher
        self._session_ttl_minutes = session_ttl_minutes
        self._session_max_signatures = session_max_signatures

    async def execute(
        self,
        command: SignIncrementCommand,
        identity_context: IdentityContext,
        bearer_token: str,
    ) -> SignIncrementResult:
        tenant_id = UUID(identity_context.tenant_id)
        request_id = get_context_values().request_id
        start = time.monotonic()
        signature: Optional[Signature] = None
        session_token: Optional[str] = None
        session_expires_at = None
        error: Optional[BaseException] = None
        claimed = False

        try:
            claim = await claim_idempotency_key(
                self._idempotency_repo, str(tenant_id), request_id, _OPERATION
            )
            claimed = claim.claimed
            if claim.existing_resource_id:
                existing = await self._signing_request_repo.find_signature_by_id(
                    UUID(claim.existing_resource_id)
                )
                if existing is not None:
                    owner = await self._signing_request_repo.find_by_id(
                        existing.signing_request_id
                    )
                    return _to_result(
                        existing,
                        owner,
                        session_token=None,
                        session_expires_at=None,
                    )

            step = await perform_signature_step(
                signing_request_repo=self._signing_request_repo,
                certificate_client=self._certificate_client,
                pin_verifier=self._pin_verifier,
                session_repo=self._session_repo,
                hsm_client=self._hsm_client,
                pades_signer=self._pades_signer,
                intermediate_cache=self._intermediate_cache,
                tenant_id=tenant_id,
                signing_request_id=command.signing_request_id,
                certificate_id=command.certificate_id,
                pin=command.pin,
                session_token_in=command.session_token,
                bearer_token=bearer_token,
                session_ttl_minutes=self._session_ttl_minutes,
                session_max_signatures=self._session_max_signatures,
            )
            signature = step.signature
            session_token = step.session_token
            session_expires_at = step.session_expires_at
            return _to_result(
                signature,
                step.signing_request,
                session_token=session_token,
                session_expires_at=session_expires_at,
            )
        except BaseException as exc:
            error = exc
            raise
        finally:
            resource_id = str(signature.id) if signature else None
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


def _to_result(
    signature: Signature,
    signing_request,
    *,
    session_token: Optional[str],
    session_expires_at,
) -> SignIncrementResult:
    return SignIncrementResult(
        signing_request_id=signature.signing_request_id,
        signature_id=signature.id,
        certificate_id=signature.certificate_id,
        status=signing_request.status.value,
        signers_number=signing_request.signers_number,
        signatures_count=signing_request.signatures_count,
        signature_format=signature.signature_format,
        signing_time=signature.signing_time,
        tsa_provider=signature.tsa_provider,
        tsa_sealed_at=signature.tsa_sealed_at,
        session_token=session_token,
        session_expires_at=session_expires_at,
    )
