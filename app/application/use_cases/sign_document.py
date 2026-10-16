"""POST /api/v1/sign use case — the single-signer convenience endpoint
(signing-plan.md point 4.3: "decisión de conveniencia, no bloqueante").
Internally this is sugar over the N-signer flow: it creates a
signing_request with signers_number=1 and immediately performs the one
signature it needs, via the same core helpers
POST /signing-requests and POST /signing-requests/{id}/sign use
(app/application/services/signing_core.py) — never a second,
independent code path for the same two tables.

Exactly one idempotency claim covers both inner steps (see
signing_core's module docstring for why two claims under the same
request_id would be unsafe): request_id comes from the client's
X-Request-ID header. resource_id is the signature id, not the
signing_request id, consistent with the new /signing-requests/{id}/sign
endpoint.
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
from app.application.services.signing_core import (
    create_signing_request_row,
    perform_signature_step,
)
from app.core.request_context import get_context_values
from app.domain.entities.Signature import Signature
from app.domain.ports.input.SignDocumentUseCase import (
    SignDocumentCommand,
    SignDocumentResult,
    SignDocumentUseCase,
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

_SERVICE_NAME = "signing-service"
_RESOURCE_TYPE = "signature"
_OPERATION = "SIGN_DOCUMENT"


class SignDocumentUseCaseImpl(SignDocumentUseCase):
    def __init__(
        self,
        certificate_client: CertificateClient,
        pin_verifier: SigningPinVerifier,
        session_repo: SigningSessionRepository,
        signing_request_repo: SigningRequestRepository,
        hsm_client: HSMClient,
        pades_signer: PAdESSigner,
        intermediate_cache: IntermediateCertificateCache,
        idempotency_repo=None,
        audit_dispatcher: Optional[AuditEventDispatcher] = None,
        *,
        session_ttl_minutes: int = 20,
        session_max_signatures: int = 0,
    ):
        self._certificate_client = certificate_client
        self._pin_verifier = pin_verifier
        self._session_repo = session_repo
        self._signing_request_repo = signing_request_repo
        self._hsm_client = hsm_client
        self._pades_signer = pades_signer
        self._intermediate_cache = intermediate_cache
        self._idempotency_repo = idempotency_repo
        self._audit_dispatcher = audit_dispatcher
        self._session_ttl_minutes = session_ttl_minutes
        self._session_max_signatures = session_max_signatures

    async def execute(
        self,
        command: SignDocumentCommand,
        identity_context: IdentityContext,
        bearer_token: str,
    ) -> SignDocumentResult:
        tenant_id = UUID(identity_context.tenant_id)
        request_id = get_context_values().request_id
        start = time.monotonic()
        signature: Optional[Signature] = None
        session_token: Optional[str] = None
        session_expires_at = None
        document_hash: Optional[str] = None
        signed_document: Optional[bytes] = None
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
                    # The session token used for the original call isn't
                    # recoverable here — it's looked up by its own hash,
                    # never by signing_request_id, and only the hash is
                    # persisted. A replay returns the signature correctly
                    # but without a session_token; the caller must fall
                    # back to a PIN on its next call in that case.
                    return _to_result(
                        existing,
                        owner.document_hash,
                        owner.document_blob,
                        session_token=None,
                        session_expires_at=None,
                    )

            signing_request = await create_signing_request_row(
                self._signing_request_repo,
                tenant_id=tenant_id,
                document=command.document,
                document_name=command.document_name,
                signers_number=1,
                identity_context=identity_context,
            )
            document_hash = signing_request.document_hash

            step = await perform_signature_step(
                signing_request_repo=self._signing_request_repo,
                certificate_client=self._certificate_client,
                pin_verifier=self._pin_verifier,
                session_repo=self._session_repo,
                hsm_client=self._hsm_client,
                pades_signer=self._pades_signer,
                intermediate_cache=self._intermediate_cache,
                tenant_id=tenant_id,
                signing_request_id=signing_request.id,
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
            signed_document = step.signing_request.document_blob
            return _to_result(
                signature,
                document_hash,
                signed_document,
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

    async def _audit(
        self,
        identity_context: IdentityContext,
        resource_id: Optional[str],
        start: float,
        error: Optional[BaseException],
    ) -> None:
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
    document_hash: str,
    signed_document: bytes,
    *,
    session_token: Optional[str],
    session_expires_at,
) -> SignDocumentResult:
    return SignDocumentResult(
        signing_request_id=signature.signing_request_id,
        signature_id=signature.id,
        certificate_id=signature.certificate_id,
        document_hash=document_hash,
        signature_value=signed_document,
        signature_format=signature.signature_format,
        signing_time=signature.signing_time,
        tsa_provider=signature.tsa_provider,
        tsa_sealed_at=signature.tsa_sealed_at,
        session_token=session_token,
        session_expires_at=session_expires_at,
    )
