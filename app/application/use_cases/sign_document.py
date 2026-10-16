"""POST /api/v1/sign use case.

Order of operations, and why: hash the document (for our own record,
`signing_requests.document_hash` — not what's actually signed, see the
PAdES step below) -> fetch the certificate -> validate its chain ->
resolve a signing-PIN session (ADR-005) -> only then produce the PAdES
signature. Each step can fail the whole request before the next one
runs, and in particular before hsm-service is ever called — a broken
chain or a wrong/locked PIN must never reach the HSM layer.

Idempotent via the same claim/replay helper certificate-service's
mutating use cases use (app/application/services/idempotency.py):
request_id comes from the client's X-Request-ID header (see
RequestContextMiddleware) via get_context_values().

Real PAdES signing (signing-plan.md point 1) via PAdESSigner — the
artifact is the complete signed PDF (PyHankoPAdESSigner), not a
detached signature over the whole file. The certificate chain embedded
is leaf + intermediate (never the root — see
IntermediateCertificateCache). signature_format ("PAdES-T" vs
"PAdES-B") and the tsa_* fields come straight from PAdESSignResult —
this use case never decides the TSA outcome itself (point 3).
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone
from typing import Optional
from uuid import UUID, uuid4

from app.application.services.audit_helpers import build_audit_data
from app.application.services.idempotency import (
    claim_idempotency_key,
    finish_idempotency_claim,
)
from app.application.services.signing_pin_session import (
    record_signature,
    start_session,
    try_resume_session,
)
from app.core.request_context import get_context_values
from app.domain.entities.SignatureRecord import SignatureRecord
from app.domain.exceptions.domain_errors import (
    CertificateChainInvalidError,
    ValidationError,
)
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
from app.domain.ports.output.SignatureRecordRepository import (
    SignatureRecordRepository,
)
from app.domain.ports.output.SigningSessionRepository import SigningSessionRepository
from app.domain.valueobjects.IdentityContext import IdentityContext
from app.domain.valueobjects.OwnerType import OwnerType
from app.infrastructure.external.certificate.intermediate_cache import (
    IntermediateCertificateCache,
)

_SERVICE_NAME = "signing-service"
_RESOURCE_TYPE = "signature"
_HASH_ALGORITHM = "SHA256"
_PDF_MAGIC = b"%PDF-"


class SignDocumentUseCaseImpl(SignDocumentUseCase):
    def __init__(
        self,
        certificate_client: CertificateClient,
        pin_verifier: SigningPinVerifier,
        session_repo: SigningSessionRepository,
        signature_repo: SignatureRecordRepository,
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
        self._signature_repo = signature_repo
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
        record: Optional[SignatureRecord] = None
        session_token: Optional[str] = None
        session_expires_at: Optional[datetime] = None
        error: Optional[BaseException] = None
        claimed = False

        try:
            if not command.document.startswith(_PDF_MAGIC):
                # Fail fast on malformed input, before claiming an
                # idempotency key or spending a certificate-service/PIN
                # round-trip on something that can never sign (point 2
                # of signing-plan.md: never trust document_name for
                # this, inspect the actual bytes).
                raise ValidationError(
                    "document_b64 does not decode to a PDF (missing %PDF- header)",
                    field="document_b64",
                )

            claim = await claim_idempotency_key(
                self._idempotency_repo, str(tenant_id), request_id, "SIGN_DOCUMENT"
            )
            claimed = claim.claimed
            if claim.existing_resource_id:
                existing = await self._signature_repo.find_by_id(
                    UUID(claim.existing_resource_id)
                )
                if existing is not None:
                    record = existing
                    # The session token used for the original call isn't
                    # recoverable here — it's looked up by its own hash,
                    # never by signing_request_id, and only the hash is
                    # persisted. A replay returns the signature correctly
                    # but without a session_token; the caller must fall
                    # back to a PIN on its next call in that case.
                    return _to_result(
                        record, session_token=None, session_expires_at=None
                    )

            document_hash = hashlib.sha256(command.document).hexdigest()

            certificate = await self._certificate_client.get_certificate(
                command.certificate_id, bearer_token
            )
            chain = await self._certificate_client.validate_chain(
                command.certificate_id, bearer_token
            )
            if not chain.valid:
                raise CertificateChainInvalidError(
                    "Certificate chain failed validation",
                    details={
                        "certificate_id": str(command.certificate_id),
                        "chain": [
                            {
                                "certificate_id": str(link.certificate_id),
                                "status": link.status,
                            }
                            for link in chain.chain
                        ],
                    },
                )

            now = datetime.now(timezone.utc)
            session = None
            if command.session_token:
                session = await try_resume_session(
                    self._session_repo,
                    command.certificate_id,
                    command.session_token,
                    now,
                )
                session_token = command.session_token

            if session is None:
                if not command.pin:
                    raise ValidationError(
                        "pin is required (no valid session_token was presented)",
                        field="pin",
                    )
                issued = await start_session(
                    self._pin_verifier,
                    self._session_repo,
                    tenant_id=tenant_id,
                    certificate_id=command.certificate_id,
                    pin=command.pin,
                    bearer_token=bearer_token,
                    ttl_minutes=self._session_ttl_minutes,
                    max_signatures=self._session_max_signatures,
                    now=now,
                )
                session = issued.session
                session_token = issued.token

            chain_pems = []
            if certificate.issuer_certificate_id is not None:
                chain_pems.append(
                    await self._intermediate_cache.get_pem(
                        certificate.issuer_certificate_id, bearer_token
                    )
                )

            pades_result = await self._pades_signer.sign_pdf(
                document=command.document,
                leaf_cert_pem=certificate.pem,
                chain_pems=chain_pems,
                key_id=certificate.key_id,
                hsm_client=self._hsm_client,
                bearer_token=bearer_token,
            )

            session = await record_signature(self._session_repo, session)
            session_expires_at = session.expires_at

            record = SignatureRecord(
                id=uuid4(),
                tenant_id=tenant_id,
                key_id=certificate.key_id,
                certificate_id=certificate.id,
                document_hash=document_hash,
                hash_algorithm=_HASH_ALGORITHM,
                signature_id=uuid4(),
                signature_value=pades_result.signed_document,
                signature_format=pades_result.signature_format,
                signing_time=now,
                document_name=command.document_name,
                user_id=_user_id(identity_context),
                organization_id=_organization_id(identity_context),
                tsa_provider=pades_result.tsa_provider,
                tsa_token=pades_result.tsa_token,
                tsa_sealed_at=pades_result.tsa_sealed_at,
            )
            await self._signature_repo.create(record)
            return _to_result(record, session_token, session_expires_at)
        except BaseException as exc:
            error = exc
            raise
        finally:
            resource_id = str(record.id) if record else None
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
            operation="SIGN_DOCUMENT",
            resource_id=resource_id,
            identity_context=identity_context,
            start=start,
            error=error,
        )
        await self._audit_dispatcher.audit_operation(None, data, identity_context)


def _user_id(identity_context: IdentityContext) -> Optional[UUID]:
    if OwnerType(identity_context.owner_type) == OwnerType.USER:
        return UUID(identity_context.owner_id)
    return None


def _organization_id(identity_context: IdentityContext) -> Optional[UUID]:
    if OwnerType(identity_context.owner_type) == OwnerType.ORGANIZATION:
        return UUID(identity_context.owner_id)
    return None


def _to_result(
    record: SignatureRecord,
    session_token: Optional[str],
    session_expires_at: Optional[datetime],
) -> SignDocumentResult:
    return SignDocumentResult(
        signing_request_id=record.id,
        signature_id=record.signature_id,
        certificate_id=record.certificate_id,
        document_hash=record.document_hash,
        signature_value=record.signature_value,
        signature_format=record.signature_format,
        signing_time=record.signing_time,
        tsa_provider=record.tsa_provider,
        tsa_sealed_at=record.tsa_sealed_at,
        session_token=session_token,
        session_expires_at=session_expires_at,
    )
