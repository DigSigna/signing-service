"""Shared core for the N-signer flow (signing-plan.md point 4):
creating a signing_request row, and performing one incremental
signature step over it.

Deliberately NOT idempotency-aware. idempotency_keys'
uk_idempotency_tenant_request is unique on (tenant_id, request_id)
ALONE, not also `operation` (migration 019) — a single client request
can only ever claim one idempotency key for that request_id. Composing
two separately-claimed sub-operations under the same request_id (which
the legacy /sign endpoint would need, since it both creates a
signing_request and signs it in one call) would make the second claim
collide with the first's already-claimed row and misinterpret its
resource_id as if it were the second operation's own. Each PUBLIC use
case (CreateSigningRequestUseCaseImpl, SignIncrementUseCaseImpl, and
the legacy SignDocumentUseCaseImpl) wraps exactly one top-level
claim/finish pair around whichever of these functions it needs — see
each use case's own module for that wrapping.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from hashlib import sha256
from typing import List, Optional
from uuid import UUID, uuid4

from app.application.services.signing_pin_session import (
    record_signature,
    start_session,
    try_resume_session,
)
from app.domain.entities.Signature import Signature
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.exceptions.domain_errors import (
    CertificateChainInvalidError,
    NotFoundError,
    SigningRequestConflictError,
    SigningRequestNotPendingError,
    ValidationError,
)
from app.domain.ports.output.CertificateClient import CertificateClient
from app.domain.ports.output.HSMClient import HSMClient
from app.domain.ports.output.PAdESSigner import PAdESSigner
from app.domain.ports.output.SigningPinVerifier import SigningPinVerifier
from app.domain.ports.output.SigningRequestRepository import (
    SigningRequestRepository,
)
from app.domain.ports.output.SigningSessionRepository import SigningSessionRepository
from py_common.auth.identity_context import IdentityContext
from py_common.auth.owner_type import OwnerType
from app.domain.valueobjects.SigningRequestStatus import SigningRequestStatus
from app.infrastructure.external.certificate.intermediate_cache import (
    IntermediateCertificateCache,
)

_HASH_ALGORITHM = "SHA256"
_PDF_MAGIC = b"%PDF-"


def require_pdf(document: bytes) -> None:
    # signing-plan.md point 2: decided by the actual bytes, never by
    # document_name.
    if not document.startswith(_PDF_MAGIC):
        raise ValidationError(
            "document_b64 does not decode to a PDF (missing %PDF- header)",
            field="document_b64",
        )


def user_id_of(identity_context: IdentityContext) -> Optional[UUID]:
    if OwnerType(identity_context.owner_type) == OwnerType.USER:
        return UUID(identity_context.owner_id)
    return None


def organization_id_of(identity_context: IdentityContext) -> Optional[UUID]:
    if OwnerType(identity_context.owner_type) == OwnerType.ORGANIZATION:
        return UUID(identity_context.owner_id)
    return None


async def create_signing_request_row(
    repo: SigningRequestRepository,
    *,
    tenant_id: UUID,
    document: bytes,
    document_name: Optional[str],
    signers_number: int,
    identity_context: IdentityContext,
    now: Optional[datetime] = None,
) -> SigningRequest:
    require_pdf(document)
    now = now or datetime.now(timezone.utc)
    request = SigningRequest(
        id=uuid4(),
        tenant_id=tenant_id,
        document_name=document_name,
        document_hash=sha256(document).hexdigest(),
        hash_algorithm=_HASH_ALGORITHM,
        signers_number=signers_number,
        signatures_count=0,
        status=SigningRequestStatus.PENDING,
        document_blob=document,
        user_id=user_id_of(identity_context),
        organization_id=organization_id_of(identity_context),
        created_at=now,
        completed_at=None,
        version=0,
    )
    await repo.create(request)
    return request


@dataclass
class SignatureStepResult:
    signing_request: SigningRequest
    signature: Signature
    session_token: Optional[str]
    session_expires_at: Optional[datetime]


async def perform_signature_step(
    *,
    signing_request_repo: SigningRequestRepository,
    certificate_client: CertificateClient,
    pin_verifier: SigningPinVerifier,
    session_repo: SigningSessionRepository,
    hsm_client: HSMClient,
    pades_signer: PAdESSigner,
    intermediate_cache: IntermediateCertificateCache,
    tenant_id: UUID,
    signing_request_id: UUID,
    certificate_id: UUID,
    pin: Optional[str],
    session_token_in: Optional[str],
    bearer_token: str,
    session_ttl_minutes: int,
    session_max_signatures: int,
) -> SignatureStepResult:
    signing_request = await signing_request_repo.find_by_id(signing_request_id)
    if signing_request is None or signing_request.tenant_id != tenant_id:
        # Same NotFoundError for "doesn't exist" and "belongs to another
        # tenant" — never leak existence across tenants (hsm-service's
        # KD-004 is the cautionary example of skipping this).
        raise NotFoundError(
            "Signing request not found",
            entity="SigningRequest",
            entity_id=str(signing_request_id),
        )
    if signing_request.status != SigningRequestStatus.PENDING:
        raise SigningRequestNotPendingError(
            "Signing request is not pending a signature",
            current_status=signing_request.status.value,
        )

    certificate = await certificate_client.get_certificate(certificate_id, bearer_token)
    chain = await certificate_client.validate_chain(certificate_id, bearer_token)
    if not chain.valid:
        raise CertificateChainInvalidError(
            "Certificate chain failed validation",
            details={
                "certificate_id": str(certificate_id),
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
    session_token_out: Optional[str] = None
    session = None
    if session_token_in:
        session = await try_resume_session(
            session_repo, certificate_id, session_token_in, now
        )
        session_token_out = session_token_in

    if session is None:
        if not pin:
            raise ValidationError(
                "pin is required (no valid session_token was presented)",
                field="pin",
            )
        issued = await start_session(
            pin_verifier,
            session_repo,
            tenant_id=tenant_id,
            certificate_id=certificate_id,
            pin=pin,
            bearer_token=bearer_token,
            ttl_minutes=session_ttl_minutes,
            max_signatures=session_max_signatures,
            now=now,
        )
        session = issued.session
        session_token_out = issued.token

    chain_pems: List[str] = []
    if certificate.issuer_certificate_id is not None:
        chain_pems.append(
            await intermediate_cache.get_pem(
                certificate.issuer_certificate_id, bearer_token
            )
        )

    # Sealing (ADR-002/point 3) is only attempted on the signature that
    # completes the request (point 4.2) — earlier signers pass
    # apply_timestamp=False and leave tsa_provider/tsa_token at None.
    is_final = signing_request.is_final_signature()
    field_name = f"Signature{signing_request.signatures_count + 1}"

    pades_result = await pades_signer.sign_pdf(
        document=signing_request.document_blob,
        leaf_cert_pem=certificate.pem,
        chain_pems=chain_pems,
        key_id=certificate.key_id,
        hsm_client=hsm_client,
        bearer_token=bearer_token,
        field_name=field_name,
        apply_timestamp=is_final,
    )

    session = await record_signature(session_repo, session)
    session_expires_at = session.expires_at

    new_document_blob = pades_result.signed_document
    # PDF incremental updates are strictly append-only — this is
    # exactly this signer's contribution, not a redundant snapshot of
    # the whole document (see Signature's own docstring / point 5).
    delta = new_document_blob[len(signing_request.document_blob) :]
    new_status = (
        SigningRequestStatus.COMPLETED if is_final else SigningRequestStatus.PENDING
    )
    completed_at = now if is_final else None

    signature = Signature(
        id=uuid4(),
        signing_request_id=signing_request.id,
        key_id=certificate.key_id,
        certificate_id=certificate.id,
        signature_value=delta,
        signature_format=pades_result.signature_format,
        signing_time=now,
        tsa_provider=pades_result.tsa_provider,
        tsa_token=pades_result.tsa_token,
        tsa_sealed_at=pades_result.tsa_sealed_at,
    )

    ok = await signing_request_repo.append_signature(
        signing_request_id=signing_request.id,
        expected_version=signing_request.version,
        new_document_blob=new_document_blob,
        new_status=new_status,
        completed_at=completed_at,
        signature=signature,
    )
    if not ok:
        raise SigningRequestConflictError(
            "Another signature was recorded for this signing request "
            "concurrently — retry the request"
        )

    signing_request.document_blob = new_document_blob
    signing_request.signatures_count += 1
    signing_request.status = new_status
    signing_request.completed_at = completed_at
    signing_request.version += 1

    return SignatureStepResult(
        signing_request=signing_request,
        signature=signature,
        session_token=session_token_out,
        session_expires_at=session_expires_at,
    )
