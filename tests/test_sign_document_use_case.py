import hashlib
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
from uuid import UUID, uuid4

import pytest

from app.application.use_cases.sign_document import SignDocumentUseCaseImpl
from app.domain.entities.Signature import Signature
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.entities.SigningSession import SigningSession
from app.domain.exceptions.domain_errors import (
    CertificateChainInvalidError,
    SigningPinInvalidError,
    ValidationError,
)
from app.domain.ports.input.SignDocumentUseCase import SignDocumentCommand
from app.domain.ports.output.CertificateClient import (
    CertificateClient,
    CertificateInfo,
    ChainLink,
    ChainValidationResult,
)
from app.domain.ports.output.HSMClient import HSMClient
from app.domain.ports.output.PAdESSigner import PAdESSigner, PAdESSignResult
from app.domain.ports.output.SigningPinVerifier import SigningPinVerifier
from app.domain.ports.output.SigningRequestRepository import (
    SigningRequestRepository,
)
from app.domain.ports.output.SigningSessionRepository import SigningSessionRepository
from app.domain.ports.output.TenantRepository import TenantRepository
from app.domain.entities.Tenant import Tenant
from py_common.auth.identity_context import IdentityContext
from py_common.auth.owner_type import OwnerType
from app.domain.valueobjects.SigningRequestStatus import SigningRequestStatus
from app.infrastructure.external.certificate.intermediate_cache import (
    IntermediateCertificateCache,
)

TENANT_ID = UUID(int=1)
CERT_ID = UUID(int=2)
KEY_ID = UUID(int=3)
USER_ID = UUID(int=4)
PDF_DOCUMENT = b"%PDF-1.4 fake test document"


def _identity() -> IdentityContext:
    ctx = IdentityContext(
        tenant_id=str(TENANT_ID),
        owner_type=OwnerType.USER,
        owner_id=str(USER_ID),
        user_id=str(USER_ID),
        cert_level=2,
        max_cert_level=2,
        can_certify=False,
        certification_path="",
        permissions=[],
    )
    return ctx


def _certificate_info(status: str = "ACTIVE") -> CertificateInfo:
    return CertificateInfo(
        id=CERT_ID,
        tenant_id=TENANT_ID,
        key_id=KEY_ID,
        common_name="Jane Doe",
        is_ca=False,
        status=status,
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        pem="pem",
    )


class _FakeCertificateClient(CertificateClient):
    def __init__(self, chain_valid: bool = True):
        self.chain_valid = chain_valid
        self.calls = []

    async def get_certificate(self, certificate_id, bearer_token):
        self.calls.append(("get_certificate", certificate_id, bearer_token))
        return _certificate_info()

    async def validate_chain(self, certificate_id, bearer_token):
        self.calls.append(("validate_chain", certificate_id, bearer_token))
        return ChainValidationResult(
            valid=self.chain_valid,
            chain=[
                ChainLink(
                    certificate_id=certificate_id,
                    common_name="Jane Doe",
                    cert_level=2,
                    status="ACTIVE" if self.chain_valid else "EXPIRED",
                )
            ],
        )


class _FakePinVerifier(SigningPinVerifier):
    def __init__(self, should_fail: bool = False):
        self.should_fail = should_fail
        self.calls = []

    async def verify(self, certificate_id, pin, bearer_token):
        self.calls.append((certificate_id, pin, bearer_token))
        if self.should_fail:
            raise SigningPinInvalidError("wrong pin", remaining_attempts=4)


class _FakeSessionRepository(SigningSessionRepository):
    def __init__(self):
        self._by_id: Dict[UUID, SigningSession] = {}
        self._by_hash: Dict[str, SigningSession] = {}

    async def create(self, session: SigningSession) -> None:
        self._by_id[session.id] = session
        self._by_hash[session.session_token_hash] = session

    async def find_by_token_hash(self, token_hash: str) -> Optional[SigningSession]:
        return self._by_hash.get(token_hash)

    async def increment_signature_count(self, session_id: UUID) -> int:
        session = self._by_id[session_id]
        session.signature_count += 1
        return session.signature_count


class _FakeSigningRequestRepository(SigningRequestRepository):
    def __init__(self):
        self._requests: Dict[UUID, SigningRequest] = {}
        self._signatures: Dict[UUID, Signature] = {}

    async def create(self, request: SigningRequest) -> None:
        self._requests[request.id] = request

    async def find_by_id(self, signing_request_id: UUID) -> Optional[SigningRequest]:
        # A copy, not the stored reference — see
        # test_sign_increment_use_case.py's identical fake for why
        # aliasing here would double-apply perform_signature_step's own
        # post-append bookkeeping on top of append_signature's.
        request = self._requests.get(signing_request_id)
        return replace(request) if request is not None else None

    async def find_signature_by_id(self, signature_id: UUID) -> Optional[Signature]:
        return self._signatures.get(signature_id)

    async def append_signature(
        self,
        signing_request_id: UUID,
        expected_version: int,
        new_document_blob: bytes,
        new_status: SigningRequestStatus,
        completed_at,
        signature: Signature,
    ) -> bool:
        request = self._requests[signing_request_id]
        if request.version != expected_version:
            return False
        request.document_blob = new_document_blob
        request.signatures_count += 1
        request.status = new_status
        request.completed_at = completed_at
        request.version += 1
        self._signatures[signature.id] = signature
        return True


class _FakeHSMClient(HSMClient):
    def __init__(self, signature: bytes = b"signature-bytes"):
        self.signature = signature
        self.calls = []

    async def create_key(self, *args, **kwargs):
        raise NotImplementedError

    async def get_public_key(self, key_id):
        raise NotImplementedError

    async def sign_hash(self, key_id, hash_bytes, bearer_token):
        self.calls.append((key_id, hash_bytes, bearer_token))
        return self.signature

    async def ping(self, key_id, bearer_token):
        raise NotImplementedError


class _FakePAdESSigner(PAdESSigner):
    """Real PDF/PAdES correctness is covered end-to-end by
    test_pyhanko_pades_signer.py — this fake keeps these tests focused
    on the use cases' own orchestration (ordering, error propagation,
    idempotency), without needing real PDF/cert fixtures for every
    case. Appends fixed bytes to `document` rather than replacing it
    outright, so signing_core's delta computation
    (new[len(old):]) behaves the same way it would against a real
    incremental PDF update."""

    def __init__(self):
        self.calls = []

    async def sign_pdf(
        self,
        document,
        leaf_cert_pem,
        chain_pems,
        key_id,
        hsm_client,
        bearer_token,
        signing_request_id=None,
        tenant_name=None,
        field_name="Signature1",
        apply_timestamp=True,
        signer_index=0,
        root_ca_name=None,
    ):
        self.calls.append(
            (document, leaf_cert_pem, tuple(chain_pems), key_id, bearer_token)
        )
        sig = await hsm_client.sign_hash(key_id, b"fake-signed-attrs", bearer_token)
        if not apply_timestamp:
            return PAdESSignResult(
                signed_document=document + b"SIGNED-PDF:" + sig,
                signature_format="PAdES-B",
                tsa_provider=None,
                tsa_token=None,
                tsa_sealed_at=datetime.now(timezone.utc),
            )
        return PAdESSignResult(
            signed_document=document + b"SIGNED-PDF:" + sig,
            signature_format="PAdES-T",
            tsa_provider="fake-tsa",
            tsa_token=b"fake-tsa-token",
            tsa_sealed_at=datetime.now(timezone.utc),
        )


class _FakeTenantRepository(TenantRepository):
    async def find_by_id(self, tenant_id):
        return Tenant(id=tenant_id, name="Acme Corp")

    async def exists(self, tenant_id):
        raise NotImplementedError

    async def find_by_hsm_slot(self, slot):
        raise NotImplementedError

    async def update_hsm_slot(self, tenant_id, slot_id):
        raise NotImplementedError


def _build_use_case(
    certificate_client=None,
    pin_verifier=None,
    session_repo=None,
    signing_request_repo=None,
    hsm_client=None,
    pades_signer=None,
    tenant_repo=None,
):
    certificate_client = certificate_client or _FakeCertificateClient()
    return SignDocumentUseCaseImpl(
        certificate_client=certificate_client,
        pin_verifier=pin_verifier or _FakePinVerifier(),
        session_repo=session_repo or _FakeSessionRepository(),
        signing_request_repo=signing_request_repo or _FakeSigningRequestRepository(),
        hsm_client=hsm_client or _FakeHSMClient(),
        pades_signer=pades_signer or _FakePAdESSigner(),
        intermediate_cache=IntermediateCertificateCache(
            certificate_client, ttl=timedelta(hours=1)
        ),
        tenant_repo=tenant_repo or _FakeTenantRepository(),
        idempotency_repo=None,
        audit_dispatcher=None,
        session_ttl_minutes=20,
        session_max_signatures=0,
    )


@pytest.mark.asyncio
async def test_sign_with_pin_issues_new_session_and_signs():
    hsm = _FakeHSMClient(signature=b"sig-bytes")
    pin_verifier = _FakePinVerifier()
    pades_signer = _FakePAdESSigner()
    use_case = _build_use_case(
        hsm_client=hsm, pin_verifier=pin_verifier, pades_signer=pades_signer
    )

    command = SignDocumentCommand(
        certificate_id=CERT_ID, document=PDF_DOCUMENT, pin="193042"
    )

    result = await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    assert result.certificate_id == CERT_ID
    assert result.signature_value == PDF_DOCUMENT + b"SIGNED-PDF:sig-bytes"
    assert result.signature_format == "PAdES-T"
    assert result.tsa_provider == "fake-tsa"
    assert result.tsa_sealed_at is not None
    assert result.document_hash == hashlib.sha256(PDF_DOCUMENT).hexdigest()
    assert result.session_token  # a brand-new session token was issued
    assert result.session_expires_at is not None

    # The use case hands the signer the current document state (here,
    # the original document — this is a single-signer request) — the
    # signer itself decides what actually goes to hsm-service, see
    # test_pyhanko_pades_signer.py for that boundary.
    assert pades_signer.calls == [(PDF_DOCUMENT, "pem", (), KEY_ID, "caller-jwt")]
    assert hsm.calls == [(KEY_ID, b"fake-signed-attrs", "caller-jwt")]
    assert pin_verifier.calls == [(CERT_ID, "193042", "caller-jwt")]


@pytest.mark.asyncio
async def test_sign_with_valid_session_token_skips_pin():
    session_repo = _FakeSessionRepository()
    now = datetime.now(timezone.utc)
    session = SigningSession(
        id=uuid4(),
        tenant_id=TENANT_ID,
        certificate_id=CERT_ID,
        session_token_hash=hashlib.sha256(b"existing-token").hexdigest(),
        issued_at=now,
        expires_at=now + timedelta(minutes=20),
    )
    await session_repo.create(session)
    pin_verifier = _FakePinVerifier()

    use_case = _build_use_case(session_repo=session_repo, pin_verifier=pin_verifier)
    command = SignDocumentCommand(
        certificate_id=CERT_ID, document=PDF_DOCUMENT, session_token="existing-token"
    )

    result = await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    assert result.session_token == "existing-token"
    assert pin_verifier.calls == []  # PIN never checked
    assert session_repo._by_id[session.id].signature_count == 1


@pytest.mark.asyncio
async def test_sign_without_pin_or_session_raises_validation_error():
    use_case = _build_use_case()
    command = SignDocumentCommand(certificate_id=CERT_ID, document=PDF_DOCUMENT)

    with pytest.raises(ValidationError):
        await use_case.execute(command, _identity(), bearer_token="caller-jwt")


@pytest.mark.asyncio
async def test_non_pdf_document_rejected_before_any_remote_call():
    certificate_client = _FakeCertificateClient()
    pin_verifier = _FakePinVerifier()
    use_case = _build_use_case(
        certificate_client=certificate_client, pin_verifier=pin_verifier
    )
    command = SignDocumentCommand(
        certificate_id=CERT_ID, document=b"not a pdf at all", pin="193042"
    )

    with pytest.raises(ValidationError) as exc_info:
        await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    assert exc_info.value.field == "document_b64"
    # Fails before spending a certificate-service or PIN round-trip.
    assert certificate_client.calls == []
    assert pin_verifier.calls == []


@pytest.mark.asyncio
async def test_fetches_and_forwards_intermediate_cert_when_present():
    issuer_id = UUID(int=99)

    class _CertClientWithIssuer(_FakeCertificateClient):
        async def get_certificate(self, certificate_id, bearer_token):
            self.calls.append(("get_certificate", certificate_id, bearer_token))
            info = _certificate_info()
            info.issuer_certificate_id = issuer_id
            return info

    certificate_client = _CertClientWithIssuer()
    pades_signer = _FakePAdESSigner()
    use_case = _build_use_case(
        certificate_client=certificate_client, pades_signer=pades_signer
    )
    command = SignDocumentCommand(
        certificate_id=CERT_ID, document=PDF_DOCUMENT, pin="193042"
    )

    await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    # get_certificate was called twice: once for the leaf (CERT_ID),
    # once more by IntermediateCertificateCache for the issuer.
    get_certificate_calls = [
        c for c in certificate_client.calls if c[0] == "get_certificate"
    ]
    assert {c[1] for c in get_certificate_calls} == {CERT_ID, issuer_id}

    # The intermediate's PEM (same fixture PEM, since _certificate_info
    # is reused) was forwarded to the signer as part of chain_pems.
    [(_doc, _leaf_pem, chain_pems, _key_id, _token)] = pades_signer.calls
    assert chain_pems == ("pem",)


@pytest.mark.asyncio
async def test_invalid_chain_raises_before_pin_or_hsm():
    hsm = _FakeHSMClient()
    pin_verifier = _FakePinVerifier()
    use_case = _build_use_case(
        certificate_client=_FakeCertificateClient(chain_valid=False),
        hsm_client=hsm,
        pin_verifier=pin_verifier,
    )
    command = SignDocumentCommand(
        certificate_id=CERT_ID, document=PDF_DOCUMENT, pin="193042"
    )

    with pytest.raises(CertificateChainInvalidError):
        await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    assert pin_verifier.calls == []
    assert hsm.calls == []


@pytest.mark.asyncio
async def test_pin_failure_never_reaches_hsm():
    hsm = _FakeHSMClient()
    use_case = _build_use_case(
        hsm_client=hsm, pin_verifier=_FakePinVerifier(should_fail=True)
    )
    command = SignDocumentCommand(
        certificate_id=CERT_ID, document=PDF_DOCUMENT, pin="000000"
    )

    with pytest.raises(SigningPinInvalidError):
        await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    assert hsm.calls == []


@pytest.mark.asyncio
async def test_signature_is_persisted_and_findable():
    signing_request_repo = _FakeSigningRequestRepository()
    use_case = _build_use_case(signing_request_repo=signing_request_repo)
    command = SignDocumentCommand(
        certificate_id=CERT_ID, document=PDF_DOCUMENT, pin="193042"
    )

    result = await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    stored_request = await signing_request_repo.find_by_id(result.signing_request_id)
    stored_signature = await signing_request_repo.find_signature_by_id(
        result.signature_id
    )
    assert stored_request is not None
    assert stored_request.status == SigningRequestStatus.COMPLETED
    assert stored_request.document_blob == result.signature_value
    assert stored_signature.certificate_id == CERT_ID
    assert stored_request.user_id == USER_ID
    assert stored_signature.tsa_provider == result.tsa_provider
    assert stored_signature.tsa_sealed_at == result.tsa_sealed_at
    # The signature row holds only this signer's delta, not a redundant
    # full-document snapshot (signing-plan.md point 5): _FakePAdESSigner
    # appends "SIGNED-PDF:" + the HSM signature to the input document,
    # so that suffix is exactly the delta a real incremental PDF update
    # would also produce.
    assert stored_signature.signature_value == b"SIGNED-PDF:signature-bytes"


# -- signing-plan.md point 2: document_name is metadata only, never an
# input to logic or file paths. -----------------------------------------


@pytest.mark.asyncio
async def test_document_name_cannot_override_the_real_content_check():
    """A document_name that lies about the content ("contrato.pdf") must
    not change the outcome — only the actual bytes decide whether this
    is a PDF."""
    use_case = _build_use_case()
    command = SignDocumentCommand(
        certificate_id=CERT_ID,
        document=b"not a pdf at all",
        document_name="contrato.pdf",
        pin="193042",
    )

    with pytest.raises(ValidationError) as exc_info:
        await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    assert exc_info.value.field == "document_b64"


@pytest.mark.asyncio
async def test_document_name_is_stored_verbatim_as_inert_text():
    """A path-traversal-shaped document_name is accepted and persisted
    unchanged — it is never interpreted as a filesystem path or used to
    pick a code path, only displayed/audited as text."""
    signing_request_repo = _FakeSigningRequestRepository()
    use_case = _build_use_case(signing_request_repo=signing_request_repo)
    traversal_name = "../../../etc/passwd"
    command = SignDocumentCommand(
        certificate_id=CERT_ID,
        document=PDF_DOCUMENT,
        document_name=traversal_name,
        pin="193042",
    )

    result = await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    stored_request = await signing_request_repo.find_by_id(result.signing_request_id)
    assert stored_request.document_name == traversal_name
