from dataclasses import replace
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
from uuid import UUID, uuid4

import pytest

from app.application.use_cases.sign_increment import SignIncrementUseCaseImpl
from app.domain.entities.Signature import Signature
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.entities.SigningSession import SigningSession
from app.domain.exceptions.domain_errors import (
    NotFoundError,
    SigningRequestConflictError,
    SigningRequestNotPendingError,
)
from app.domain.ports.input.SignIncrementUseCase import SignIncrementCommand
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
from py_common.auth.identity_context import IdentityContext
from py_common.auth.owner_type import OwnerType
from app.domain.valueobjects.SigningRequestStatus import SigningRequestStatus
from app.infrastructure.external.certificate.intermediate_cache import (
    IntermediateCertificateCache,
)

TENANT_ID = UUID(int=1)
OTHER_TENANT_ID = UUID(int=77)
CERT_ID = UUID(int=2)
KEY_ID = UUID(int=3)
USER_ID = UUID(int=4)
PDF_DOCUMENT = b"%PDF-1.4 fake test document"


def _identity() -> IdentityContext:
    return IdentityContext(
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


def _certificate_info() -> CertificateInfo:
    return CertificateInfo(
        id=CERT_ID,
        tenant_id=TENANT_ID,
        key_id=KEY_ID,
        common_name="Jane Doe",
        is_ca=False,
        status="ACTIVE",
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        pem="pem",
    )


class _FakeCertificateClient(CertificateClient):
    def __init__(self, chain_valid: bool = True):
        self.chain_valid = chain_valid

    async def get_certificate(self, certificate_id, bearer_token):
        return _certificate_info()

    async def validate_chain(self, certificate_id, bearer_token):
        return ChainValidationResult(
            valid=self.chain_valid,
            chain=[
                ChainLink(
                    certificate_id=certificate_id,
                    common_name="Jane Doe",
                    cert_level=2,
                    status="ACTIVE",
                )
            ],
        )


class _FakePinVerifier(SigningPinVerifier):
    def __init__(self):
        self.calls = []

    async def verify(self, certificate_id, pin, bearer_token):
        self.calls.append((certificate_id, pin, bearer_token))


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
        self.requests: Dict[UUID, SigningRequest] = {}
        self.signatures: Dict[UUID, Signature] = {}
        # Set by a test to simulate a concurrent write winning the race
        # right before this repo's own append_signature runs.
        self.sabotage_version_before_append: Dict[UUID, bool] = {}

    async def create(self, request: SigningRequest) -> None:
        self.requests[request.id] = request

    async def find_by_id(self, signing_request_id: UUID) -> Optional[SigningRequest]:
        # A copy, not the stored reference: the real SQLAlchemy adapter
        # builds a brand-new dataclass from the DB row on every call, so
        # a caller's local mutation of what it got back (as
        # perform_signature_step does, to build its own return value)
        # must never alias — and thus corrupt — this repo's own stored
        # state.
        request = self.requests.get(signing_request_id)
        return replace(request) if request is not None else None

    async def find_signature_by_id(self, signature_id: UUID) -> Optional[Signature]:
        return self.signatures.get(signature_id)

    async def append_signature(
        self,
        signing_request_id: UUID,
        expected_version: int,
        new_document_blob: bytes,
        new_status: SigningRequestStatus,
        completed_at,
        signature: Signature,
    ) -> bool:
        request = self.requests[signing_request_id]
        if self.sabotage_version_before_append.get(signing_request_id):
            request.version += 1  # simulate another /sign call winning first
        if request.version != expected_version:
            return False
        request.document_blob = new_document_blob
        request.signatures_count += 1
        request.status = new_status
        request.completed_at = completed_at
        request.version += 1
        self.signatures[signature.id] = signature
        return True


class _FakeHSMClient(HSMClient):
    def __init__(self):
        self.calls = []

    async def create_key(self, *args, **kwargs):
        raise NotImplementedError

    async def get_public_key(self, key_id):
        raise NotImplementedError

    async def sign_hash(self, key_id, hash_bytes, bearer_token):
        self.calls.append((key_id, hash_bytes, bearer_token))
        return b"sig-bytes"

    async def ping(self, key_id, bearer_token):
        raise NotImplementedError


class _FakePAdESSigner(PAdESSigner):
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
        field_name="Signature1",
        apply_timestamp=True,
    ):
        self.calls.append((field_name, apply_timestamp))
        sig = await hsm_client.sign_hash(key_id, b"fake-signed-attrs", bearer_token)
        new_document = document + f":{field_name}:".encode() + sig
        if not apply_timestamp:
            return PAdESSignResult(
                signed_document=new_document,
                signature_format="PAdES-B",
                tsa_provider=None,
                tsa_token=None,
                tsa_sealed_at=datetime.now(timezone.utc),
            )
        return PAdESSignResult(
            signed_document=new_document,
            signature_format="PAdES-T",
            tsa_provider="fake-tsa",
            tsa_token=b"fake-tsa-token",
            tsa_sealed_at=datetime.now(timezone.utc),
        )


def _make_request(signers_number: int = 2) -> SigningRequest:
    return SigningRequest(
        id=uuid4(),
        tenant_id=TENANT_ID,
        document_name="contrato.pdf",
        document_hash="deadbeef",
        hash_algorithm="SHA256",
        signers_number=signers_number,
        signatures_count=0,
        status=SigningRequestStatus.PENDING,
        document_blob=PDF_DOCUMENT,
        user_id=USER_ID,
        organization_id=None,
        created_at=datetime.now(timezone.utc),
        completed_at=None,
        version=0,
    )


def _build_use_case(
    signing_request_repo=None,
    certificate_client=None,
    pin_verifier=None,
    session_repo=None,
    hsm_client=None,
    pades_signer=None,
):
    certificate_client = certificate_client or _FakeCertificateClient()
    return SignIncrementUseCaseImpl(
        signing_request_repo=signing_request_repo or _FakeSigningRequestRepository(),
        certificate_client=certificate_client,
        pin_verifier=pin_verifier or _FakePinVerifier(),
        session_repo=session_repo or _FakeSessionRepository(),
        hsm_client=hsm_client or _FakeHSMClient(),
        pades_signer=pades_signer or _FakePAdESSigner(),
        intermediate_cache=IntermediateCertificateCache(
            certificate_client, ttl=timedelta(hours=1)
        ),
        idempotency_repo=None,
        audit_dispatcher=None,
        session_ttl_minutes=20,
        session_max_signatures=0,
    )


@pytest.mark.asyncio
async def test_first_of_two_signers_stays_pending_without_sealing():
    repo = _FakeSigningRequestRepository()
    request = _make_request(signers_number=2)
    await repo.create(request)
    pades_signer = _FakePAdESSigner()
    use_case = _build_use_case(signing_request_repo=repo, pades_signer=pades_signer)

    result = await use_case.execute(
        SignIncrementCommand(
            signing_request_id=request.id, certificate_id=CERT_ID, pin="193042"
        ),
        _identity(),
        bearer_token="caller-jwt",
    )

    assert result.status == "PENDING"
    assert result.signatures_count == 1
    assert result.signers_number == 2
    assert result.tsa_provider is None  # not the final signer — never sealed
    assert pades_signer.calls == [("Signature1", False)]
    assert repo.requests[request.id].status == SigningRequestStatus.PENDING


@pytest.mark.asyncio
async def test_second_of_two_signers_completes_and_seals():
    repo = _FakeSigningRequestRepository()
    request = _make_request(signers_number=2)
    request.signatures_count = 1
    request.version = 1
    await repo.create(request)
    pades_signer = _FakePAdESSigner()
    use_case = _build_use_case(signing_request_repo=repo, pades_signer=pades_signer)

    result = await use_case.execute(
        SignIncrementCommand(
            signing_request_id=request.id, certificate_id=CERT_ID, pin="193042"
        ),
        _identity(),
        bearer_token="caller-jwt",
    )

    assert result.status == "COMPLETED"
    assert result.signatures_count == 2
    assert result.tsa_provider == "fake-tsa"
    assert pades_signer.calls == [("Signature2", True)]
    assert repo.requests[request.id].status == SigningRequestStatus.COMPLETED
    assert repo.requests[request.id].completed_at is not None


@pytest.mark.asyncio
async def test_unknown_signing_request_raises_not_found():
    use_case = _build_use_case()

    with pytest.raises(NotFoundError):
        await use_case.execute(
            SignIncrementCommand(
                signing_request_id=uuid4(), certificate_id=CERT_ID, pin="193042"
            ),
            _identity(),
            bearer_token="caller-jwt",
        )


@pytest.mark.asyncio
async def test_signing_request_from_another_tenant_raises_not_found():
    repo = _FakeSigningRequestRepository()
    request = _make_request()
    request.tenant_id = OTHER_TENANT_ID
    await repo.create(request)
    use_case = _build_use_case(signing_request_repo=repo)

    with pytest.raises(NotFoundError):
        await use_case.execute(
            SignIncrementCommand(
                signing_request_id=request.id, certificate_id=CERT_ID, pin="193042"
            ),
            _identity(),
            bearer_token="caller-jwt",
        )


@pytest.mark.asyncio
async def test_already_completed_request_rejects_further_signatures():
    repo = _FakeSigningRequestRepository()
    request = _make_request(signers_number=1)
    request.status = SigningRequestStatus.COMPLETED
    request.signatures_count = 1
    await repo.create(request)
    use_case = _build_use_case(signing_request_repo=repo)

    with pytest.raises(SigningRequestNotPendingError):
        await use_case.execute(
            SignIncrementCommand(
                signing_request_id=request.id, certificate_id=CERT_ID, pin="193042"
            ),
            _identity(),
            bearer_token="caller-jwt",
        )


@pytest.mark.asyncio
async def test_concurrent_signature_loses_optimistic_lock_raises_conflict():
    """Two /sign calls racing on the same signing_request_id: whichever
    commits its append_signature second must not silently overwrite the
    first's work (last-write-wins data loss) — it must see the version
    mismatch and raise, never retried automatically here."""
    repo = _FakeSigningRequestRepository()
    request = _make_request(signers_number=2)
    await repo.create(request)
    repo.sabotage_version_before_append[request.id] = True
    use_case = _build_use_case(signing_request_repo=repo)

    with pytest.raises(SigningRequestConflictError):
        await use_case.execute(
            SignIncrementCommand(
                signing_request_id=request.id, certificate_id=CERT_ID, pin="193042"
            ),
            _identity(),
            bearer_token="caller-jwt",
        )
    # The losing call's signature must never have been persisted.
    assert repo.signatures == {}
