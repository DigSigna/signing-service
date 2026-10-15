import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
from uuid import UUID, uuid4

import pytest

from app.application.use_cases.sign_document import SignDocumentUseCaseImpl
from app.domain.entities.SignatureRecord import SignatureRecord
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
from app.domain.ports.output.SignatureRecordRepository import (
    SignatureRecordRepository,
)
from app.domain.ports.output.SigningPinVerifier import SigningPinVerifier
from app.domain.ports.output.SigningSessionRepository import SigningSessionRepository
from app.domain.valueobjects.IdentityContext import IdentityContext
from app.domain.valueobjects.OwnerType import OwnerType

TENANT_ID = UUID(int=1)
CERT_ID = UUID(int=2)
KEY_ID = UUID(int=3)
USER_ID = UUID(int=4)


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
        permissions={},
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


class _FakeSignatureRepository(SignatureRecordRepository):
    def __init__(self):
        self._by_id: Dict[UUID, SignatureRecord] = {}

    async def create(self, record: SignatureRecord) -> None:
        self._by_id[record.id] = record

    async def find_by_id(self, signing_request_id: UUID) -> Optional[SignatureRecord]:
        return self._by_id.get(signing_request_id)


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


def _build_use_case(
    certificate_client=None,
    pin_verifier=None,
    session_repo=None,
    signature_repo=None,
    hsm_client=None,
):
    return SignDocumentUseCaseImpl(
        certificate_client=certificate_client or _FakeCertificateClient(),
        pin_verifier=pin_verifier or _FakePinVerifier(),
        session_repo=session_repo or _FakeSessionRepository(),
        signature_repo=signature_repo or _FakeSignatureRepository(),
        hsm_client=hsm_client or _FakeHSMClient(),
        idempotency_repo=None,
        audit_dispatcher=None,
        session_ttl_minutes=20,
        session_max_signatures=0,
    )


@pytest.mark.asyncio
async def test_sign_with_pin_issues_new_session_and_signs():
    hsm = _FakeHSMClient(signature=b"sig-bytes")
    pin_verifier = _FakePinVerifier()
    use_case = _build_use_case(hsm_client=hsm, pin_verifier=pin_verifier)

    document = b"hello world"
    command = SignDocumentCommand(
        certificate_id=CERT_ID, document=document, pin="193042"
    )

    result = await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    assert result.certificate_id == CERT_ID
    assert result.signature_value == b"sig-bytes"
    assert result.signature_format == "RAW"
    assert result.document_hash == hashlib.sha256(document).hexdigest()
    assert result.session_token  # a brand-new session token was issued
    assert result.session_expires_at is not None

    # hsm-service received the raw document, never a pre-hashed digest.
    assert hsm.calls == [(KEY_ID, document, "caller-jwt")]
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
        certificate_id=CERT_ID, document=b"doc", session_token="existing-token"
    )

    result = await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    assert result.session_token == "existing-token"
    assert pin_verifier.calls == []  # PIN never checked
    assert session_repo._by_id[session.id].signature_count == 1


@pytest.mark.asyncio
async def test_sign_without_pin_or_session_raises_validation_error():
    use_case = _build_use_case()
    command = SignDocumentCommand(certificate_id=CERT_ID, document=b"doc")

    with pytest.raises(ValidationError):
        await use_case.execute(command, _identity(), bearer_token="caller-jwt")


@pytest.mark.asyncio
async def test_invalid_chain_raises_before_pin_or_hsm():
    hsm = _FakeHSMClient()
    pin_verifier = _FakePinVerifier()
    use_case = _build_use_case(
        certificate_client=_FakeCertificateClient(chain_valid=False),
        hsm_client=hsm,
        pin_verifier=pin_verifier,
    )
    command = SignDocumentCommand(certificate_id=CERT_ID, document=b"doc", pin="193042")

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
    command = SignDocumentCommand(certificate_id=CERT_ID, document=b"doc", pin="000000")

    with pytest.raises(SigningPinInvalidError):
        await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    assert hsm.calls == []


@pytest.mark.asyncio
async def test_signature_is_persisted_and_findable():
    signature_repo = _FakeSignatureRepository()
    use_case = _build_use_case(signature_repo=signature_repo)
    command = SignDocumentCommand(certificate_id=CERT_ID, document=b"doc", pin="193042")

    result = await use_case.execute(command, _identity(), bearer_token="caller-jwt")

    stored = await signature_repo.find_by_id(result.signing_request_id)
    assert stored is not None
    assert stored.certificate_id == CERT_ID
    assert stored.user_id == USER_ID
    assert stored.signature_value == result.signature_value
