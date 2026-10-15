import hashlib
from datetime import datetime, timedelta, timezone
from typing import Dict, Optional
from uuid import UUID, uuid4

import pytest

from app.application.services.signing_pin_session import (
    record_signature,
    start_session,
    try_resume_session,
)
from app.domain.entities.SigningSession import SigningSession
from app.domain.exceptions.domain_errors import SigningPinInvalidError
from app.domain.ports.output.SigningPinVerifier import SigningPinVerifier
from app.domain.ports.output.SigningSessionRepository import SigningSessionRepository

TENANT_ID = UUID(int=1)
CERTIFICATE_ID = UUID(int=2)
OTHER_CERTIFICATE_ID = UUID(int=3)


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


class _FakePinVerifier(SigningPinVerifier):
    def __init__(self, should_fail: bool = False):
        self.should_fail = should_fail
        self.calls = []

    async def verify(self, certificate_id, pin: str, bearer_token: str) -> None:
        self.calls.append((certificate_id, pin, bearer_token))
        if self.should_fail:
            raise SigningPinInvalidError("wrong pin", remaining_attempts=4)


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@pytest.mark.asyncio
async def test_start_session_verifies_pin_then_persists_hashed_token():
    repo = _FakeSessionRepository()
    verifier = _FakePinVerifier()

    issued = await start_session(
        verifier,
        repo,
        tenant_id=TENANT_ID,
        certificate_id=CERTIFICATE_ID,
        pin="193042",
        bearer_token="caller-jwt",
        ttl_minutes=20,
        max_signatures=0,
    )

    assert verifier.calls == [(CERTIFICATE_ID, "193042", "caller-jwt")]
    assert issued.session.tenant_id == TENANT_ID
    assert issued.session.certificate_id == CERTIFICATE_ID
    assert issued.session.signature_count == 0
    assert issued.session.max_signatures is None  # 0 means unbounded
    assert issued.session.session_token_hash == _token_hash(issued.token)
    # The raw token is never persisted anywhere the repo can see.
    assert issued.token != issued.session.session_token_hash


@pytest.mark.asyncio
async def test_start_session_propagates_pin_failure_without_creating_session():
    repo = _FakeSessionRepository()
    verifier = _FakePinVerifier(should_fail=True)

    with pytest.raises(SigningPinInvalidError):
        await start_session(
            verifier,
            repo,
            tenant_id=TENANT_ID,
            certificate_id=CERTIFICATE_ID,
            pin="000000",
            bearer_token="caller-jwt",
            ttl_minutes=20,
            max_signatures=0,
        )

    assert repo._by_id == {}


@pytest.mark.asyncio
async def test_try_resume_session_returns_valid_session():
    repo = _FakeSessionRepository()
    now = datetime.now(timezone.utc)
    session = SigningSession(
        id=uuid4(),
        tenant_id=TENANT_ID,
        certificate_id=CERTIFICATE_ID,
        session_token_hash=_token_hash("my-token"),
        issued_at=now,
        expires_at=now + timedelta(minutes=20),
    )
    await repo.create(session)

    resumed = await try_resume_session(repo, CERTIFICATE_ID, "my-token", now=now)

    assert resumed is session


@pytest.mark.asyncio
async def test_try_resume_session_returns_none_for_unknown_token():
    repo = _FakeSessionRepository()
    resumed = await try_resume_session(repo, CERTIFICATE_ID, "no-such-token")
    assert resumed is None


@pytest.mark.asyncio
async def test_try_resume_session_returns_none_for_mismatched_certificate():
    repo = _FakeSessionRepository()
    now = datetime.now(timezone.utc)
    session = SigningSession(
        id=uuid4(),
        tenant_id=TENANT_ID,
        certificate_id=CERTIFICATE_ID,
        session_token_hash=_token_hash("my-token"),
        issued_at=now,
        expires_at=now + timedelta(minutes=20),
    )
    await repo.create(session)

    resumed = await try_resume_session(repo, OTHER_CERTIFICATE_ID, "my-token", now=now)

    assert resumed is None


@pytest.mark.asyncio
async def test_try_resume_session_returns_none_when_expired():
    repo = _FakeSessionRepository()
    now = datetime.now(timezone.utc)
    session = SigningSession(
        id=uuid4(),
        tenant_id=TENANT_ID,
        certificate_id=CERTIFICATE_ID,
        session_token_hash=_token_hash("my-token"),
        issued_at=now - timedelta(minutes=30),
        expires_at=now - timedelta(minutes=10),
    )
    await repo.create(session)

    resumed = await try_resume_session(repo, CERTIFICATE_ID, "my-token", now=now)

    assert resumed is None


@pytest.mark.asyncio
async def test_try_resume_session_returns_none_when_signature_budget_exhausted():
    repo = _FakeSessionRepository()
    now = datetime.now(timezone.utc)
    session = SigningSession(
        id=uuid4(),
        tenant_id=TENANT_ID,
        certificate_id=CERTIFICATE_ID,
        session_token_hash=_token_hash("my-token"),
        issued_at=now,
        expires_at=now + timedelta(minutes=20),
        max_signatures=2,
        signature_count=2,
    )
    await repo.create(session)

    resumed = await try_resume_session(repo, CERTIFICATE_ID, "my-token", now=now)

    assert resumed is None


@pytest.mark.asyncio
async def test_record_signature_increments_via_repository():
    repo = _FakeSessionRepository()
    now = datetime.now(timezone.utc)
    session = SigningSession(
        id=uuid4(),
        tenant_id=TENANT_ID,
        certificate_id=CERTIFICATE_ID,
        session_token_hash=_token_hash("my-token"),
        issued_at=now,
        expires_at=now + timedelta(minutes=20),
    )
    await repo.create(session)

    updated = await record_signature(repo, session)

    assert updated.signature_count == 1
    assert repo._by_id[session.id].signature_count == 1
