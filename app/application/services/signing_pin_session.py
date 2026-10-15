"""Signing-PIN session grace window (ADR-005 decision 4/6).

Three entry points, meant to be composed by the eventual /sign use case:
  1. try_resume_session() — the caller presents a session token from a
     prior successful PIN check; returns it if still valid for this
     certificate, without consuming anything yet (a pure lookup — the
     use case may still fail to actually produce a signature after
     this, e.g. hsm-service errors out, and a check alone shouldn't
     burn part of the session's budget).
  2. start_session() — no valid session: verify the PIN against
     certificate-service (raises on failure — a wrong/locked PIN never
     reaches this function's caller, let alone hsm-service), then issue
     a brand new session.
  3. record_signature() — called once a signature has actually been
     produced, for whichever session resolved from (1) or (2), so a
     failed signing attempt never consumes part of the budget.

The raw session token is only ever generated here and handed back to
the caller once; only its hash is ever persisted (SigningSessionRepository).
"""

from __future__ import annotations

import hashlib
import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Optional
from uuid import UUID, uuid4

from app.domain.entities.SigningSession import SigningSession
from app.domain.ports.output.SigningPinVerifier import SigningPinVerifier
from app.domain.ports.output.SigningSessionRepository import SigningSessionRepository


@dataclass
class SigningSessionIssued:
    session: SigningSession
    token: str


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


async def try_resume_session(
    session_repo: SigningSessionRepository,
    certificate_id: UUID,
    session_token: str,
    now: Optional[datetime] = None,
) -> Optional[SigningSession]:
    """Returns the session if session_token is valid for
    certificate_id, else None — a None result means the caller must
    fall back to start_session() with a PIN. Never raised as an error:
    an expired/exhausted/unknown token is an expected, routine outcome
    here, not a failure. Does not consume any of the session's budget —
    see record_signature()."""
    now = now or datetime.now(timezone.utc)
    token_hash = _hash_token(session_token)
    session = await session_repo.find_by_token_hash(token_hash)
    if session is None:
        return None
    if session.certificate_id != certificate_id:
        return None
    if not session.is_valid(now):
        return None

    return session


async def record_signature(
    session_repo: SigningSessionRepository, session: SigningSession
) -> SigningSession:
    """Call once a signature has actually been produced using `session`
    (from try_resume_session() or start_session()) — never before, so a
    failed signing attempt (e.g. hsm-service errors out) doesn't consume
    part of the session's budget for nothing."""
    session.signature_count = await session_repo.increment_signature_count(session.id)
    return session


async def start_session(
    pin_verifier: SigningPinVerifier,
    session_repo: SigningSessionRepository,
    *,
    tenant_id: UUID,
    certificate_id: UUID,
    pin: str,
    bearer_token: str,
    ttl_minutes: int,
    max_signatures: int,
    now: Optional[datetime] = None,
) -> SigningSessionIssued:
    """Verifies the PIN first — pin_verifier.verify() raises
    SigningPinInvalidError/SigningPinLockedError/SigningPinNotSetError/
    SigningPinNotApplicableError on any failure, which propagates
    unchanged; no session is created unless verification succeeds.
    max_signatures=0 means unbounded, matching Settings.
    SIGNING_PIN_SESSION_MAX_SIGNATURES's own convention."""
    await pin_verifier.verify(certificate_id, pin, bearer_token)

    now = now or datetime.now(timezone.utc)
    token = secrets.token_urlsafe(32)
    session = SigningSession(
        id=uuid4(),
        tenant_id=tenant_id,
        certificate_id=certificate_id,
        session_token_hash=_hash_token(token),
        issued_at=now,
        expires_at=now + timedelta(minutes=ttl_minutes),
        max_signatures=max_signatures or None,
        signature_count=0,
    )
    await session_repo.create(session)
    return SigningSessionIssued(session=session, token=token)
