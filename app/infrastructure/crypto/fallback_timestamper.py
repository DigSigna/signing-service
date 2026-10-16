"""RFC 3161 timestamping with a primary/secondary fallback chain
(ADR-002, signing-plan.md point 3). Free public TSAs, no self-hosted
service, no account required for either candidate.

What gets timestamped here is always the signature value, never the
document or its hash directly — that's inherent to how a *signature*
timestamp works (RFC 3161 "signatureTimeStampToken" unsigned attribute):
the TSA's message imprint is computed over the already-produced
signatureValue, which doesn't exist until hsm-service has signed. There
is no way to request it any earlier.

pyHanko's TimeStamper.async_timestamp() contract is "return a valid
token, or raise" — there is no graceful "no timestamp" return. The
caller (PyHankoPAdESSigner) is the one that decides what "both
providers down" means for the overall signature; this class only
chains providers and raises _AllTsaProvidersFailedError (itself a
TimestampRequestError, so it still satisfies the interface) when none
of them answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional, Tuple

from asn1crypto import cms
from pyhanko.sign.timestamps import (
    HTTPTimeStamper,
    TimestampRequestError,
    TimeStamper,
)

from app.core.logger import get_logger

logger = get_logger("signing-service")


class AllTsaProvidersFailedError(TimestampRequestError):
    """Raised when every configured TSA candidate failed — the caller
    (PyHankoPAdESSigner) catches this specifically to fall back to a
    local pseudo-timestamp instead of failing the whole signature."""


@dataclass(frozen=True)
class TsaCandidate:
    name: str
    url: str
    timeout_seconds: float = 5.0


class FallbackChainTimeStamper(TimeStamper):
    """Tries each delegate in order; the first one to return a valid
    token wins. `last_provider`/`last_token_der` record which delegate
    actually answered the most recent successful call, for
    PyHankoPAdESSigner to persist alongside the signature — pyHanko's
    own API has no way to surface that from inside async_sign_pdf().

    Takes (name, TimeStamper) pairs directly rather than URLs, so tests
    can inject fakes without any real network access — see
    `from_candidates()` for the production construction path (real
    HTTPTimeStamper instances from URLs)."""

    def __init__(self, delegates: List[Tuple[str, TimeStamper]]):
        if not delegates:
            raise ValueError("FallbackChainTimeStamper needs at least one delegate")
        self._delegates = delegates
        self.last_provider: Optional[str] = None
        self.last_token_der: Optional[bytes] = None
        super().__init__()

    @classmethod
    def from_candidates(
        cls, candidates: List[TsaCandidate]
    ) -> "FallbackChainTimeStamper":
        return cls(
            [
                (c.name, HTTPTimeStamper(c.url, timeout=c.timeout_seconds))
                for c in candidates
            ]
        )

    async def async_timestamp(
        self, message_digest: bytes, md_algorithm: str
    ) -> cms.ContentInfo:
        errors = []
        for name, delegate in self._delegates:
            try:
                token = await delegate.async_timestamp(message_digest, md_algorithm)
            except TimestampRequestError as exc:
                logger.warning(
                    "TSA candidate failed, trying next",
                    action="tsa_candidate_failed",
                    provider=name,
                    error=str(exc),
                )
                errors.append(f"{name}: {exc}")
                continue
            self.last_provider = name
            self.last_token_der = token.dump()
            return token

        logger.warning(
            "All TSA candidates failed — falling back to local pseudo-timestamp",
            action="tsa_all_failed",
        )
        raise AllTsaProvidersFailedError("; ".join(errors))
