"""Caches the issuing CA's PEM for embedding in a PAdES signature's
certificate chain (signing-plan.md point 1 decision: embed leaf +
intermediate, never the root — the root is a trust anchor that belongs
in the verifier's trust store, not the document).

Long TTL by design: the same intermediate CA issues every certificate
under it, so without this cache every single signature would cost an
extra certificate-service round-trip to re-fetch a PEM that essentially
never changes (only on CA rotation). In-memory, per-process — acceptable
because a stale entry only matters in the narrow window right after a
CA rotation, and simply re-fetches on the next TTL expiry; no push
invalidation exists or is needed at this scale.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict
from uuid import UUID

from app.domain.ports.output.CertificateChainCache import CertificateChainCache
from app.domain.ports.output.CertificateClient import CertificateClient


@dataclass
class _CacheEntry:
    pem: str
    cached_at: datetime


class IntermediateCertificateCache(CertificateChainCache):
    def __init__(self, certificate_client: CertificateClient, ttl: timedelta):
        self._client = certificate_client
        self._ttl = ttl
        self._entries: Dict[UUID, _CacheEntry] = {}

    async def get_pem(self, certificate_id: UUID, bearer_token: str) -> str:
        now = datetime.now(timezone.utc)
        entry = self._entries.get(certificate_id)
        if entry is not None and now - entry.cached_at < self._ttl:
            return entry.pem

        info = await self._client.get_certificate(certificate_id, bearer_token)
        self._entries[certificate_id] = _CacheEntry(pem=info.pem, cached_at=now)
        return info.pem
