"""Port for fetching a certificate's PEM for chain embedding.

Extracted from the application layer importing the concrete
IntermediateCertificateCache directly (infrastructure) — a hexagonal
violation found during an architecture review, 2026-10-19: the
application layer must depend on an abstraction here, not know where
or how the PEM is actually fetched/cached.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from uuid import UUID


class CertificateChainCache(ABC):
    @abstractmethod
    async def get_pem(self, certificate_id: UUID, bearer_token: str) -> str:
        """Returns the certificate's PEM, cached or freshly fetched.
        Raises whatever the underlying CertificateClient raises
        (NotFoundError, CertificateServiceUnavailableError) on a miss."""
        raise NotImplementedError
