"""Client for the parts of certificate-service's API this service needs
before it will sign anything: the certificate itself (for its key_id/pem)
and a structural/cryptographic validation of its chain up to the root.
Signing-PIN verification is a separate port (SigningPinVerifier) — a
distinct concern against a distinct endpoint."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass
from datetime import datetime
from typing import List
from uuid import UUID


@dataclass
class CertificateInfo:
    id: UUID
    tenant_id: UUID
    key_id: UUID
    common_name: str
    is_ca: bool
    status: str
    not_before: datetime
    not_after: datetime
    pem: str


@dataclass
class ChainLink:
    certificate_id: UUID
    common_name: str
    cert_level: int
    status: str


@dataclass
class ChainValidationResult:
    valid: bool
    chain: List[ChainLink]


class CertificateClient(ABC):
    @abstractmethod
    async def get_certificate(
        self, certificate_id: UUID, bearer_token: str
    ) -> CertificateInfo:
        """Raises NotFoundError (entity="certificate") if it doesn't exist
        or the caller isn't authorized to see it — certificate-service
        reports both cases identically, without revealing which."""
        raise NotImplementedError

    @abstractmethod
    async def validate_chain(
        self, certificate_id: UUID, bearer_token: str
    ) -> ChainValidationResult:
        """Structural/cryptographic validation only (expiration,
        revocation, signature at every link) — not tenant-scoped, any
        authenticated caller may validate any chain. Returns normally
        with valid=False rather than raising; the caller decides what a
        broken chain means for it."""
        raise NotImplementedError
