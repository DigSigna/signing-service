"""Replaces SignatureRecordRepository (signing-plan.md point 4 made the
old 1:1 signing_request<->signature assumption it was built on wrong).
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from datetime import datetime
from typing import Optional
from uuid import UUID

from app.domain.entities.Signature import Signature
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.valueobjects.SigningRequestStatus import SigningRequestStatus


class SigningRequestRepository(ABC):
    @abstractmethod
    async def create(self, request: SigningRequest) -> None:
        raise NotImplementedError

    @abstractmethod
    async def find_by_id(self, signing_request_id: UUID) -> Optional[SigningRequest]:
        raise NotImplementedError

    @abstractmethod
    async def find_signature_by_id(self, signature_id: UUID) -> Optional[Signature]:
        """Used for idempotency replay (resource_id is a signature id,
        not a signing_request id — a signing_request can own more than
        one signature since migration 026)."""
        raise NotImplementedError

    @abstractmethod
    async def append_signature(
        self,
        signing_request_id: UUID,
        expected_version: int,
        new_document_blob: bytes,
        new_status: SigningRequestStatus,
        completed_at: Optional[datetime],
        signature: Signature,
    ) -> bool:
        """Atomically: updates signing_requests (document_blob,
        signatures_count += 1, status, completed_at, version += 1),
        gated on the current version equalling `expected_version`, and
        inserts `signature`. Returns False (persisting nothing) if the
        version check fails — a concurrent /sign call on the same
        signing_request_id already won the race. Callers must surface
        this as a conflict for the client to retry; this method never
        retries internally (an automatic retry could re-run the whole
        PIN/HSM/TSA chain unexpectedly for a signature that already
        exists)."""
        raise NotImplementedError
