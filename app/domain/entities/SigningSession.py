"""The signing-PIN grace window (ADR-005 decision 4/6): after one
successful PIN verification, a session lets the holder sign further
documents with the same certificate without re-entering the PIN, bounded
by time and/or a signature count — whichever is reached first."""

from dataclasses import dataclass
from datetime import datetime
from typing import Optional
from uuid import UUID


@dataclass
class SigningSession:
    id: UUID
    tenant_id: UUID
    certificate_id: UUID
    session_token_hash: str
    issued_at: datetime
    expires_at: datetime
    max_signatures: Optional[int] = None
    signature_count: int = 0

    def has_remaining_signatures(self) -> bool:
        return self.max_signatures is None or self.signature_count < self.max_signatures

    def is_valid(self, now: datetime) -> bool:
        return now < self.expires_at and self.has_remaining_signatures()
