from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID

from app.domain.entities.SigningSession import SigningSession


class SigningSessionRepository(ABC):
    @abstractmethod
    async def create(self, session: SigningSession) -> None:
        """Persists a newly issued session. session.session_token_hash is
        already the hash — the raw token never reaches this layer."""
        raise NotImplementedError

    @abstractmethod
    async def find_by_token_hash(self, token_hash: str) -> Optional[SigningSession]:
        """token_hash is unique across all sessions (any tenant/
        certificate) — the caller is responsible for also checking the
        returned session's certificate_id matches the one it asked to
        sign with."""
        raise NotImplementedError

    @abstractmethod
    async def increment_signature_count(self, session_id: UUID) -> int:
        """Atomically increments signature_count and returns the new
        value — never a plain read-modify-write, same reasoning as
        certificate-service's increment_failed_pin_attempts."""
        raise NotImplementedError
