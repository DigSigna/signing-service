"""Equivalente a hsm-service's output.IdempotencyRepository
(internal/domain/ports/output/idempotency_repository.go)."""

from abc import ABC, abstractmethod
from typing import Optional

from app.domain.entities.IdempotencyRecord import IdempotencyRecord


class IdempotencyKeyExistsError(Exception):
    """Raised by claim() when (tenant_id, request_id) is already claimed, by
    this request or a concurrent one.

    Deliberately NOT a DomainError: it's an infrastructure-level signal
    meant to be caught by app.application.services.idempotency's
    claim_idempotency_key, which looks up the existing claim to tell a
    completed request (replay its resource_id) apart from one still in
    flight (raise DuplicateRequestError). It should never escape past that
    helper.
    """


class IdempotencyRepository(ABC):
    @abstractmethod
    async def claim(self, tenant_id: str, request_id: str, operation: str) -> None:
        """Atomically reserves (tenant_id, request_id) for operation before
        the real work starts. Raises IdempotencyKeyExistsError if already
        claimed."""
        raise NotImplementedError

    @abstractmethod
    async def find_by_request_id(
        self, tenant_id: str, request_id: str
    ) -> Optional[IdempotencyRecord]:
        raise NotImplementedError

    @abstractmethod
    async def complete(self, tenant_id: str, request_id: str, resource_id: str) -> None:
        """Records the resource created by a successful claimed operation,
        so a future retry can replay it instead of repeating the side
        effect."""
        raise NotImplementedError

    @abstractmethod
    async def release(self, tenant_id: str, request_id: str) -> None:
        """Removes a claim after its operation failed, so a genuine retry
        can claim it again cleanly."""
        raise NotImplementedError
