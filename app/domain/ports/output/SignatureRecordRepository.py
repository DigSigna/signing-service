from abc import ABC, abstractmethod
from typing import Optional
from uuid import UUID

from app.domain.entities.SignatureRecord import SignatureRecord


class SignatureRecordRepository(ABC):
    @abstractmethod
    async def create(self, record: SignatureRecord) -> None:
        """Persists both the signing_requests and signatures rows for
        `record`, in one transaction."""
        raise NotImplementedError

    @abstractmethod
    async def find_by_id(self, signing_request_id: UUID) -> Optional[SignatureRecord]:
        """Used to replay the result of a signing_request_id previously
        returned as an idempotency claim's resource_id."""
        raise NotImplementedError
