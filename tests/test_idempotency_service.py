from typing import Dict, Optional

import pytest

from app.application.services.idempotency import (
    claim_idempotency_key,
    finish_idempotency_claim,
)
from app.domain.entities.IdempotencyRecord import IdempotencyRecord
from app.domain.exceptions.domain_errors import DuplicateRequestError
from app.domain.ports.output.IdempotencyRepository import (
    IdempotencyKeyExistsError,
    IdempotencyRepository,
)


class _FakeIdempotencyRepository(IdempotencyRepository):
    def __init__(self):
        self._records: Dict[tuple, IdempotencyRecord] = {}
        self.completed_with: Optional[str] = None
        self.released = False

    async def claim(self, tenant_id: str, request_id: str, operation: str) -> None:
        key = (tenant_id, request_id)
        if key in self._records:
            raise IdempotencyKeyExistsError()
        self._records[key] = IdempotencyRecord(
            id="id-1", tenant_id=tenant_id, request_id=request_id, operation=operation
        )

    async def find_by_request_id(self, tenant_id: str, request_id: str):
        return self._records.get((tenant_id, request_id))

    async def complete(self, tenant_id: str, request_id: str, resource_id: str) -> None:
        self.completed_with = resource_id
        record = self._records[(tenant_id, request_id)]
        record.resource_id = resource_id

    async def release(self, tenant_id: str, request_id: str) -> None:
        self.released = True
        del self._records[(tenant_id, request_id)]


@pytest.mark.asyncio
async def test_claim_skips_when_no_request_id():
    repo = _FakeIdempotencyRepository()

    result = await claim_idempotency_key(repo, "tenant-1", None, "ISSUE_CERTIFICATE")

    assert result.claimed is False
    assert result.existing_resource_id is None
    assert repo._records == {}


@pytest.mark.asyncio
async def test_claim_skips_when_no_repo():
    result = await claim_idempotency_key(None, "tenant-1", "req-1", "ISSUE_CERTIFICATE")

    assert result.claimed is False
    assert result.existing_resource_id is None


@pytest.mark.asyncio
async def test_fresh_claim_succeeds():
    repo = _FakeIdempotencyRepository()

    result = await claim_idempotency_key(repo, "tenant-1", "req-1", "ISSUE_CERTIFICATE")

    assert result.claimed is True
    assert result.existing_resource_id is None


@pytest.mark.asyncio
async def test_duplicate_with_completed_resource_is_replayed():
    repo = _FakeIdempotencyRepository()
    await repo.claim("tenant-1", "req-1", "ISSUE_CERTIFICATE")
    await repo.complete("tenant-1", "req-1", "cert-123")

    result = await claim_idempotency_key(repo, "tenant-1", "req-1", "ISSUE_CERTIFICATE")

    assert result.claimed is False
    assert result.existing_resource_id == "cert-123"


@pytest.mark.asyncio
async def test_duplicate_still_in_flight_raises_duplicate_request_error():
    repo = _FakeIdempotencyRepository()
    await repo.claim("tenant-1", "req-1", "ISSUE_CERTIFICATE")

    with pytest.raises(DuplicateRequestError) as exc_info:
        await claim_idempotency_key(repo, "tenant-1", "req-1", "ISSUE_CERTIFICATE")

    assert exc_info.value.idempotency_key == "req-1"
    assert exc_info.value.details["tenant_id"] == "tenant-1"


@pytest.mark.asyncio
async def test_finish_claim_completes_on_success():
    repo = _FakeIdempotencyRepository()
    await repo.claim("tenant-1", "req-1", "ISSUE_CERTIFICATE")

    await finish_idempotency_claim(repo, "tenant-1", "req-1", "cert-123", error=None)

    assert repo.completed_with == "cert-123"
    assert repo.released is False


@pytest.mark.asyncio
async def test_finish_claim_releases_on_failure():
    repo = _FakeIdempotencyRepository()
    await repo.claim("tenant-1", "req-1", "ISSUE_CERTIFICATE")

    await finish_idempotency_claim(
        repo, "tenant-1", "req-1", None, error=RuntimeError("boom")
    )

    assert repo.released is True
    assert repo.completed_with is None


@pytest.mark.asyncio
async def test_finish_claim_without_repo_does_not_crash():
    await finish_idempotency_claim(None, "tenant-1", "req-1", "cert-123", error=None)
