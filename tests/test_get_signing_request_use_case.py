from datetime import datetime, timezone
from typing import Dict, Optional
from uuid import UUID, uuid4

import pytest

from app.application.use_cases.get_signing_request import GetSigningRequestUseCaseImpl
from app.domain.entities.Signature import Signature
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.exceptions.domain_errors import NotFoundError
from app.domain.ports.output.SigningRequestRepository import (
    SigningRequestRepository,
)
from py_common.auth.identity_context import IdentityContext
from py_common.auth.owner_type import OwnerType
from app.domain.valueobjects.SigningRequestStatus import SigningRequestStatus

TENANT_ID = UUID(int=1)
OTHER_TENANT_ID = UUID(int=77)
USER_ID = UUID(int=4)
PDF_DOCUMENT = b"%PDF-1.4 fake test document"


def _identity() -> IdentityContext:
    return IdentityContext(
        tenant_id=str(TENANT_ID),
        owner_type=OwnerType.USER,
        owner_id=str(USER_ID),
        user_id=str(USER_ID),
        cert_level=2,
        max_cert_level=2,
        can_certify=False,
        certification_path="",
        permissions=[],
    )


class _FakeSigningRequestRepository(SigningRequestRepository):
    def __init__(self):
        self.requests: Dict[UUID, SigningRequest] = {}

    async def create(self, request: SigningRequest) -> None:
        self.requests[request.id] = request

    async def find_by_id(self, signing_request_id: UUID) -> Optional[SigningRequest]:
        return self.requests.get(signing_request_id)

    async def find_signature_by_id(self, signature_id: UUID) -> Optional[Signature]:
        return None

    async def append_signature(self, *args, **kwargs) -> bool:
        raise NotImplementedError

    async def cancel(self, *args, **kwargs) -> bool:
        raise NotImplementedError

    async def void(self, *args, **kwargs) -> bool:
        raise NotImplementedError


def _make_request(status: SigningRequestStatus, **overrides) -> SigningRequest:
    defaults = dict(
        id=uuid4(),
        tenant_id=TENANT_ID,
        document_name="contrato.pdf",
        document_hash="deadbeef",
        hash_algorithm="SHA256",
        signers_number=1,
        signatures_count=0,
        status=status,
        document_blob=PDF_DOCUMENT,
        user_id=USER_ID,
        organization_id=None,
        created_at=datetime.now(timezone.utc),
        completed_at=None,
        version=0,
    )
    defaults.update(overrides)
    return SigningRequest(**defaults)


@pytest.mark.asyncio
async def test_pending_request_never_exposes_the_document():
    repo = _FakeSigningRequestRepository()
    request = _make_request(SigningRequestStatus.PENDING)
    await repo.create(request)
    use_case = GetSigningRequestUseCaseImpl(repo)

    result = await use_case.execute(request.id, _identity())

    assert result.status == "PENDING"
    assert result.document is None


@pytest.mark.asyncio
async def test_completed_request_returns_the_document_verbatim():
    repo = _FakeSigningRequestRepository()
    request = _make_request(
        SigningRequestStatus.COMPLETED,
        signatures_count=1,
        completed_at=datetime.now(timezone.utc),
    )
    await repo.create(request)
    use_case = GetSigningRequestUseCaseImpl(repo)

    result = await use_case.execute(request.id, _identity())

    assert result.status == "COMPLETED"
    assert result.document == PDF_DOCUMENT
    assert result.completed_at is not None


@pytest.mark.asyncio
async def test_unknown_id_raises_not_found():
    repo = _FakeSigningRequestRepository()
    use_case = GetSigningRequestUseCaseImpl(repo)

    with pytest.raises(NotFoundError):
        await use_case.execute(uuid4(), _identity())


@pytest.mark.asyncio
async def test_other_tenants_request_raises_not_found():
    repo = _FakeSigningRequestRepository()
    request = _make_request(SigningRequestStatus.COMPLETED)
    request.tenant_id = OTHER_TENANT_ID
    await repo.create(request)
    use_case = GetSigningRequestUseCaseImpl(repo)

    with pytest.raises(NotFoundError):
        await use_case.execute(request.id, _identity())
