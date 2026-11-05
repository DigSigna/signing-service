from dataclasses import replace
from datetime import datetime, timezone
from typing import Dict, Optional
from uuid import UUID, uuid4

import pytest

from app.application.use_cases.void_signing_request import (
    VoidSigningRequestUseCaseImpl,
)
from app.domain.entities.Signature import Signature
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.exceptions.domain_errors import (
    AuthorizationError,
    NotFoundError,
    SigningRequestConflictError,
    SigningRequestNotCompletedError,
)
from app.domain.ports.input.VoidSigningRequestUseCase import (
    VoidSigningRequestCommand,
)
from app.domain.ports.output.SigningRequestRepository import (
    SigningRequestRepository,
)
from py_common.auth.identity_context import IdentityContext
from py_common.auth.owner_type import OwnerType
from app.domain.valueobjects.SigningRequestStatus import SigningRequestStatus

TENANT_ID = UUID(int=1)
OTHER_TENANT_ID = UUID(int=77)
USER_ID = UUID(int=4)
OTHER_USER_ID = UUID(int=5)
ORG_ID = UUID(int=6)
OTHER_ORG_ID = UUID(int=7)
NEW_SIGNING_REQUEST_ID = UUID(int=8)
PDF_DOCUMENT = b"%PDF-1.4 fake test document"


def _identity(
    user_id: UUID = USER_ID,
    owner_type: OwnerType = OwnerType.USER,
    owner_id: Optional[UUID] = None,
) -> IdentityContext:
    return IdentityContext(
        tenant_id=str(TENANT_ID),
        owner_type=owner_type,
        owner_id=str(owner_id if owner_id is not None else user_id),
        user_id=str(user_id),
        cert_level=2,
        max_cert_level=2,
        can_certify=owner_type != OwnerType.USER,
        certification_path="",
        permissions=[],
    )


class _FakeSigningRequestRepository(SigningRequestRepository):
    def __init__(self):
        self.requests: Dict[UUID, SigningRequest] = {}
        # Set by a test to simulate a concurrent write winning the race
        # right before this repo's own void() runs.
        self.sabotage_version_before_void: Dict[UUID, bool] = {}

    async def create(self, request: SigningRequest) -> None:
        self.requests[request.id] = request

    async def find_by_id(self, signing_request_id: UUID) -> Optional[SigningRequest]:
        request = self.requests.get(signing_request_id)
        return replace(request) if request is not None else None

    async def find_signature_by_id(self, signature_id: UUID) -> Optional[Signature]:
        return None

    async def append_signature(self, *args, **kwargs) -> bool:
        raise NotImplementedError

    async def cancel(self, *args, **kwargs) -> bool:
        raise NotImplementedError

    async def void(
        self,
        signing_request_id: UUID,
        expected_version: int,
        superseded_by_signing_request_id: UUID,
        void_reason: str,
        voided_at: datetime,
    ) -> bool:
        request = self.requests[signing_request_id]
        if self.sabotage_version_before_void.get(signing_request_id):
            request.version += 1  # simulate a concurrent write winning first
        if request.version != expected_version:
            return False
        request.superseded_by_signing_request_id = superseded_by_signing_request_id
        request.voided_at = voided_at
        request.void_reason = void_reason
        request.version += 1
        return True


def _make_request(**overrides) -> SigningRequest:
    defaults = dict(
        id=uuid4(),
        tenant_id=TENANT_ID,
        document_name="contrato.pdf",
        document_hash="deadbeef",
        hash_algorithm="SHA256",
        signers_number=1,
        signatures_count=1,
        status=SigningRequestStatus.COMPLETED,
        document_blob=PDF_DOCUMENT,
        user_id=USER_ID,
        organization_id=None,
        created_at=datetime.now(timezone.utc),
        completed_at=datetime.now(timezone.utc),
        version=0,
    )
    defaults.update(overrides)
    return SigningRequest(**defaults)


def _build_use_case(repo: SigningRequestRepository) -> VoidSigningRequestUseCaseImpl:
    return VoidSigningRequestUseCaseImpl(
        signing_request_repo=repo,
        idempotency_repo=None,
        audit_dispatcher=None,
    )


def _command(
    signing_request_id: UUID, reason: str = "superseded"
) -> VoidSigningRequestCommand:
    return VoidSigningRequestCommand(
        signing_request_id=signing_request_id,
        superseded_by_signing_request_id=NEW_SIGNING_REQUEST_ID,
        reason=reason,
    )


@pytest.mark.asyncio
async def test_owner_voids_their_own_completed_request():
    repo = _FakeSigningRequestRepository()
    request = _make_request()
    await repo.create(request)
    use_case = _build_use_case(repo)

    result = await use_case.execute(_command(request.id), _identity())

    assert result.status == "COMPLETED"  # status never changes
    assert result.superseded_by_signing_request_id == NEW_SIGNING_REQUEST_ID
    assert result.void_reason == "superseded"
    assert result.voided_at is not None
    stored = repo.requests[request.id]
    assert stored.status == SigningRequestStatus.COMPLETED
    assert stored.superseded_by_signing_request_id == NEW_SIGNING_REQUEST_ID


@pytest.mark.asyncio
async def test_tenant_admin_can_void_someone_elses_request():
    repo = _FakeSigningRequestRepository()
    request = _make_request(user_id=OTHER_USER_ID)
    await repo.create(request)
    use_case = _build_use_case(repo)
    tenant_admin = _identity(
        user_id=UUID(int=99), owner_type=OwnerType.TENANT, owner_id=TENANT_ID
    )

    result = await use_case.execute(_command(request.id), tenant_admin)

    assert result.superseded_by_signing_request_id == NEW_SIGNING_REQUEST_ID


@pytest.mark.asyncio
async def test_organization_admin_for_the_same_org_can_void():
    repo = _FakeSigningRequestRepository()
    request = _make_request(user_id=None, organization_id=ORG_ID)
    await repo.create(request)
    use_case = _build_use_case(repo)
    org_admin = _identity(
        user_id=UUID(int=99), owner_type=OwnerType.ORGANIZATION, owner_id=ORG_ID
    )

    result = await use_case.execute(_command(request.id), org_admin)

    assert result.superseded_by_signing_request_id == NEW_SIGNING_REQUEST_ID


@pytest.mark.asyncio
async def test_organization_admin_for_a_different_org_cannot_void():
    repo = _FakeSigningRequestRepository()
    request = _make_request(user_id=None, organization_id=ORG_ID)
    await repo.create(request)
    use_case = _build_use_case(repo)
    other_org_admin = _identity(
        user_id=UUID(int=99), owner_type=OwnerType.ORGANIZATION, owner_id=OTHER_ORG_ID
    )

    with pytest.raises(AuthorizationError):
        await use_case.execute(_command(request.id), other_org_admin)


@pytest.mark.asyncio
async def test_unrelated_signing_user_cannot_void_someone_elses_request():
    repo = _FakeSigningRequestRepository()
    request = _make_request(user_id=USER_ID)
    await repo.create(request)
    use_case = _build_use_case(repo)

    with pytest.raises(AuthorizationError):
        await use_case.execute(_command(request.id), _identity(user_id=OTHER_USER_ID))
    assert repo.requests[request.id].superseded_by_signing_request_id is None


@pytest.mark.asyncio
async def test_pending_request_cannot_be_voided():
    repo = _FakeSigningRequestRepository()
    request = _make_request(
        status=SigningRequestStatus.PENDING, signatures_count=0, completed_at=None
    )
    await repo.create(request)
    use_case = _build_use_case(repo)

    with pytest.raises(SigningRequestNotCompletedError):
        await use_case.execute(_command(request.id), _identity())


@pytest.mark.asyncio
async def test_unknown_signing_request_raises_not_found():
    use_case = _build_use_case(_FakeSigningRequestRepository())

    with pytest.raises(NotFoundError):
        await use_case.execute(_command(uuid4()), _identity())


@pytest.mark.asyncio
async def test_signing_request_from_another_tenant_raises_not_found():
    repo = _FakeSigningRequestRepository()
    request = _make_request(tenant_id=OTHER_TENANT_ID)
    await repo.create(request)
    use_case = _build_use_case(repo)

    with pytest.raises(NotFoundError):
        await use_case.execute(_command(request.id), _identity())


@pytest.mark.asyncio
async def test_concurrent_write_loses_optimistic_lock_raises_conflict():
    repo = _FakeSigningRequestRepository()
    request = _make_request()
    await repo.create(request)
    repo.sabotage_version_before_void[request.id] = True
    use_case = _build_use_case(repo)

    with pytest.raises(SigningRequestConflictError):
        await use_case.execute(_command(request.id), _identity())
