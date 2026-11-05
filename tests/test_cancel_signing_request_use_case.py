from dataclasses import replace
from datetime import datetime, timezone
from typing import Dict, Optional
from uuid import UUID, uuid4

import pytest

from app.application.use_cases.cancel_signing_request import (
    CancelSigningRequestUseCaseImpl,
)
from app.domain.entities.Signature import Signature
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.exceptions.domain_errors import (
    AuthorizationError,
    NotFoundError,
    SigningRequestConflictError,
    SigningRequestNotCancellableError,
    SigningRequestNotPendingError,
)
from app.domain.ports.input.CancelSigningRequestUseCase import (
    CancelSigningRequestCommand,
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
PDF_DOCUMENT = b"%PDF-1.4 fake test document"


def _identity(user_id: UUID = USER_ID) -> IdentityContext:
    return IdentityContext(
        tenant_id=str(TENANT_ID),
        owner_type=OwnerType.USER,
        owner_id=str(user_id),
        user_id=str(user_id),
        cert_level=2,
        max_cert_level=2,
        can_certify=False,
        certification_path="",
        permissions=[],
    )


class _FakeSigningRequestRepository(SigningRequestRepository):
    def __init__(self):
        self.requests: Dict[UUID, SigningRequest] = {}
        # Set by a test to simulate a concurrent write winning the race
        # right before this repo's own cancel() runs.
        self.sabotage_version_before_cancel: Dict[UUID, bool] = {}

    async def create(self, request: SigningRequest) -> None:
        self.requests[request.id] = request

    async def find_by_id(self, signing_request_id: UUID) -> Optional[SigningRequest]:
        request = self.requests.get(signing_request_id)
        return replace(request) if request is not None else None

    async def find_signature_by_id(self, signature_id: UUID) -> Optional[Signature]:
        return None

    async def append_signature(self, *args, **kwargs) -> bool:
        raise NotImplementedError

    async def cancel(
        self,
        signing_request_id: UUID,
        expected_version: int,
    ) -> bool:
        request = self.requests[signing_request_id]
        if self.sabotage_version_before_cancel.get(signing_request_id):
            request.version += 1  # simulate a concurrent write winning first
        if request.version != expected_version:
            return False
        request.status = SigningRequestStatus.CANCELLED
        request.version += 1
        return True

    async def void(self, *args, **kwargs) -> bool:
        raise NotImplementedError


def _make_request(**overrides) -> SigningRequest:
    defaults = dict(
        id=uuid4(),
        tenant_id=TENANT_ID,
        document_name="contrato.pdf",
        document_hash="deadbeef",
        hash_algorithm="SHA256",
        signers_number=1,
        signatures_count=0,
        status=SigningRequestStatus.PENDING,
        document_blob=PDF_DOCUMENT,
        user_id=USER_ID,
        organization_id=None,
        created_at=datetime.now(timezone.utc),
        completed_at=None,
        version=0,
    )
    defaults.update(overrides)
    return SigningRequest(**defaults)


def _build_use_case(repo: SigningRequestRepository) -> CancelSigningRequestUseCaseImpl:
    return CancelSigningRequestUseCaseImpl(
        signing_request_repo=repo,
        idempotency_repo=None,
        audit_dispatcher=None,
    )


@pytest.mark.asyncio
async def test_owner_cancels_pending_single_signer_request():
    repo = _FakeSigningRequestRepository()
    request = _make_request()
    await repo.create(request)
    use_case = _build_use_case(repo)

    result = await use_case.execute(
        CancelSigningRequestCommand(signing_request_id=request.id), _identity()
    )

    assert result.status == "CANCELLED"
    assert repo.requests[request.id].status == SigningRequestStatus.CANCELLED
    assert repo.requests[request.id].version == 1


@pytest.mark.asyncio
async def test_unknown_signing_request_raises_not_found():
    use_case = _build_use_case(_FakeSigningRequestRepository())

    with pytest.raises(NotFoundError):
        await use_case.execute(
            CancelSigningRequestCommand(signing_request_id=uuid4()), _identity()
        )


@pytest.mark.asyncio
async def test_signing_request_from_another_tenant_raises_not_found():
    repo = _FakeSigningRequestRepository()
    request = _make_request(tenant_id=OTHER_TENANT_ID)
    await repo.create(request)
    use_case = _build_use_case(repo)

    with pytest.raises(NotFoundError):
        await use_case.execute(
            CancelSigningRequestCommand(signing_request_id=request.id), _identity()
        )


@pytest.mark.asyncio
async def test_multi_signer_request_is_out_of_scope():
    repo = _FakeSigningRequestRepository()
    request = _make_request(signers_number=2)
    await repo.create(request)
    use_case = _build_use_case(repo)

    with pytest.raises(SigningRequestNotCancellableError):
        await use_case.execute(
            CancelSigningRequestCommand(signing_request_id=request.id), _identity()
        )
    # Rejected before touching the row at all.
    assert repo.requests[request.id].status == SigningRequestStatus.PENDING


@pytest.mark.asyncio
async def test_organization_owned_request_with_no_user_id_is_out_of_scope():
    repo = _FakeSigningRequestRepository()
    request = _make_request(user_id=None, organization_id=ORG_ID)
    await repo.create(request)
    use_case = _build_use_case(repo)

    with pytest.raises(SigningRequestNotCancellableError):
        await use_case.execute(
            CancelSigningRequestCommand(signing_request_id=request.id),
            _identity(),
        )


@pytest.mark.asyncio
async def test_someone_else_cannot_cancel_another_users_request():
    repo = _FakeSigningRequestRepository()
    request = _make_request(user_id=USER_ID)
    await repo.create(request)
    use_case = _build_use_case(repo)

    with pytest.raises(AuthorizationError):
        await use_case.execute(
            CancelSigningRequestCommand(signing_request_id=request.id),
            _identity(user_id=OTHER_USER_ID),
        )
    assert repo.requests[request.id].status == SigningRequestStatus.PENDING


@pytest.mark.asyncio
async def test_already_completed_request_cannot_be_cancelled():
    repo = _FakeSigningRequestRepository()
    request = _make_request(
        status=SigningRequestStatus.COMPLETED,
        signatures_count=1,
        completed_at=datetime.now(timezone.utc),
    )
    await repo.create(request)
    use_case = _build_use_case(repo)

    with pytest.raises(SigningRequestNotPendingError):
        await use_case.execute(
            CancelSigningRequestCommand(signing_request_id=request.id), _identity()
        )


@pytest.mark.asyncio
async def test_already_cancelled_request_rejects_a_second_cancel():
    repo = _FakeSigningRequestRepository()
    request = _make_request(status=SigningRequestStatus.CANCELLED)
    await repo.create(request)
    use_case = _build_use_case(repo)

    with pytest.raises(SigningRequestNotPendingError):
        await use_case.execute(
            CancelSigningRequestCommand(signing_request_id=request.id), _identity()
        )


@pytest.mark.asyncio
async def test_concurrent_write_loses_optimistic_lock_raises_conflict():
    repo = _FakeSigningRequestRepository()
    request = _make_request()
    await repo.create(request)
    repo.sabotage_version_before_cancel[request.id] = True
    use_case = _build_use_case(repo)

    with pytest.raises(SigningRequestConflictError):
        await use_case.execute(
            CancelSigningRequestCommand(signing_request_id=request.id), _identity()
        )
