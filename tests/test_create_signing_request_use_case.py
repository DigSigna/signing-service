import hashlib
from typing import Dict, Optional
from uuid import UUID

import pytest

from app.application.use_cases.create_signing_request import (
    CreateSigningRequestUseCaseImpl,
)
from app.domain.entities.Signature import Signature
from app.domain.entities.SigningRequest import SigningRequest
from app.domain.exceptions.domain_errors import ValidationError
from app.domain.ports.input.CreateSigningRequestUseCase import (
    CreateSigningRequestCommand,
)
from app.domain.ports.output.SigningRequestRepository import (
    SigningRequestRepository,
)
from py_common.auth.identity_context import IdentityContext
from py_common.auth.owner_type import OwnerType
from app.domain.valueobjects.SigningRequestStatus import SigningRequestStatus

TENANT_ID = UUID(int=1)
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


@pytest.mark.asyncio
async def test_create_signing_request_stores_document_as_pending():
    repo = _FakeSigningRequestRepository()
    use_case = CreateSigningRequestUseCaseImpl(signing_request_repo=repo)

    result = await use_case.execute(
        CreateSigningRequestCommand(
            document=PDF_DOCUMENT, document_name="contrato.pdf", signers_number=3
        ),
        _identity(),
        bearer_token="caller-jwt",
    )

    assert result.status == "PENDING"
    assert result.signers_number == 3
    assert result.signatures_count == 0

    stored = repo.requests[result.signing_request_id]
    assert stored.document_blob == PDF_DOCUMENT
    assert stored.document_hash == hashlib.sha256(PDF_DOCUMENT).hexdigest()
    assert stored.document_name == "contrato.pdf"
    assert stored.user_id == USER_ID
    assert stored.status == SigningRequestStatus.PENDING


@pytest.mark.asyncio
async def test_non_pdf_document_rejected():
    repo = _FakeSigningRequestRepository()
    use_case = CreateSigningRequestUseCaseImpl(signing_request_repo=repo)

    with pytest.raises(ValidationError) as exc_info:
        await use_case.execute(
            CreateSigningRequestCommand(
                document=b"not a pdf", document_name=None, signers_number=1
            ),
            _identity(),
            bearer_token="caller-jwt",
        )

    assert exc_info.value.field == "document_b64"
    assert repo.requests == {}
