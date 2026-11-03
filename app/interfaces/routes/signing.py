from __future__ import annotations

import base64
import binascii
from uuid import UUID

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST

from app.application.use_cases.create_signing_request import (
    CreateSigningRequestUseCaseImpl,
)
from app.application.use_cases.get_signing_request import (
    GetSigningRequestUseCaseImpl,
)
from app.application.use_cases.sign_document import SignDocumentUseCaseImpl
from app.application.use_cases.sign_increment import SignIncrementUseCaseImpl
from app.core.config import get_settings
from app.domain.ports.input.CreateSigningRequestUseCase import (
    CreateSigningRequestCommand,
)
from app.domain.ports.input.SignDocumentUseCase import SignDocumentCommand
from app.domain.ports.input.SignIncrementUseCase import SignIncrementCommand
from py_common.idempotency.sqlalchemy_repository import (
    SQLAlchemyIdempotencyRepository,
)
from app.infrastructure.database.repositories.signing_pin_session_repository import (
    SQLAlchemySigningSessionRepository,
)
from app.infrastructure.database.repositories.signing_request_repository import (
    SQLAlchemySigningRequestRepository,
)
from app.infrastructure.database.repositories.tenant_repository import (
    SQLAlchemyTenantRepository,
)
from app.infrastructure.database.adapters.audited_tenant_repository import (
    AuditedTenantRepository,
)
from app.infrastructure.database.session import get_session
from py_common.auth.permissions import get_identity_context
from app.interfaces.dependencies import (
    get_audit_dispatcher,
    get_bearer_token,
    get_certificate_client,
    get_hsm_client,
    get_intermediate_cache,
    get_pades_signer,
    get_pin_verifier,
)
from app.interfaces.schemas.errors import ErrorResponse
from app.interfaces.schemas.signing import (
    CreateSigningRequestRequest,
    CreateSigningRequestResponse,
    GetSigningRequestResponse,
    SignDocumentRequest,
    SignDocumentResponse,
    SignIncrementRequest,
    SignIncrementResponse,
)

router = APIRouter()

_SIGN_RESPONSES = {
    400: {
        "model": ErrorResponse,
        "description": "ValidationError — document_b64 inválido, o falta pin "
        "sin un session_token vigente",
    },
    403: {
        "model": ErrorResponse,
        "description": "AuthorizationError — el caller debe reenviar el JWT del "
        "propio titular del certificado",
    },
    404: {
        "model": ErrorResponse,
        "description": "NotFoundError — certificate_id no existe o el caller no "
        "tiene autoridad para verlo",
    },
    409: {
        "model": ErrorResponse,
        "description": "SigningPinNotSetError, o DuplicateRequestError si un "
        "request con el mismo X-Request-ID ya está en curso",
    },
    422: {
        "model": ErrorResponse,
        "description": "CertificateChainInvalidError — la cadena del certificado "
        "no valida (expirado/revocado/firma rota en algún eslabón)",
    },
    423: {
        "model": ErrorResponse,
        "description": "SigningPinLockedError — demasiados intentos fallidos",
    },
    502: {
        "model": ErrorResponse,
        "description": "CertificateServiceUnavailableError, "
        "SigningPinVerificationUnavailableError, o HsmError",
    },
}

_SIGN_INCREMENT_RESPONSES = {
    **_SIGN_RESPONSES,
    409: {
        "model": ErrorResponse,
        "description": "SigningPinNotSetError, SigningRequestNotPendingError "
        "(el request ya está COMPLETED/CANCELLED/EXPIRED), "
        "SigningRequestConflictError (otra firma concurrente ganó la carrera "
        "— reintentar), o DuplicateRequestError",
    },
}


def _decode_document(document_b64: str) -> bytes:
    try:
        return base64.b64decode(document_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST, detail="document_b64 is not valid base64"
        ) from exc


def _signing_request_repo(session: AsyncSession) -> SQLAlchemySigningRequestRepository:
    return SQLAlchemySigningRequestRepository(session)


def _tenant_repo(request: Request, session: AsyncSession) -> AuditedTenantRepository:
    return AuditedTenantRepository(
        SQLAlchemyTenantRepository(session), get_audit_dispatcher(request)
    )


def _build_sign_document_use_case(
    request: Request, session: AsyncSession
) -> SignDocumentUseCaseImpl:
    settings = get_settings()
    return SignDocumentUseCaseImpl(
        certificate_client=get_certificate_client(request),
        pin_verifier=get_pin_verifier(request),
        session_repo=SQLAlchemySigningSessionRepository(session),
        signing_request_repo=_signing_request_repo(session),
        hsm_client=get_hsm_client(request),
        pades_signer=get_pades_signer(request),
        intermediate_cache=get_intermediate_cache(request),
        tenant_repo=_tenant_repo(request, session),
        idempotency_repo=SQLAlchemyIdempotencyRepository(session),
        audit_dispatcher=get_audit_dispatcher(request),
        session_ttl_minutes=settings.SIGNING_PIN_SESSION_TTL_MINUTES,
        session_max_signatures=settings.SIGNING_PIN_SESSION_MAX_SIGNATURES,
    )


def _build_create_signing_request_use_case(
    request: Request, session: AsyncSession
) -> CreateSigningRequestUseCaseImpl:
    return CreateSigningRequestUseCaseImpl(
        signing_request_repo=_signing_request_repo(session),
        idempotency_repo=SQLAlchemyIdempotencyRepository(session),
        audit_dispatcher=get_audit_dispatcher(request),
    )


def _build_sign_increment_use_case(
    request: Request, session: AsyncSession
) -> SignIncrementUseCaseImpl:
    settings = get_settings()
    return SignIncrementUseCaseImpl(
        signing_request_repo=_signing_request_repo(session),
        certificate_client=get_certificate_client(request),
        pin_verifier=get_pin_verifier(request),
        session_repo=SQLAlchemySigningSessionRepository(session),
        hsm_client=get_hsm_client(request),
        pades_signer=get_pades_signer(request),
        intermediate_cache=get_intermediate_cache(request),
        tenant_repo=_tenant_repo(request, session),
        idempotency_repo=SQLAlchemyIdempotencyRepository(session),
        audit_dispatcher=get_audit_dispatcher(request),
        session_ttl_minutes=settings.SIGNING_PIN_SESSION_TTL_MINUTES,
        session_max_signatures=settings.SIGNING_PIN_SESSION_MAX_SIGNATURES,
    )


@router.post(
    "/sign",
    response_model=SignDocumentResponse,
    status_code=HTTP_201_CREATED,
    summary="Firmar un documento con un certificado propio (un solo firmante)",
    description="Azúcar sintáctico sobre el flujo de N firmantes "
    "(signing-plan.md punto 4.3): crea un signing_request con "
    "signers_number=1 y lo firma en la misma llamada. Para más de un "
    "firmante usar POST /signing-requests + POST /signing-requests/{id}/sign. "
    "Hashea el documento, obtiene y valida la cadena del certificado vía "
    "certificate-service, resuelve el signing PIN (PIN nuevo o "
    "session_token vigente — ADR-005), pide a hsm-service que firme y "
    "sella con un TSA (ADR-002). Devuelve session_token/session_expires_at "
    "para evitar re-pedir el PIN en la próxima firma dentro de la ventana "
    "de gracia.",
    responses=_SIGN_RESPONSES,
)
async def sign_document(
    request: Request,
    payload: SignDocumentRequest,
    identity=Depends(get_identity_context),
    session: AsyncSession = Depends(get_session),
) -> SignDocumentResponse:
    use_case = _build_sign_document_use_case(request, session)
    bearer_token = get_bearer_token(request)
    document = _decode_document(payload.document_b64)

    command = SignDocumentCommand(
        certificate_id=payload.certificate_id,
        document=document,
        document_name=payload.document_name,
        pin=payload.pin,
        session_token=payload.session_token,
    )
    result = await use_case.execute(command, identity, bearer_token)
    return SignDocumentResponse.from_result(result)


@router.post(
    "/signing-requests",
    response_model=CreateSigningRequestResponse,
    status_code=HTTP_201_CREATED,
    summary="Crear un signing_request para uno o varios firmantes",
    description="Guarda el documento (signing-plan.md punto 4.2) y "
    "responde su id. No firma nada todavía — usar "
    "POST /signing-requests/{id}/sign una vez por firmante.",
    responses={
        400: _SIGN_RESPONSES[400],
        409: _SIGN_RESPONSES[409],
    },
)
async def create_signing_request(
    request: Request,
    payload: CreateSigningRequestRequest,
    identity=Depends(get_identity_context),
    session: AsyncSession = Depends(get_session),
) -> CreateSigningRequestResponse:
    use_case = _build_create_signing_request_use_case(request, session)
    bearer_token = get_bearer_token(request)
    document = _decode_document(payload.document_b64)

    command = CreateSigningRequestCommand(
        document=document,
        document_name=payload.document_name,
        signers_number=payload.signers_number,
    )
    result = await use_case.execute(command, identity, bearer_token)
    return CreateSigningRequestResponse.from_result(result)


@router.post(
    "/signing-requests/{signing_request_id}/sign",
    response_model=SignIncrementResponse,
    status_code=HTTP_201_CREATED,
    summary="Agregar una firma incremental a un signing_request existente",
    description="Un llamado por firmante (signing-plan.md punto 4.2): lee "
    "el documento en su estado actual, agrega la firma de este firmante "
    "sobre ese estado, e incrementa signatures_count. Si esta firma "
    "completa signers_number, sella con un TSA (ADR-002) en el mismo "
    "request y marca status=COMPLETED.",
    responses=_SIGN_INCREMENT_RESPONSES,
)
async def sign_increment(
    request: Request,
    signing_request_id: UUID,
    payload: SignIncrementRequest,
    identity=Depends(get_identity_context),
    session: AsyncSession = Depends(get_session),
) -> SignIncrementResponse:
    use_case = _build_sign_increment_use_case(request, session)
    bearer_token = get_bearer_token(request)

    command = SignIncrementCommand(
        signing_request_id=signing_request_id,
        certificate_id=payload.certificate_id,
        pin=payload.pin,
        session_token=payload.session_token,
    )
    result = await use_case.execute(command, identity, bearer_token)
    return SignIncrementResponse.from_result(result)


@router.get(
    "/signing-requests/{signing_request_id}",
    response_model=GetSigningRequestResponse,
    summary="Consultar el estado de un signing_request",
    description="Solo lectura, sin efectos secundarios (signing-plan.md "
    "punto 4.2). document_b64 solo viene presente si status == COMPLETED.",
    responses={404: _SIGN_RESPONSES[404]},
)
async def get_signing_request(
    signing_request_id: UUID,
    identity=Depends(get_identity_context),
    session: AsyncSession = Depends(get_session),
) -> GetSigningRequestResponse:
    use_case = GetSigningRequestUseCaseImpl(_signing_request_repo(session))
    result = await use_case.execute(signing_request_id, identity)
    return GetSigningRequestResponse.from_result(result)
