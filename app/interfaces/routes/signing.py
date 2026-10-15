from __future__ import annotations

import base64
import binascii

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.status import HTTP_201_CREATED, HTTP_400_BAD_REQUEST

from app.application.use_cases.sign_document import SignDocumentUseCaseImpl
from app.core.config import get_settings
from app.domain.ports.input.SignDocumentUseCase import SignDocumentCommand
from app.infrastructure.database.repositories.idempotency_repository import (
    SQLAlchemyIdempotencyRepository,
)
from app.infrastructure.database.repositories.signature_record_repository import (
    SQLAlchemySignatureRecordRepository,
)
from app.infrastructure.database.repositories.signing_pin_session_repository import (
    SQLAlchemySigningSessionRepository,
)
from app.infrastructure.database.session import get_session
from app.interfaces.auth.permissions import get_identity_context
from app.interfaces.dependencies import (
    get_audit_dispatcher,
    get_bearer_token,
    get_certificate_client,
    get_hsm_client,
    get_pin_verifier,
)
from app.interfaces.schemas.errors import ErrorResponse
from app.interfaces.schemas.signing import SignDocumentRequest, SignDocumentResponse

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


def _build_use_case(request: Request, session: AsyncSession) -> SignDocumentUseCaseImpl:
    settings = get_settings()
    return SignDocumentUseCaseImpl(
        certificate_client=get_certificate_client(request),
        pin_verifier=get_pin_verifier(request),
        session_repo=SQLAlchemySigningSessionRepository(session),
        signature_repo=SQLAlchemySignatureRecordRepository(session),
        hsm_client=get_hsm_client(request),
        idempotency_repo=SQLAlchemyIdempotencyRepository(session),
        audit_dispatcher=get_audit_dispatcher(request),
        session_ttl_minutes=settings.SIGNING_PIN_SESSION_TTL_MINUTES,
        session_max_signatures=settings.SIGNING_PIN_SESSION_MAX_SIGNATURES,
    )


@router.post(
    "/sign",
    response_model=SignDocumentResponse,
    status_code=HTTP_201_CREATED,
    summary="Firmar un documento con un certificado propio",
    description="Hashea el documento, obtiene y valida la cadena del "
    "certificado vía certificate-service, resuelve el signing PIN (PIN nuevo "
    "o session_token vigente — ADR-005) y pide a hsm-service que firme. "
    "signature_format es siempre RAW hoy (sin empaquetado PKCS#7/CMS todavía). "
    "Devuelve session_token/session_expires_at para evitar re-pedir el PIN en "
    "la próxima firma dentro de la ventana de gracia.",
    responses=_SIGN_RESPONSES,
)
async def sign_document(
    request: Request,
    payload: SignDocumentRequest,
    identity=Depends(get_identity_context),
    session: AsyncSession = Depends(get_session),
) -> SignDocumentResponse:
    use_case = _build_use_case(request, session)
    bearer_token = get_bearer_token(request)

    try:
        document = base64.b64decode(payload.document_b64, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise HTTPException(
            status_code=HTTP_400_BAD_REQUEST, detail="document_b64 is not valid base64"
        ) from exc

    command = SignDocumentCommand(
        certificate_id=payload.certificate_id,
        document=document,
        document_name=payload.document_name,
        pin=payload.pin,
        session_token=payload.session_token,
    )
    result = await use_case.execute(command, identity, bearer_token)
    return SignDocumentResponse.from_result(result)
