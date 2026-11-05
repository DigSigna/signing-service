from __future__ import annotations

import base64
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.domain.ports.input.CancelSigningRequestUseCase import (
    CancelSigningRequestResult,
)
from app.domain.ports.input.CreateSigningRequestUseCase import (
    CreateSigningRequestResult,
)
from app.domain.ports.input.GetSigningRequestUseCase import GetSigningRequestResult
from app.domain.ports.input.SignDocumentUseCase import SignDocumentResult
from app.domain.ports.input.SignIncrementUseCase import SignIncrementResult
from app.domain.ports.input.VoidSigningRequestUseCase import VoidSigningRequestResult

_PIN_PATTERN = r"^\d{4,6}$"
_MAX_SIGNERS = 20  # pragmatic guard against abuse, not a modeled business limit.


class SignDocumentRequest(BaseModel):
    certificate_id: UUID
    document_b64: str = Field(..., description="Documento completo, base64")
    document_name: Optional[str] = Field(None, max_length=255)
    pin: Optional[str] = Field(
        None,
        pattern=_PIN_PATTERN,
        description="Requerido si no se presenta un session_token vigente",
    )
    session_token: Optional[str] = Field(
        None,
        description="Devuelto por una firma anterior — evita re-pedir el PIN "
        "dentro de la ventana de gracia (ADR-005)",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "certificate_id": "eb6dc1bc-74e9-43cd-9b0c-e47e36d6f7bd",
                "document_b64": "JVBERi0xLjQK...",
                "document_name": "contrato.pdf",
                "pin": "193042",
            }
        }
    )


class SignDocumentResponse(BaseModel):
    signing_request_id: UUID
    signature_id: UUID
    certificate_id: UUID
    document_hash: str = Field(..., description="SHA-256 del documento original, hex")
    signed_document_b64: str = Field(
        ...,
        description="El PDF completo, con la firma PAdES-B embebida (incremental "
        "update) — no una firma separada del documento",
    )
    signature_format: str = Field(
        ..., description="PAdES-T si se logró sellar con un TSA real, PAdES-B si no"
    )
    signing_time: datetime
    tsa_provider: Optional[str] = Field(
        None,
        description="'freetsa'/'certum' si un TSA real selló la firma; "
        "'local-pseudo' si ambos TSA fallaron (ADR-002) — no bloquea la firma, "
        "pero esta fila necesitará re-sellado más adelante",
    )
    tsa_sealed_at: Optional[datetime] = None
    session_token: Optional[str] = Field(
        None,
        description="Usar en la próxima firma dentro de session_expires_at para "
        "saltar el PIN. None en una respuesta repetida (idempotency replay).",
    )
    session_expires_at: Optional[datetime] = None

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "signing_request_id": "a1b2c3d4-0000-0000-0000-000000000001",
                "signature_id": "a1b2c3d4-0000-0000-0000-000000000002",
                "certificate_id": "eb6dc1bc-74e9-43cd-9b0c-e47e36d6f7bd",
                "document_hash": (
                    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
                ),
                "signed_document_b64": "JVBERi0xLjQK...",
                "signature_format": "PAdES-T",
                "signing_time": "2026-10-15T19:30:00+00:00",
                "tsa_provider": "freetsa",
                "tsa_sealed_at": "2026-10-15T19:30:01+00:00",
                "session_token": "9f2c...",
                "session_expires_at": "2026-10-15T19:50:00+00:00",
            }
        }
    )

    @classmethod
    def from_result(cls, result: SignDocumentResult) -> "SignDocumentResponse":
        return cls(
            signing_request_id=result.signing_request_id,
            signature_id=result.signature_id,
            certificate_id=result.certificate_id,
            document_hash=result.document_hash,
            signed_document_b64=base64.b64encode(result.signature_value).decode(
                "utf-8"
            ),
            signature_format=result.signature_format,
            signing_time=result.signing_time,
            tsa_provider=result.tsa_provider,
            tsa_sealed_at=result.tsa_sealed_at,
            session_token=result.session_token,
            session_expires_at=result.session_expires_at,
        )


# ---------------------------------------------------------------------------
# N-signer flow (signing-plan.md point 4): POST /signing-requests,
# POST /signing-requests/{id}/sign, GET /signing-requests/{id}.
# ---------------------------------------------------------------------------


class CreateSigningRequestRequest(BaseModel):
    document_b64: str = Field(..., description="Documento completo, base64")
    document_name: Optional[str] = Field(None, max_length=255)
    signers_number: int = Field(
        1,
        ge=1,
        le=_MAX_SIGNERS,
        description="Cuántas firmas se necesitan antes de COMPLETED",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "document_b64": "JVBERi0xLjQK...",
                "document_name": "contrato.pdf",
                "signers_number": 2,
            }
        }
    )


class CreateSigningRequestResponse(BaseModel):
    signing_request_id: UUID
    status: str
    signers_number: int
    signatures_count: int
    created_at: datetime

    @classmethod
    def from_result(
        cls, result: CreateSigningRequestResult
    ) -> "CreateSigningRequestResponse":
        return cls(
            signing_request_id=result.signing_request_id,
            status=result.status,
            signers_number=result.signers_number,
            signatures_count=result.signatures_count,
            created_at=result.created_at,
        )


class SignIncrementRequest(BaseModel):
    certificate_id: UUID
    pin: Optional[str] = Field(
        None,
        pattern=_PIN_PATTERN,
        description="Requerido si no se presenta un session_token vigente",
    )
    session_token: Optional[str] = Field(
        None,
        description="Devuelto por una firma anterior — evita re-pedir el PIN "
        "dentro de la ventana de gracia (ADR-005)",
    )

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "certificate_id": "eb6dc1bc-74e9-43cd-9b0c-e47e36d6f7bd",
                "pin": "193042",
            }
        }
    )


class SignIncrementResponse(BaseModel):
    signing_request_id: UUID
    signature_id: UUID
    certificate_id: UUID
    status: str = Field(
        ...,
        description="PENDING si quedan firmantes, COMPLETED si esta firma "
        "cerró el request",
    )
    signers_number: int
    signatures_count: int
    signature_format: str
    signing_time: datetime
    tsa_provider: Optional[str] = Field(
        None,
        description="Solo se intenta sellar la firma que completa el request "
        "(signing-plan.md punto 4.2) — None en firmas intermedias",
    )
    tsa_sealed_at: Optional[datetime] = None
    session_token: Optional[str] = None
    session_expires_at: Optional[datetime] = None

    @classmethod
    def from_result(cls, result: SignIncrementResult) -> "SignIncrementResponse":
        return cls(
            signing_request_id=result.signing_request_id,
            signature_id=result.signature_id,
            certificate_id=result.certificate_id,
            status=result.status,
            signers_number=result.signers_number,
            signatures_count=result.signatures_count,
            signature_format=result.signature_format,
            signing_time=result.signing_time,
            tsa_provider=result.tsa_provider,
            tsa_sealed_at=result.tsa_sealed_at,
            session_token=result.session_token,
            session_expires_at=result.session_expires_at,
        )


class GetSigningRequestResponse(BaseModel):
    signing_request_id: UUID
    status: str
    signers_number: int
    signatures_count: int
    created_at: datetime
    completed_at: Optional[datetime] = None
    document_b64: Optional[str] = Field(
        None, description="Solo presente si status == COMPLETED"
    )
    superseded_by_signing_request_id: Optional[UUID] = Field(
        None,
        description="Id del signing_request nuevo que reemplaza a este "
        "(Caso 3, Opción B) — presente solo si fue marcado como superado",
    )
    voided_at: Optional[datetime] = Field(
        None, description="Cuándo se marcó como superado — None si sigue vigente"
    )
    void_reason: Optional[str] = None

    @classmethod
    def from_result(
        cls, result: GetSigningRequestResult
    ) -> "GetSigningRequestResponse":
        return cls(
            signing_request_id=result.signing_request_id,
            status=result.status,
            signers_number=result.signers_number,
            signatures_count=result.signatures_count,
            created_at=result.created_at,
            completed_at=result.completed_at,
            document_b64=(
                base64.b64encode(result.document).decode("utf-8")
                if result.document is not None
                else None
            ),
            superseded_by_signing_request_id=result.superseded_by_signing_request_id,
            voided_at=result.voided_at,
            void_reason=result.void_reason,
        )


# ---------------------------------------------------------------------------
# Caso 2: cancelar un signing_request de un solo firmante antes de firmar.
# ---------------------------------------------------------------------------


class CancelSigningRequestResponse(BaseModel):
    signing_request_id: UUID
    status: str = Field(..., description="Siempre 'CANCELLED' en una respuesta 200")

    @classmethod
    def from_result(
        cls, result: CancelSigningRequestResult
    ) -> "CancelSigningRequestResponse":
        return cls(
            signing_request_id=result.signing_request_id,
            status=result.status,
        )


# ---------------------------------------------------------------------------
# Caso 3, Opción B: marcar un signing_request ya COMPLETED como superado.
# ---------------------------------------------------------------------------


class VoidSigningRequestRequest(BaseModel):
    superseded_by_signing_request_id: UUID = Field(
        ..., description="Id del signing_request nuevo que reemplaza a este"
    )
    reason: str = Field(..., min_length=1, max_length=255)

    model_config = ConfigDict(
        json_schema_extra={
            "example": {
                "superseded_by_signing_request_id": (
                    "a1b2c3d4-0000-0000-0000-000000000099"
                ),
                "reason": "Corrección de domicilio del firmante",
            }
        }
    )


class VoidSigningRequestResponse(BaseModel):
    signing_request_id: UUID
    status: str = Field(
        ..., description="Siempre 'COMPLETED' -- marcar como superado nunca lo cambia"
    )
    superseded_by_signing_request_id: UUID
    voided_at: datetime
    void_reason: Optional[str] = None

    @classmethod
    def from_result(
        cls, result: VoidSigningRequestResult
    ) -> "VoidSigningRequestResponse":
        return cls(
            signing_request_id=result.signing_request_id,
            status=result.status,
            superseded_by_signing_request_id=result.superseded_by_signing_request_id,
            voided_at=result.voided_at,
            void_reason=result.void_reason,
        )
