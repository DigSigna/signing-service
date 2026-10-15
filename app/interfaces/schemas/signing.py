from __future__ import annotations

import base64
from datetime import datetime
from typing import Optional
from uuid import UUID

from pydantic import BaseModel, ConfigDict, Field

from app.domain.ports.input.SignDocumentUseCase import SignDocumentResult

_PIN_PATTERN = r"^\d{4,6}$"


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
    signature_format: str = Field(..., description="PAdES-B hoy; XAdES/CAdES a futuro")
    signing_time: datetime
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
                "signature_format": "PAdES-B",
                "signing_time": "2026-10-15T19:30:00+00:00",
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
            session_token=result.session_token,
            session_expires_at=result.session_expires_at,
        )
