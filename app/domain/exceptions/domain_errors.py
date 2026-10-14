"""Domain-level exception definitions for signing-service.

Equivalente Python de hsm-service/internal/domain/exceptions/domain_errors.go,
adaptado al idioma del lenguaje: Go usa un único struct DomainError{Code, Message,
Details} + un switch de ErrorCode porque no tiene excepciones; Python sí las
tiene, así que mantenemos una jerarquía de dataclasses (ya establecida en este
archivo y consumida por IdentityContext.py / http_client.py) en lugar de
aplanarla a un solo tipo. Lo que SÍ se porta explícitamente del archivo Go:

- Un `code` estable por error (ClassVar, no depende del nombre de la clase)
  para que ErrorHandlingMiddleware pueda mapear cualquier DomainError a una
  respuesta HTTP consistente sin una cadena de isinstance.
- Un `http_status` por error, en vez de que el middleware decida caso por caso.
- Un `details` dict por instancia para contexto estructurado adicional
  (equivalente a `Details map[string]interface{}` + `WithDetail` en Go) —
  pero `with_detail` devuelve una copia nueva (dataclasses.replace) en vez de
  mutar in-place: el patrón Go mutaba el *mismo puntero* que podían ser
  singletons compartidos (`DomainErrKeyNotFound.WithDetail(...)`), lo cual
  filtra detalles entre call sites distintos. No se replica ese patrón acá.
"""

from __future__ import annotations

from dataclasses import dataclass, field, fields, replace
from typing import Any, ClassVar, Dict, Optional


@dataclass
class DomainError(Exception):
    """Base class for all domain errors."""

    code: ClassVar[str] = "INTERNAL_ERROR"
    http_status: ClassVar[int] = 500

    message: str
    details: Dict[str, Any] = field(default_factory=dict)

    def __str__(self) -> str:  # pragma: no cover - trivial
        return self.message

    def with_detail(self, key: str, value: Any) -> "DomainError":
        """Returns a new instance with an added detail; never mutates self."""
        return replace(self, details={**self.details, key: value})

    def to_dict(self) -> Dict[str, Any]:
        """Merges every subclass-specific field (e.g. CertificateChain
        InvalidError.broken_at, ValidationError.field, NotFoundError.
        entity_id) into `details` — previously only the base `message`/
        `details` were ever serialized, so every subclass's own extra
        field was silently dropped from the HTTP response, defeating its
        purpose (a caller could never actually learn broken_at)."""
        extra = {
            f.name: getattr(self, f.name)
            for f in fields(self)
            if f.name not in ("message", "details")
            and getattr(self, f.name) is not None
        }
        return {
            "code": self.code,
            "message": self.message,
            "details": {**extra, **self.details},
        }


def get_error_code(error: Optional[BaseException]) -> str:
    """Equivalente a GetCode en hsm-service: "SUCCESS" si no hubo error,
    el código del DomainError si lo es, "INTERNAL_ERROR" para cualquier otra
    excepción. Pensado para decorators de auditoría (ver
    AuditedTenantCARepository) que reportan el resultado de una operación
    sin conocer su tipo de error concreto."""

    if error is None:
        return "SUCCESS"
    if isinstance(error, DomainError):
        return error.code
    return "INTERNAL_ERROR"


# ---------------------------------------------------------------------------
# Genéricos
# ---------------------------------------------------------------------------


@dataclass
class ValidationError(DomainError):
    """Raised when domain invariants or input validation fails."""

    code: ClassVar[str] = "VALIDATION_ERROR"
    http_status: ClassVar[int] = 400

    field: Optional[str] = None


@dataclass
class NotFoundError(DomainError):
    """Raised when a domain entity is not found."""

    code: ClassVar[str] = "NOT_FOUND"
    http_status: ClassVar[int] = 404

    entity: Optional[str] = None
    entity_id: Optional[str] = None


@dataclass
class AuthorizationError(DomainError):
    """Raised when authorization checks fail."""

    code: ClassVar[str] = "AUTHORIZATION_ERROR"
    http_status: ClassVar[int] = 403


@dataclass
class ConfigurationError(DomainError):
    """Raised when required configuration is missing or invalid."""

    code: ClassVar[str] = "CONFIGURATION_ERROR"
    http_status: ClassVar[int] = 500


@dataclass
class DuplicateRequestError(DomainError):
    """Raised when an idempotency key collides with an in-flight/completed
    request. Equivalente a ErrDuplicateRequest en hsm-service. Hoy respaldado
    solo por una tabla local de idempotencia (sin verification-service ni
    audit-service todavía — ver CLAUDE.md, handler híbrido pendiente)."""

    code: ClassVar[str] = "DUPLICATE_REQUEST"
    http_status: ClassVar[int] = 409

    idempotency_key: Optional[str] = None


# ---------------------------------------------------------------------------
# Identidad / ownership (ya en uso por IdentityContext)
# ---------------------------------------------------------------------------


@dataclass
class TenantRequiredError(DomainError):
    """Se requiere un Tenant ID."""

    code: ClassVar[str] = "TENANT_REQUIRED"
    http_status: ClassVar[int] = 400


@dataclass
class OwnerIdRequiredError(DomainError):
    """Se requiere un Owner ID."""

    code: ClassVar[str] = "OWNER_ID_REQUIRED"
    http_status: ClassVar[int] = 400


@dataclass
class InvalidOwnerTypeError(DomainError):
    """El tipo de propietario no es válido."""

    code: ClassVar[str] = "INVALID_OWNER_TYPE"
    http_status: ClassVar[int] = 400


# ---------------------------------------------------------------------------
# HSM (vía RemoteHSMClient — este servicio nunca toca el HSM directamente)
# ---------------------------------------------------------------------------


@dataclass
class HsmError(DomainError):
    """Base class for HSM-related failures."""

    code: ClassVar[str] = "HSM_ERROR"
    http_status: ClassVar[int] = 502


@dataclass
class HsmConnectionError(HsmError):
    """Raised when the HSM client cannot connect or initialize."""

    code: ClassVar[str] = "HSM_CONNECTION_ERROR"
    http_status: ClassVar[int] = 503


@dataclass
class HsmOperationError(HsmError):
    """Raised when an HSM operation fails."""

    code: ClassVar[str] = "HSM_OPERATION_FAILED"
    http_status: ClassVar[int] = 502


# ---------------------------------------------------------------------------
# Auditoría (estrategia híbrida: HTTP primero, DB como fallback)
# ---------------------------------------------------------------------------


@dataclass
class AuditError(DomainError):
    """Base class for audit transport errors."""

    code: ClassVar[str] = "AUDIT_ERROR"
    http_status: ClassVar[int] = 500


@dataclass
class AuditDispatchError(AuditError):
    """Raised when sending audit events fails."""

    code: ClassVar[str] = "AUDIT_DISPATCH_FAILED"


@dataclass
class AuditStorageError(AuditError):
    """Raised when storing audit events locally fails."""

    code: ClassVar[str] = "AUDIT_STORAGE_FAILED"
