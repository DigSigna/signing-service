"""Domain-level exception definitions for signing-service.

The generic base (DomainError, to_dict/_jsonable, get_error_code, and the
error subclasses that don't belong to any specific business domain —
ValidationError, NotFoundError, AuthorizationError, ConfigurationError,
DuplicateRequestError, TenantRequiredError, OwnerIdRequiredError,
InvalidOwnerTypeError, Hsm*, Audit*) now lives in py_common.errors —
certificate-service's copy of this file (where it was originally copied
from) was byte-for-byte identical up to that point. Only the subclasses
specific to this service's own business domain (signing PIN verification,
certificate lookup/chain validation, signing requests) stay here.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import ClassVar, Optional

from py_common.errors import (  # noqa: F401 - re-exported for existing importers
    AuditDispatchError,
    AuditError,
    AuditStorageError,
    AuthorizationError,
    ConfigurationError,
    DomainError,
    DuplicateRequestError,
    HsmConnectionError,
    HsmError,
    HsmOperationError,
    InvalidOwnerTypeError,
    NotFoundError,
    OwnerIdRequiredError,
    TenantRequiredError,
    ValidationError,
    get_error_code,
)

__all__ = [
    "AuditDispatchError",
    "AuditError",
    "AuditStorageError",
    "AuthorizationError",
    "CertificateChainInvalidError",
    "CertificateServiceUnavailableError",
    "ConfigurationError",
    "DomainError",
    "DuplicateRequestError",
    "HsmConnectionError",
    "HsmError",
    "HsmOperationError",
    "InvalidOwnerTypeError",
    "NotFoundError",
    "OwnerIdRequiredError",
    "SigningPinError",
    "SigningPinInvalidError",
    "SigningPinLockedError",
    "SigningPinNotApplicableError",
    "SigningPinNotSetError",
    "SigningPinVerificationUnavailableError",
    "SigningRequestConflictError",
    "SigningRequestNotCancellableError",
    "SigningRequestNotCompletedError",
    "SigningRequestNotPendingError",
    "TenantRequiredError",
    "ValidationError",
    "get_error_code",
]

# ---------------------------------------------------------------------------
# Signing PIN (ADR-005) — el PIN en sí vive en certificate-service (dueño
# de la fila `certificates`); este servicio solo consume su endpoint
# interno /internal/certificates/{id}/verify-pin y traduce sus respuestas
# de error a estos equivalentes locales, para que ErrorHandlingMiddleware
# los mapee igual que cualquier otro DomainError propio. No incluye
# SigningPinAlreadySetError (set/reset de PIN no es responsabilidad de
# signing-service).
# ---------------------------------------------------------------------------


@dataclass
class SigningPinError(DomainError):
    """Base class for signing-PIN errors surfaced via certificate-service's
    verify-pin endpoint."""

    code: ClassVar[str] = "SIGNING_PIN_ERROR"
    http_status: ClassVar[int] = 400


@dataclass
class SigningPinNotApplicableError(SigningPinError):
    """Raised when verification is attempted against a CA certificate."""

    code: ClassVar[str] = "SIGNING_PIN_NOT_APPLICABLE"
    http_status: ClassVar[int] = 400


@dataclass
class SigningPinNotSetError(SigningPinError):
    """Raised when verification is attempted before any PIN was ever set."""

    code: ClassVar[str] = "SIGNING_PIN_NOT_SET"
    http_status: ClassVar[int] = 409


@dataclass
class SigningPinInvalidError(SigningPinError):
    """Raised when the PIN is wrong — carries how many attempts remain
    before lockout."""

    code: ClassVar[str] = "SIGNING_PIN_INVALID"
    http_status: ClassVar[int] = 400

    remaining_attempts: Optional[int] = None


@dataclass
class SigningPinLockedError(SigningPinError):
    """Raised when verification is attempted during an active lockout
    window — 423, mirroring certificate-service's own choice."""

    code: ClassVar[str] = "SIGNING_PIN_LOCKED"
    http_status: ClassVar[int] = 423

    locked_until: Optional[datetime] = None


@dataclass
class SigningPinVerificationUnavailableError(SigningPinError):
    """Raised when certificate-service is unreachable, times out, or
    returns a response this service can't parse — distinct from the
    pass/fail outcomes above, which all mean certificate-service was
    reached and answered."""

    code: ClassVar[str] = "SIGNING_PIN_VERIFICATION_UNAVAILABLE"
    http_status: ClassVar[int] = 502


# ---------------------------------------------------------------------------
# Certificate lookup/chain validation (CertificateClient, consumed by the
# /sign use case before it ever asks hsm-service to sign)
# ---------------------------------------------------------------------------


@dataclass
class CertificateServiceUnavailableError(DomainError):
    """Raised when certificate-service is unreachable, times out, or
    returns a response this service can't parse, for either
    get_certificate or validate_chain."""

    code: ClassVar[str] = "CERTIFICATE_SERVICE_UNAVAILABLE"
    http_status: ClassVar[int] = 502


@dataclass
class CertificateChainInvalidError(DomainError):
    """Raised by the /sign use case when CertificateClient.validate_chain
    returns valid=False — expired/revoked/broken-signature somewhere
    between the leaf and the root. certificate-service itself doesn't
    raise this (it returns {valid: false, chain: [...]} as a normal 200
    response); this service is the one that decides a broken chain means
    signing must not proceed."""

    code: ClassVar[str] = "CERTIFICATE_CHAIN_INVALID"
    http_status: ClassVar[int] = 422


# ---------------------------------------------------------------------------
# Signing requests (optimistic concurrency, lifecycle state)
# ---------------------------------------------------------------------------


@dataclass
class SigningRequestNotPendingError(DomainError):
    """Raised by SignIncrementUseCaseImpl when the signing_request is no
    longer PENDING (already COMPLETED, or CANCELLED/EXPIRED/FAILED) —
    distinct from NotFoundError (wrong id / wrong tenant)."""

    code: ClassVar[str] = "SIGNING_REQUEST_NOT_PENDING"
    http_status: ClassVar[int] = 409

    current_status: Optional[str] = None


@dataclass
class SigningRequestConflictError(DomainError):
    """Raised when SigningRequestRepository.append_signature/cancel/void
    loses the optimistic-concurrency race (signing-plan.md point 4) —
    another call on the same signing_request_id committed first. The
    client should retry the whole call (fresh PIN/session resolution for
    /sign; a fresh GET + decision for /cancel or /void), never silently
    retried server-side."""

    code: ClassVar[str] = "SIGNING_REQUEST_CONFLICT"
    http_status: ClassVar[int] = 409


@dataclass
class SigningRequestNotCancellableError(DomainError):
    """Raised by CancelSigningRequestUseCaseImpl when the signing_request
    is structurally out of scope for cancellation in this MVP slice
    (Caso 2): more than one signer (signers_number > 1 — would need to
    know which of the N signers already signed, left as a future
    extension), or no single identifiable owner (user_id IS NULL,
    i.e. ORGANIZATION-owned). Distinct from SigningRequestNotPendingError
    (right shape, wrong lifecycle state)."""

    code: ClassVar[str] = "SIGNING_REQUEST_NOT_CANCELLABLE"
    http_status: ClassVar[int] = 422

    signing_request_id: Optional[str] = None


@dataclass
class SigningRequestNotCompletedError(DomainError):
    """Raised by VoidSigningRequestUseCaseImpl when the OLD signing_request
    never reached COMPLETED (Caso 3, Opción B) — superseding only makes
    sense for a document that was actually signed; a request still
    PENDING should be cancelled instead (CancelSigningRequestUseCase),
    not voided."""

    code: ClassVar[str] = "SIGNING_REQUEST_NOT_COMPLETED"
    http_status: ClassVar[int] = 409

    current_status: Optional[str] = None
