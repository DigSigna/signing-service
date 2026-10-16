from enum import Enum


class SigningRequestStatus(str, Enum):
    """signing_requests.status (migrations 003 + 026). SIGNED is legacy
    only — pre-multi-signer rows written before signing-plan.md point 4;
    no code path written after this point ever writes it, but reads must
    tolerate it existing on old rows."""

    PENDING = "PENDING"
    SIGNED = "SIGNED"
    COMPLETED = "COMPLETED"
    PENDING_TSA_RETRY = "PENDING_TSA_RETRY"
    FAILED = "FAILED"
    CANCELLED = "CANCELLED"
    EXPIRED = "EXPIRED"
