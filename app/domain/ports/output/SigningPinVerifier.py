from abc import ABC, abstractmethod
from uuid import UUID


class SigningPinVerifier(ABC):
    """Verifies a certificate holder's signing PIN (ADR-005) against
    certificate-service, which owns the PIN end-to-end on its
    `certificates` row. Must be called, and must succeed, before this
    service ever asks hsm-service to sign — a failed check here must
    never reach the HSM layer."""

    @abstractmethod
    async def verify(self, certificate_id: UUID, pin: str, bearer_token: str) -> None:
        """Raises SigningPinInvalidError, SigningPinLockedError,
        SigningPinNotSetError or SigningPinNotApplicableError on failure.
        Returns None on success. bearer_token is the original caller's JWT,
        forwarded as-is — certificate-service requires it to belong to the
        certificate's own holder (no fixed service token, same convention
        RemoteHSMClient already uses for hsm-service)."""
        raise NotImplementedError
