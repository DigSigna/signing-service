"""HTTP client adapter for certificate-service's verify-pin endpoint
(ADR-005). Mirrors RemoteHSMClient's style (app/infrastructure/external/
hsm/http_client.py): stateless forwarding of the caller's own JWT, no
fixed service token.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

import httpx

from app.domain.exceptions.domain_errors import (
    DomainError,
    SigningPinInvalidError,
    SigningPinLockedError,
    SigningPinNotApplicableError,
    SigningPinNotSetError,
    SigningPinVerificationUnavailableError,
)
from app.domain.ports.output.SigningPinVerifier import SigningPinVerifier

_ERROR_CODES: Dict[str, type] = {
    "SIGNING_PIN_INVALID": SigningPinInvalidError,
    "SIGNING_PIN_LOCKED": SigningPinLockedError,
    "SIGNING_PIN_NOT_SET": SigningPinNotSetError,
    "SIGNING_PIN_NOT_APPLICABLE": SigningPinNotApplicableError,
}


@dataclass(frozen=True)
class RemoteSigningPinVerifierConfig:
    base_url: str
    timeout_seconds: float = 5.0


class RemoteSigningPinVerifier(SigningPinVerifier):
    def __init__(
        self,
        config: RemoteSigningPinVerifierConfig,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        if not config.base_url:
            raise ValueError(
                "CERTIFICATE_SERVICE_BASE_URL is required to verify signing PINs"
            )
        self._config = config
        self._client = http_client

    async def verify(self, certificate_id: UUID, pin: str, bearer_token: str) -> None:
        url = (
            f"{self._config.base_url.rstrip('/')}"
            f"/internal/certificates/{certificate_id}/verify-pin"
        )
        token = bearer_token.strip()
        headers = {
            "Authorization": (
                token if token.lower().startswith("bearer ") else f"Bearer {token}"
            )
        }
        timeout = httpx.Timeout(self._config.timeout_seconds)
        client = self._client or httpx.AsyncClient(timeout=timeout)
        should_close = self._client is None
        try:
            response = await client.post(url, json={"pin": pin}, headers=headers)
        except httpx.RequestError as exc:
            raise SigningPinVerificationUnavailableError(
                f"certificate-service unreachable: {exc}"
            ) from exc
        finally:
            if should_close:
                await client.aclose()

        if response.status_code == 200:
            return

        raise _map_error_response(response)


def _map_error_response(response: httpx.Response) -> DomainError:
    try:
        body = response.json()
        error = body.get("error", {})
        code = error.get("code")
        message = error.get("message", "Signing PIN verification failed")
        details = error.get("details", {}) or {}
    except ValueError:
        return SigningPinVerificationUnavailableError(
            f"certificate-service returned a non-JSON error "
            f"(status {response.status_code}): {response.text}"
        )

    error_cls = _ERROR_CODES.get(code)
    if error_cls is None:
        return SigningPinVerificationUnavailableError(
            f"certificate-service returned an unrecognized error code "
            f"'{code}' (status {response.status_code}): {message}"
        )

    kwargs: Dict[str, Any] = {}
    if error_cls is SigningPinInvalidError:
        kwargs["remaining_attempts"] = details.get("remaining_attempts")
    elif error_cls is SigningPinLockedError:
        locked_until = details.get("locked_until")
        if locked_until:
            kwargs["locked_until"] = datetime.fromisoformat(locked_until)

    return error_cls(message, **kwargs)
