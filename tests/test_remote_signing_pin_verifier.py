import json
from datetime import datetime, timezone
from uuid import UUID

import httpx
import pytest

from app.domain.exceptions.domain_errors import (
    SigningPinInvalidError,
    SigningPinLockedError,
    SigningPinNotApplicableError,
    SigningPinNotSetError,
    SigningPinVerificationUnavailableError,
)
from app.infrastructure.external.certificate.http_pin_verifier import (
    RemoteSigningPinVerifier,
    RemoteSigningPinVerifierConfig,
)

CERT_ID = UUID(int=1)


def _error_response(status: int, code: str, message: str = "failed", details=None):
    return httpx.Response(
        status,
        json={"error": {"code": code, "message": message, "details": details or {}}},
    )


def _client_for(handler) -> httpx.AsyncClient:
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport, base_url="http://cert-service")


@pytest.mark.asyncio
async def test_verify_success_forwards_bearer_token_and_pin():
    def handler(request: httpx.Request):
        assert request.url.path == f"/internal/certificates/{CERT_ID}/verify-pin"
        assert request.method == "POST"
        assert json.loads(request.content) == {"pin": "193042"}
        assert request.headers["authorization"] == "Bearer caller-jwt"
        return httpx.Response(200, json={"valid": True})

    async with _client_for(handler) as client:
        verifier = RemoteSigningPinVerifier(
            RemoteSigningPinVerifierConfig(base_url="http://cert-service"),
            http_client=client,
        )
        # Must not raise.
        await verifier.verify(CERT_ID, "193042", bearer_token="caller-jwt")


@pytest.mark.asyncio
async def test_verify_invalid_pin_raises_with_remaining_attempts():
    def handler(_request: httpx.Request):
        return _error_response(
            400,
            "SIGNING_PIN_INVALID",
            "Incorrect signing PIN",
            {"remaining_attempts": 3},
        )

    async with _client_for(handler) as client:
        verifier = RemoteSigningPinVerifier(
            RemoteSigningPinVerifierConfig(base_url="http://cert-service"),
            http_client=client,
        )
        with pytest.raises(SigningPinInvalidError) as exc_info:
            await verifier.verify(CERT_ID, "000000", bearer_token="caller-jwt")

        assert exc_info.value.remaining_attempts == 3


@pytest.mark.asyncio
async def test_verify_locked_raises_with_locked_until_parsed():
    locked_until = datetime(2026, 1, 1, tzinfo=timezone.utc)

    def handler(_request: httpx.Request):
        return _error_response(
            423,
            "SIGNING_PIN_LOCKED",
            "locked",
            {"locked_until": locked_until.isoformat()},
        )

    async with _client_for(handler) as client:
        verifier = RemoteSigningPinVerifier(
            RemoteSigningPinVerifierConfig(base_url="http://cert-service"),
            http_client=client,
        )
        with pytest.raises(SigningPinLockedError) as exc_info:
            await verifier.verify(CERT_ID, "000000", bearer_token="caller-jwt")

        assert exc_info.value.locked_until == locked_until


@pytest.mark.asyncio
async def test_verify_not_set_raises():
    def handler(_request: httpx.Request):
        return _error_response(409, "SIGNING_PIN_NOT_SET", "no pin set")

    async with _client_for(handler) as client:
        verifier = RemoteSigningPinVerifier(
            RemoteSigningPinVerifierConfig(base_url="http://cert-service"),
            http_client=client,
        )
        with pytest.raises(SigningPinNotSetError):
            await verifier.verify(CERT_ID, "000000", bearer_token="caller-jwt")


@pytest.mark.asyncio
async def test_verify_not_applicable_raises():
    def handler(_request: httpx.Request):
        return _error_response(400, "SIGNING_PIN_NOT_APPLICABLE", "is a CA")

    async with _client_for(handler) as client:
        verifier = RemoteSigningPinVerifier(
            RemoteSigningPinVerifierConfig(base_url="http://cert-service"),
            http_client=client,
        )
        with pytest.raises(SigningPinNotApplicableError):
            await verifier.verify(CERT_ID, "000000", bearer_token="caller-jwt")


@pytest.mark.asyncio
async def test_verify_unrecognized_error_code_raises_unavailable():
    def handler(_request: httpx.Request):
        return _error_response(404, "CERTIFICATE_NOT_FOUND", "no such certificate")

    async with _client_for(handler) as client:
        verifier = RemoteSigningPinVerifier(
            RemoteSigningPinVerifierConfig(base_url="http://cert-service"),
            http_client=client,
        )
        with pytest.raises(SigningPinVerificationUnavailableError):
            await verifier.verify(CERT_ID, "000000", bearer_token="caller-jwt")


@pytest.mark.asyncio
async def test_verify_connection_error_raises_unavailable():
    def handler(_request: httpx.Request):
        raise httpx.ConnectError("boom")

    async with _client_for(handler) as client:
        verifier = RemoteSigningPinVerifier(
            RemoteSigningPinVerifierConfig(base_url="http://cert-service"),
            http_client=client,
        )
        with pytest.raises(SigningPinVerificationUnavailableError):
            await verifier.verify(CERT_ID, "000000", bearer_token="caller-jwt")


def test_requires_base_url():
    with pytest.raises(ValueError):
        RemoteSigningPinVerifier(RemoteSigningPinVerifierConfig(base_url=""))
