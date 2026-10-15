import json
from datetime import datetime, timezone
from uuid import UUID

import httpx
import pytest

from app.domain.exceptions.domain_errors import (
    CertificateServiceUnavailableError,
    NotFoundError,
)
from app.infrastructure.external.certificate.http_certificate_client import (
    RemoteCertificateClient,
    RemoteCertificateClientConfig,
)

CERT_ID = UUID(int=1)
KEY_ID = UUID(int=2)
TENANT_ID = UUID(int=3)


def _client_for(handler) -> httpx.AsyncClient:
    transport = httpx.MockTransport(handler)
    return httpx.AsyncClient(transport=transport, base_url="http://cert-service")


def _certificate_json():
    return {
        "id": str(CERT_ID),
        "tenant_id": str(TENANT_ID),
        "key_id": str(KEY_ID),
        "common_name": "Jane Doe",
        "is_ca": False,
        "status": "ACTIVE",
        "not_before": datetime(2026, 1, 1, tzinfo=timezone.utc).isoformat(),
        "not_after": datetime(2027, 1, 1, tzinfo=timezone.utc).isoformat(),
        "pem": "-----BEGIN CERTIFICATE-----\nMII...\n-----END CERTIFICATE-----",
    }


@pytest.mark.asyncio
async def test_get_certificate_success_forwards_bearer_token():
    def handler(request: httpx.Request):
        assert request.url.path == f"/api/v1/certificates/{CERT_ID}"
        assert request.method == "GET"
        assert request.headers["authorization"] == "Bearer caller-jwt"
        return httpx.Response(200, json=_certificate_json())

    async with _client_for(handler) as client:
        remote = RemoteCertificateClient(
            RemoteCertificateClientConfig(base_url="http://cert-service"),
            http_client=client,
        )
        info = await remote.get_certificate(CERT_ID, bearer_token="caller-jwt")

        assert info.id == CERT_ID
        assert info.key_id == KEY_ID
        assert info.tenant_id == TENANT_ID
        assert info.is_ca is False
        assert info.status == "ACTIVE"


@pytest.mark.asyncio
async def test_get_certificate_not_found():
    def handler(_request: httpx.Request):
        return httpx.Response(
            404,
            json={
                "error": {"code": "NOT_FOUND", "message": "not found", "details": {}}
            },
        )

    async with _client_for(handler) as client:
        remote = RemoteCertificateClient(
            RemoteCertificateClientConfig(base_url="http://cert-service"),
            http_client=client,
        )
        with pytest.raises(NotFoundError) as exc_info:
            await remote.get_certificate(CERT_ID, bearer_token="caller-jwt")

        assert exc_info.value.entity == "certificate"


@pytest.mark.asyncio
async def test_get_certificate_unparseable_response_raises_unavailable():
    def handler(_request: httpx.Request):
        return httpx.Response(200, json={"id": str(CERT_ID)})  # missing fields

    async with _client_for(handler) as client:
        remote = RemoteCertificateClient(
            RemoteCertificateClientConfig(base_url="http://cert-service"),
            http_client=client,
        )
        with pytest.raises(CertificateServiceUnavailableError):
            await remote.get_certificate(CERT_ID, bearer_token="caller-jwt")


@pytest.mark.asyncio
async def test_validate_chain_success():
    def handler(request: httpx.Request):
        assert request.url.path == "/internal/certificates/validate-chain"
        assert json.loads(request.content) == {"certificate_id": str(CERT_ID)}
        return httpx.Response(
            200,
            json={
                "valid": True,
                "chain": [
                    {
                        "certificate_id": str(CERT_ID),
                        "common_name": "Jane Doe",
                        "cert_level": 2,
                        "status": "ACTIVE",
                    }
                ],
            },
        )

    async with _client_for(handler) as client:
        remote = RemoteCertificateClient(
            RemoteCertificateClientConfig(base_url="http://cert-service"),
            http_client=client,
        )
        result = await remote.validate_chain(CERT_ID, bearer_token="caller-jwt")

        assert result.valid is True
        assert result.chain[0].certificate_id == CERT_ID


@pytest.mark.asyncio
async def test_validate_chain_invalid_is_not_raised():
    """valid=False is a normal 200 response — the client just reports it;
    deciding what it means is the use case's job, not this adapter's."""

    def handler(_request: httpx.Request):
        return httpx.Response(
            200,
            json={
                "valid": False,
                "chain": [
                    {
                        "certificate_id": str(CERT_ID),
                        "common_name": "Jane Doe",
                        "cert_level": 2,
                        "status": "EXPIRED",
                    }
                ],
            },
        )

    async with _client_for(handler) as client:
        remote = RemoteCertificateClient(
            RemoteCertificateClientConfig(base_url="http://cert-service"),
            http_client=client,
        )
        result = await remote.validate_chain(CERT_ID, bearer_token="caller-jwt")

        assert result.valid is False
        assert result.chain[0].status == "EXPIRED"


@pytest.mark.asyncio
async def test_validate_chain_connection_error_raises_unavailable():
    def handler(_request: httpx.Request):
        raise httpx.ConnectError("boom")

    async with _client_for(handler) as client:
        remote = RemoteCertificateClient(
            RemoteCertificateClientConfig(base_url="http://cert-service"),
            http_client=client,
        )
        with pytest.raises(CertificateServiceUnavailableError):
            await remote.validate_chain(CERT_ID, bearer_token="caller-jwt")


def test_requires_base_url():
    with pytest.raises(ValueError):
        RemoteCertificateClient(RemoteCertificateClientConfig(base_url=""))
