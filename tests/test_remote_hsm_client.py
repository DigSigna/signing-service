import base64
import json
from uuid import UUID

import httpx
import pytest

from app.domain.valueobjects import Algorithm, KeyPurpose, Owner, OwnerType
from app.infrastructure.external.hsm.http_client import RemoteHSMClient, RemoteHSMConfig


@pytest.mark.asyncio
async def test_remote_hsm_client_create_key_and_sign():
    """Mocks hsm-service's real routes/payloads exactly as confirmed against
    the live service (router.go, key_dtos.go, key_handler.go) — not the
    client's own (previously wrong) assumptions, to actually catch
    URL/field-name regressions instead of just mirroring the bug."""

    key_id = UUID(int=1)
    public_key = b"public-key"
    signature = b"signature"

    def handler(request: httpx.Request):
        if request.url.path == "/api/v1/keys" and request.method == "POST":
            body = json.loads(request.content)
            assert body == {
                "name": "test",
                "algorithm": "RSA",
                "key_size": 2048,
                "usage": "SIGNING",
            }
            # Stateless services: no fixed service token, the caller's own
            # JWT is forwarded as-is.
            assert request.headers["authorization"] == "Bearer caller-jwt"
            # KeyHandler.CreateKey responds with "id", not "key_id".
            return httpx.Response(201, json={"id": str(key_id)})
        if (
            request.url.path == f"/api/v1/public/keys/{key_id}/public-key"
            and request.method == "GET"
        ):
            # Public, unauthenticated — no Authorization header expected.
            assert "authorization" not in request.headers
            return httpx.Response(
                200,
                json={
                    "public_key": base64.b64encode(public_key).decode("utf-8"),
                    "key_id": str(key_id),
                },
            )
        if request.url.path == "/api/v1/keys/sign" and request.method == "POST":
            body = json.loads(request.content)
            assert body == {
                "key_id": str(key_id),
                "hash": base64.b64encode(b"data").decode("utf-8"),
            }
            assert request.headers["authorization"] == "Bearer caller-jwt"
            return httpx.Response(
                200,
                json={
                    "signature": base64.b64encode(signature).decode("utf-8"),
                    "key_id": str(key_id),
                },
            )
        return httpx.Response(404, json={"error": "not found"})

    transport = httpx.MockTransport(handler)
    async with httpx.AsyncClient(transport=transport, base_url="http://hsm") as client:
        remote = RemoteHSMClient(
            RemoteHSMConfig(base_url="http://hsm"), http_client=client
        )
        owner = Owner(type=OwnerType.TENANT, id=UUID(int=2))

        created_id = await remote.create_key(
            tenant_id=UUID(int=3),
            name="test",
            algorithm=Algorithm.RSA,
            key_size=2048,
            purpose=KeyPurpose.SIGNING,
            owner=owner,
            bearer_token="caller-jwt",
        )
        assert created_id == key_id

        public_bytes = await remote.get_public_key(key_id)
        assert public_bytes == public_key

        sig = await remote.sign_hash(key_id, b"data", bearer_token="caller-jwt")
        assert sig == signature
