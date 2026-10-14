"""HTTP client adapter for the HSM service."""

from __future__ import annotations

import base64
from dataclasses import dataclass
from typing import Any, Dict, Optional
from uuid import UUID

import httpx

from app.domain.exceptions.domain_errors import HsmConnectionError, HsmOperationError
from app.domain.ports.output.HSMClient import HSMClient
from app.domain.valueobjects import Algorithm, KeyPurpose, Owner


@dataclass(frozen=True)
class RemoteHSMConfig:
    base_url: str
    timeout_seconds: float = 5.0


class RemoteHSMClient(HSMClient):
    """Remote HSM client using HTTP calls to hsm-service."""

    def __init__(
        self, config: RemoteHSMConfig, http_client: Optional[httpx.AsyncClient] = None
    ) -> None:
        if not config.base_url:
            raise ValueError("HSM_SERVICE_BASE_URL is required for remote backend")
        self._config = config
        self._client = http_client

    async def create_key(
        self,
        tenant_id: UUID,
        name: str,
        algorithm: Algorithm,
        key_size: int,
        purpose: KeyPurpose,
        owner: Owner,
        bearer_token: str,
    ) -> UUID:
        # hsm-service's CreateKeyRequest (requests/key_dtos.go) only accepts
        # {name, algorithm, key_size, usage} — tenant_id/owner are derived
        # server-side from the caller's own JWT, and the field is "usage",
        # not "purpose". Stateless services: no fixed service token, the
        # original caller's JWT is forwarded as-is (see bearer_token).
        payload = {
            "name": name,
            "algorithm": algorithm.value,
            "key_size": key_size,
            "usage": purpose.value,
        }
        data = await self._post_json("/api/v1/keys", payload, bearer_token)
        # KeyHandler.CreateKey (key_handler.go) responds with "id", not "key_id".
        key_id = data.get("id")
        if not key_id:
            raise HsmOperationError("Missing id in HSM response")
        return UUID(key_id)

    async def get_public_key(self, key_id: UUID) -> bytes:
        # Public, unauthenticated, not tenant-scoped (router.go: api/public group).
        data = await self._get_json(f"/api/v1/public/keys/{key_id}/public-key")
        value = data.get("public_key") or data.get("public_key_der")
        if not value:
            raise HsmOperationError("Missing public_key in HSM response")
        return base64.b64decode(value)

    async def sign_hash(
        self, key_id: UUID, hash_bytes: bytes, bearer_token: str
    ) -> bytes:
        # key_id travels in the body (SignHashRequest), not the URL path.
        payload = {
            "key_id": str(key_id),
            "hash": base64.b64encode(hash_bytes).decode("utf-8"),
        }
        data = await self._post_json("/api/v1/keys/sign", payload, bearer_token)
        signature = data.get("signature")
        if not signature:
            raise HsmOperationError("Missing signature in HSM response")
        return base64.b64decode(signature)

    async def ping(self, key_id: UUID, bearer_token: str) -> None:
        await self._get_json(f"/api/v1/keys/{key_id}", bearer_token)

    async def _get_json(
        self, path: str, bearer_token: Optional[str] = None
    ) -> Dict[str, Any]:
        return await self._request_json("GET", path, None, bearer_token)

    async def _post_json(
        self, path: str, payload: Dict[str, Any], bearer_token: Optional[str] = None
    ) -> Dict[str, Any]:
        return await self._request_json("POST", path, payload, bearer_token)

    async def _request_json(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]],
        bearer_token: Optional[str] = None,
    ) -> Dict[str, Any]:
        url = f"{self._config.base_url.rstrip('/')}{path}"
        timeout = httpx.Timeout(self._config.timeout_seconds)
        client = self._client or httpx.AsyncClient(timeout=timeout)
        should_close = self._client is None
        headers: Dict[str, str] = {}
        if bearer_token:
            token = bearer_token.strip()
            headers["Authorization"] = (
                token if token.lower().startswith("bearer ") else f"Bearer {token}"
            )
        try:
            response = await client.request(method, url, json=payload, headers=headers)
            response.raise_for_status()
            return response.json()
        except httpx.RequestError as exc:
            raise HsmConnectionError(f"HSM service unreachable: {exc}") from exc
        except httpx.HTTPStatusError as exc:
            raise HsmOperationError(f"HSM request failed: {exc.response.text}") from exc
        finally:
            if should_close:
                await client.aclose()
