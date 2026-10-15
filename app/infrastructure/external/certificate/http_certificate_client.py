"""HTTP client adapter for certificate-service's certificate lookup and
chain-validation endpoints. Same stateless-forwarding convention as
RemoteHSMClient and RemoteSigningPinVerifier: the original caller's JWT
is forwarded as-is, no fixed service token.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, Optional
from uuid import UUID

import httpx

from app.domain.exceptions.domain_errors import (
    CertificateServiceUnavailableError,
    NotFoundError,
)
from app.domain.ports.output.CertificateClient import (
    CertificateClient,
    CertificateInfo,
    ChainLink,
    ChainValidationResult,
)


@dataclass(frozen=True)
class RemoteCertificateClientConfig:
    base_url: str
    timeout_seconds: float = 5.0


class RemoteCertificateClient(CertificateClient):
    def __init__(
        self,
        config: RemoteCertificateClientConfig,
        http_client: Optional[httpx.AsyncClient] = None,
    ) -> None:
        if not config.base_url:
            raise ValueError(
                "CERTIFICATE_SERVICE_BASE_URL is required to look up certificates"
            )
        self._config = config
        self._client = http_client

    async def get_certificate(
        self, certificate_id: UUID, bearer_token: str
    ) -> CertificateInfo:
        response = await self._get(
            f"/api/v1/certificates/{certificate_id}", bearer_token
        )
        if response.status_code == 404:
            raise NotFoundError(
                "Certificate not found",
                entity="certificate",
                entity_id=str(certificate_id),
            )
        if response.status_code != 200:
            raise _unavailable("get_certificate", response)

        data = _parse_json("get_certificate", response)
        try:
            return CertificateInfo(
                id=UUID(data["id"]),
                tenant_id=UUID(data["tenant_id"]),
                key_id=UUID(data["key_id"]),
                common_name=data["common_name"],
                is_ca=data["is_ca"],
                status=data["status"],
                not_before=datetime.fromisoformat(data["not_before"]),
                not_after=datetime.fromisoformat(data["not_after"]),
                pem=data["pem"],
                issuer_certificate_id=(
                    UUID(data["issuer_certificate_id"])
                    if data.get("issuer_certificate_id")
                    else None
                ),
            )
        except (KeyError, ValueError) as exc:
            raise CertificateServiceUnavailableError(
                f"certificate-service returned an unparseable certificate: {exc}"
            ) from exc

    async def validate_chain(
        self, certificate_id: UUID, bearer_token: str
    ) -> ChainValidationResult:
        response = await self._post(
            "/internal/certificates/validate-chain",
            {"certificate_id": str(certificate_id)},
            bearer_token,
        )
        if response.status_code != 200:
            raise _unavailable("validate_chain", response)

        data = _parse_json("validate_chain", response)
        try:
            return ChainValidationResult(
                valid=data["valid"],
                chain=[
                    ChainLink(
                        certificate_id=UUID(link["certificate_id"]),
                        common_name=link["common_name"],
                        cert_level=link["cert_level"],
                        status=link["status"],
                    )
                    for link in data["chain"]
                ],
            )
        except (KeyError, ValueError) as exc:
            raise CertificateServiceUnavailableError(
                f"certificate-service returned an unparseable chain result: {exc}"
            ) from exc

    async def _get(self, path: str, bearer_token: str) -> httpx.Response:
        return await self._request("GET", path, None, bearer_token)

    async def _post(
        self, path: str, payload: Dict[str, Any], bearer_token: str
    ) -> httpx.Response:
        return await self._request("POST", path, payload, bearer_token)

    async def _request(
        self,
        method: str,
        path: str,
        payload: Optional[Dict[str, Any]],
        bearer_token: str,
    ) -> httpx.Response:
        url = f"{self._config.base_url.rstrip('/')}{path}"
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
            return await client.request(method, url, json=payload, headers=headers)
        except httpx.RequestError as exc:
            raise CertificateServiceUnavailableError(
                f"certificate-service unreachable: {exc}"
            ) from exc
        finally:
            if should_close:
                await client.aclose()


def _unavailable(
    op: str, response: httpx.Response
) -> CertificateServiceUnavailableError:
    return CertificateServiceUnavailableError(
        f"certificate-service's {op} failed (status {response.status_code}): "
        f"{response.text}"
    )


def _parse_json(op: str, response: httpx.Response) -> Dict[str, Any]:
    try:
        return response.json()
    except ValueError as exc:
        raise CertificateServiceUnavailableError(
            f"certificate-service's {op} returned a non-JSON response: {exc}"
        ) from exc
