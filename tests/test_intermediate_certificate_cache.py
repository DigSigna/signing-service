from datetime import datetime, timedelta, timezone
from uuid import UUID

import pytest

from app.domain.ports.output.CertificateClient import CertificateClient, CertificateInfo
from app.infrastructure.external.certificate.intermediate_cache import (
    IntermediateCertificateCache,
)

CERT_ID = UUID(int=1)


def _info(pem: str) -> CertificateInfo:
    return CertificateInfo(
        id=CERT_ID,
        tenant_id=UUID(int=2),
        key_id=UUID(int=3),
        common_name="Test CA",
        is_ca=True,
        status="ACTIVE",
        not_before=datetime(2026, 1, 1, tzinfo=timezone.utc),
        not_after=datetime(2027, 1, 1, tzinfo=timezone.utc),
        pem=pem,
    )


class _FakeCertificateClient(CertificateClient):
    def __init__(self):
        self.pem = "first-pem"
        self.calls = 0

    async def get_certificate(self, certificate_id, bearer_token):
        self.calls += 1
        return _info(self.pem)

    async def validate_chain(self, certificate_id, bearer_token):
        raise NotImplementedError


@pytest.mark.asyncio
async def test_second_call_within_ttl_does_not_refetch():
    client = _FakeCertificateClient()
    cache = IntermediateCertificateCache(client, ttl=timedelta(hours=1))

    first = await cache.get_pem(CERT_ID, "jwt")
    client.pem = "second-pem"  # simulates a rotation that shouldn't be seen yet
    second = await cache.get_pem(CERT_ID, "jwt")

    assert first == "first-pem"
    assert second == "first-pem"
    assert client.calls == 1


@pytest.mark.asyncio
async def test_refetches_after_ttl_expires():
    client = _FakeCertificateClient()
    cache = IntermediateCertificateCache(client, ttl=timedelta(seconds=0))

    first = await cache.get_pem(CERT_ID, "jwt")
    client.pem = "second-pem"
    second = await cache.get_pem(CERT_ID, "jwt")

    assert first == "first-pem"
    assert second == "second-pem"
    assert client.calls == 2


@pytest.mark.asyncio
async def test_different_certificate_ids_are_cached_independently():
    client = _FakeCertificateClient()
    cache = IntermediateCertificateCache(client, ttl=timedelta(hours=1))
    other_id = UUID(int=99)

    await cache.get_pem(CERT_ID, "jwt")
    await cache.get_pem(other_id, "jwt")

    assert client.calls == 2
