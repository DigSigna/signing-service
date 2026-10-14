from uuid import UUID

import pytest
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa

from app.domain.valueobjects import Algorithm, KeyPurpose, Owner, OwnerType
from app.infrastructure.external.hsm.in_memory_client import InMemoryHSMClient


@pytest.mark.asyncio
async def test_in_memory_hsm_rsa_sign_verify():
    client = InMemoryHSMClient()
    owner = Owner(type=OwnerType.TENANT, id=UUID(int=1))

    key_id = await client.create_key(
        tenant_id=UUID(int=2),
        name="test",
        algorithm=Algorithm.RSA,
        key_size=2048,
        purpose=KeyPurpose.SIGNING,
        owner=owner,
        bearer_token="caller-jwt",
    )

    public_der = await client.get_public_key(key_id)
    public_key = serialization.load_der_public_key(public_der)

    # sign_hash takes raw data; the HSM hashes internally (see HSMClient.sign_hash).
    payload = b"hello-world"
    signature = await client.sign_hash(key_id, payload, bearer_token="caller-jwt")

    assert isinstance(signature, bytes)
    assert signature

    assert isinstance(public_key, rsa.RSAPublicKey)
    public_key.verify(signature, payload, padding.PKCS1v15(), hashes.SHA256())


@pytest.mark.asyncio
async def test_in_memory_hsm_ecdsa_sign_verify():
    client = InMemoryHSMClient()
    owner = Owner(type=OwnerType.TENANT, id=UUID(int=3))

    key_id = await client.create_key(
        tenant_id=UUID(int=4),
        name="test",
        algorithm=Algorithm.ECDSA,
        key_size=256,
        purpose=KeyPurpose.SIGNING,
        owner=owner,
        bearer_token="caller-jwt",
    )

    public_der = await client.get_public_key(key_id)
    public_key = serialization.load_der_public_key(public_der)

    payload = b"hello-world"
    signature = await client.sign_hash(key_id, payload, bearer_token="caller-jwt")

    assert isinstance(signature, bytes)
    assert signature

    assert isinstance(public_key, ec.EllipticCurvePublicKey)
    public_key.verify(signature, payload, ec.ECDSA(hashes.SHA256()))
