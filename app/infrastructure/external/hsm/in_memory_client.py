"""In-memory HSM client adapter for development/testing."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
from typing import Dict
from uuid import UUID, uuid4

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519, padding, rsa

from app.domain.ports.output.HSMClient import HSMClient
from app.domain.valueobjects import Algorithm, KeyPurpose, Owner


@dataclass(frozen=True)
class StoredKey:
    algorithm: Algorithm
    private_key: object


class InMemoryHSMClient(HSMClient):
    """Simple, non-persistent HSM client for local development.

    sign_hash takes the raw data to sign and hashes it (SHA-256) internally
    before signing — matching RemoteHSMClient/hsm-service's real PKCS#11
    mechanism (CKM_SHA256_RSA_PKCS; see client_crypto.go), which also hashes
    internally rather than expecting a pre-computed digest. Do NOT pass an
    already-hashed digest here: it would get hashed twice, producing a
    signature that real X.509 verifiers (which hash the TBS bytes themselves
    exactly once) would reject.
    """

    def __init__(self) -> None:
        self._keys: Dict[UUID, StoredKey] = {}
        self._lock = asyncio.Lock()

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
        del tenant_id, name, purpose, owner, bearer_token
        private_key = self._generate_key(algorithm, key_size)
        key_id = uuid4()
        async with self._lock:
            self._keys[key_id] = StoredKey(algorithm=algorithm, private_key=private_key)
        return key_id

    async def get_public_key(self, key_id: UUID) -> bytes:
        stored = await self._get_key(key_id)
        public_key = stored.private_key.public_key()
        return public_key.public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    async def sign_hash(
        self, key_id: UUID, hash_bytes: bytes, bearer_token: str
    ) -> bytes:
        del bearer_token
        stored = await self._get_key(key_id)
        if stored.algorithm == Algorithm.RSA:
            return stored.private_key.sign(
                hash_bytes,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
        if stored.algorithm in {Algorithm.ECC, Algorithm.ECDSA}:
            return stored.private_key.sign(hash_bytes, ec.ECDSA(hashes.SHA256()))
        if stored.algorithm == Algorithm.ED25519:
            return stored.private_key.sign(hash_bytes)
        raise ValueError(f"unsupported algorithm: {stored.algorithm}")

    async def _get_key(self, key_id: UUID) -> StoredKey:
        async with self._lock:
            stored = self._keys.get(key_id)
        if stored is None:
            raise KeyError(f"key not found: {key_id}")
        return stored

    def _generate_key(self, algorithm: Algorithm, key_size: int) -> object:
        if algorithm == Algorithm.RSA:
            size = key_size if key_size >= 2048 else 2048
            return rsa.generate_private_key(public_exponent=65537, key_size=size)
        if algorithm in {Algorithm.ECC, Algorithm.ECDSA}:
            curve = self._curve_from_size(key_size)
            return ec.generate_private_key(curve)
        if algorithm == Algorithm.ED25519:
            return ed25519.Ed25519PrivateKey.generate()
        raise ValueError(f"unsupported algorithm: {algorithm}")

    @staticmethod
    def _curve_from_size(key_size: int) -> ec.EllipticCurve:
        if key_size >= 521:
            return ec.SECP521R1()
        if key_size >= 384:
            return ec.SECP384R1()
        return ec.SECP256R1()
