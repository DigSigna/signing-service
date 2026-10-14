"""JWT key manager for loading RSA public keys from PEM or JWKS.

Equivalente a hsm-service's KeyManagerAdapter
(internal/infrastructure/auth/key_manager_adapter.go), implementando el
puerto JWTKeyProvider.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from typing import Dict, Optional

import requests
from cryptography.hazmat.primitives import serialization
from jwt.algorithms import RSAAlgorithm

from app.core.logger import get_logger
from app.domain.ports.output.JWTKeyProvider import JWTKeyProvider

logger = get_logger("key-manager")


@dataclass
class KeyManagerConfig:
    mode: str
    public_key_path: str
    jwks_url: str
    jwks_cache_minutes: int = 60


class KeyManagerAdapter(JWTKeyProvider):
    def __init__(self, config: KeyManagerConfig):
        self._config = config
        self._keys: Dict[str, object] = {}
        self._last_fetch: float = 0.0
        self._cache_time = config.jwks_cache_minutes * 60
        self._load_initial_keys()

    def _load_initial_keys(self) -> None:
        if self._config.mode == "development":
            if not self._config.public_key_path:
                raise ValueError("AUTH_PUBLIC_KEY_PATH is required in development mode")
            self._load_from_pem(self._config.public_key_path, "dev-key")
            return
        self._fetch_jwks()

    def _load_from_pem(self, filepath: str, key_id: str) -> None:
        with open(filepath, "rb") as pem_file:
            data = pem_file.read()
        public_key = serialization.load_pem_public_key(data)
        self._keys[key_id] = public_key

    def _fetch_jwks(self) -> None:
        if not self._config.jwks_url:
            raise ValueError("JWKS URL not configured")

        response = requests.get(self._config.jwks_url, timeout=5)
        response.raise_for_status()
        jwks = response.json()

        keys: Dict[str, object] = {}
        for jwk in jwks.get("keys", []):
            kid = jwk.get("kid")
            if not kid:
                continue
            keys[kid] = RSAAlgorithm.from_jwk(json.dumps(jwk))

        self._keys = keys
        self._last_fetch = time.time()

    def get_public_key(self, kid: Optional[str]) -> object:
        if (
            self._config.mode == "production"
            and time.time() - self._last_fetch > self._cache_time
        ):
            try:
                self._fetch_jwks()
            except Exception as exc:
                # No propagamos: seguimos con las claves cacheadas; si el kid
                # pedido ya no está, el lookup de abajo falla igual con un
                # error claro. Pero no podemos silenciarlo sin loguear (ver
                # hallazgo ya documentado en CLAUDE.md / key_manager_adapter.go).
                logger.warning(
                    "Failed to refresh JWKS cache",
                    action="jwks_refresh_failed",
                    error=str(exc),
                )

        if kid:
            key = self._keys.get(kid)
            if key:
                return key
            raise ValueError(f"public key not found for kid: {kid}")

        if len(self._keys) == 1:
            return next(iter(self._keys.values()))

        if "dev-key" in self._keys:
            return self._keys["dev-key"]

        raise ValueError("public key not found and kid missing")
