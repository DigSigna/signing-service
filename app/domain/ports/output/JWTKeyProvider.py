"""Equivalente a hsm-service's output.JWTKeyProvider
(internal/domain/ports/output/jwt_key_provider.go)."""

from abc import ABC, abstractmethod
from typing import Optional


class JWTKeyProvider(ABC):
    """Port for JWT key management. Implementations handle loading, caching,
    and retrieving JWT signing keys from various sources (JWKS endpoints,
    PEM files, etc.)."""

    @abstractmethod
    def get_public_key(self, kid: Optional[str]) -> object:
        """Retrieves a public key by its key ID (kid). Raises if the key is
        not found or cannot be retrieved."""
        raise NotImplementedError
