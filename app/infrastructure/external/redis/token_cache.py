"""Redis-backed token cache for JWT status checks."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from redis import Redis


@dataclass(frozen=True)
class TokenCacheConfig:
    host: str
    port: int
    password: str
    db: int
    prefix: str = "token"
    socket_timeout: float = 1.0


class TokenCache:
    def __init__(
        self, config: TokenCacheConfig, client: Optional[Redis] = None
    ) -> None:
        self._config = config
        self._client = client or Redis(
            host=config.host,
            port=config.port,
            password=config.password or None,
            db=config.db,
            socket_timeout=config.socket_timeout,
            socket_connect_timeout=config.socket_timeout,
            decode_responses=True,
        )

    def exists(self, token_id: str) -> bool:
        key = self._format_key(token_id)
        return bool(self._client.exists(key))

    def set_token(self, token_id: str, ttl_seconds: int) -> None:
        key = self._format_key(token_id)
        self._client.setex(key, ttl_seconds, "active")

    def _format_key(self, token_id: str) -> str:
        return f"{self._config.prefix}:{token_id}"
