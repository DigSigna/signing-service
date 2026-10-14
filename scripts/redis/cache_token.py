"""Store a token_id/jti in Redis with TTL.

Usage:
    python scripts/redis/cache_token.py --token-id <id> --ttl 3600

Environment variables:
  REDIS_HOST, REDIS_PORT, REDIS_PASSWORD, REDIS_DB, AUTH_TOKEN_CACHE_PREFIX
"""

from __future__ import annotations

import argparse
import os
import sys
from typing import Any, Dict

from redis import Redis


def _get_env(name: str, default: str = "") -> str:
    return os.getenv(name, default)


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Cache token id in Redis")
    parser.add_argument("--token-id", required=True, help="Token id")
    parser.add_argument("--ttl", type=int, default=3600, help="TTL in seconds")
    return parser.parse_args()


def main() -> int:
    args = _parse_args()
    token_id = str(args.token_id)

    prefix = _get_env("AUTH_TOKEN_CACHE_PREFIX", "token")
    key = f"{prefix}:{token_id}"

    client = Redis(
        host=_get_env("REDIS_HOST", "localhost"),
        port=int(_get_env("REDIS_PORT", "6379")),
        password=_get_env("REDIS_PASSWORD") or None,
        db=int(_get_env("REDIS_DB", "0")),
        decode_responses=True,
    )
    client.setex(key, args.ttl, "active")
    print(f"Cached token_id {token_id} with TTL {args.ttl}s")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:  # pragma: no cover
        print(f"Error: {exc}", file=sys.stderr)
        raise SystemExit(1)
