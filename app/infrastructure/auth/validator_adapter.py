"""JWT validator with custom claims validation.

Equivalente a hsm-service's ValidatorAdapter
(internal/infrastructure/auth/validator_adapter.go), implementando el
puerto JWTValidator. CustomClaims vive en el puerto
(app/domain/ports/output/JWTValidator.py), no acá.
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import jwt

from app.domain.ports.output.JWTKeyProvider import JWTKeyProvider
from app.domain.ports.output.JWTValidator import CustomClaims, JWTValidator
from app.infrastructure.external.redis.token_cache import TokenCache


class JWTValidatorAdapter(JWTValidator):
    def __init__(
        self,
        key_manager: JWTKeyProvider,
        issuer: Optional[str],
        audience: Optional[str],
        token_cache: Optional[TokenCache] = None,
        token_cache_enabled: bool = False,
        token_cache_strict: bool = True,
    ):
        self._key_manager = key_manager
        self._issuer = issuer
        self._audience = audience
        self._token_cache = token_cache
        self._token_cache_enabled = token_cache_enabled
        self._token_cache_strict = token_cache_strict

    def validate_token(self, token_string: str) -> CustomClaims:
        header = jwt.get_unverified_header(token_string)
        kid = header.get("kid")

        public_key = self._key_manager.get_public_key(kid)
        options: Dict[str, bool] = {}
        if not self._audience:
            options["verify_aud"] = False

        decode_kwargs: Dict[str, Any] = {
            "algorithms": ["RS256", "RS384", "RS512"],
            "options": options,
        }
        if self._audience:
            decode_kwargs["audience"] = self._audience
        if self._issuer:
            decode_kwargs["issuer"] = self._issuer

        claims = jwt.decode(token_string, public_key, **decode_kwargs)

        self._validate_claims(claims)
        self._validate_token_cache(claims)
        return CustomClaims(
            token_id=_resolve_token_id(claims),
            tenant_id=claims.get("tenant_id", ""),
            owner_type=claims.get("owner_type", ""),
            owner_id=claims.get("owner_id", ""),
            organization_id=claims.get("organization_id"),
            parent_key_id=claims.get("parent_key_id"),
            user_id=claims.get("user_id", ""),
            cert_level=int(claims.get("cert_level", 0)),
            max_cert_level=int(claims.get("max_cert_level", 0)),
            can_certify=bool(claims.get("can_certify", False)),
            certification_path=claims.get("certification_path", ""),
            permissions=claims.get("permissions") or {},
        )

    def _validate_claims(self, claims: Dict[str, Any]) -> None:
        if claims.get("tenant_id", "") == "":
            raise ValueError("tenant_id is required")
        if claims.get("owner_id", "") == "":
            raise ValueError("owner_id is required")

    def _validate_token_cache(self, claims: Dict[str, Any]) -> None:
        if not self._token_cache_enabled:
            return
        if not self._token_cache:
            raise ValueError("token cache is enabled but not configured")
        token_id = _resolve_token_id(claims)
        if not token_id:
            raise ValueError("token_id/jti is required for token cache")
        try:
            if not self._token_cache.exists(token_id):
                raise ValueError("token revoked or not found in cache")
        except Exception:
            if self._token_cache_strict:
                raise


def _resolve_token_id(claims: Dict[str, Any]) -> Optional[str]:
    return claims.get("token_id") or claims.get("jti")
