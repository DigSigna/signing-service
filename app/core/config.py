from __future__ import annotations

from functools import lru_cache
from pathlib import Path
import os
import re
from typing import Any, Dict, Optional
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse

import yaml
from pydantic import AliasChoices, AliasPath, Field
from pydantic_settings import BaseSettings, SettingsConfigDict

_ENV_PATTERN = re.compile(r"\$\{([^:}]+)(?::([^}]*))?\}")


def _expand_env(value: str) -> str:
    def _replace(match: re.Match[str]) -> str:
        key = match.group(1)
        default = match.group(2) or ""
        return os.getenv(key, default)

    return _ENV_PATTERN.sub(_replace, value)


def _walk_and_expand(data: Any) -> Any:
    if isinstance(data, dict):
        return {key: _walk_and_expand(value) for key, value in data.items()}
    if isinstance(data, list):
        return [_walk_and_expand(value) for value in data]
    if isinstance(data, str):
        return _expand_env(data)
    return data


def _find_yaml_path() -> Optional[Path]:
    for env_key in ("CONFIG_FILE", "CONFIG_PATH", "CONFIG_YAML"):
        raw = os.getenv(env_key)
        if raw:
            return Path(raw)

    default_path = Path("config/config.yaml")
    if default_path.exists():
        return default_path

    fallback = Path("config/config.yml")
    return fallback if fallback.exists() else None


def _yaml_settings_source() -> Dict[str, Any]:
    path = _find_yaml_path()
    if not path or not path.exists():
        return {}

    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        return {}
    return _walk_and_expand(data)


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=".env",
        case_sensitive=True,
        extra="ignore",
    )

    PROJECT_NAME: str = Field(
        default="Digital Signature Microservice",
        validation_alias=AliasChoices("PROJECT_NAME", AliasPath("project", "name")),
    )
    VERSION: str = Field(
        default="1.0.0",
        validation_alias=AliasChoices("VERSION", AliasPath("project", "version")),
    )
    API_V1_STR: str = Field(
        default="/api/v1",
        validation_alias=AliasChoices("API_V1_STR", AliasPath("project", "api_v1_str")),
    )

    ENVIRONMENT: str = Field(
        default="development",
        validation_alias=AliasChoices("ENVIRONMENT", AliasPath("environment")),
    )
    LOG_LEVEL: str = Field(
        default="INFO",
        validation_alias=AliasChoices("LOG_LEVEL", AliasPath("logging", "level")),
    )

    DB_URL: Optional[str] = Field(
        default=None,
        validation_alias=AliasChoices(
            "DB_URL",
            "DATABASE_URL",
            AliasPath("database", "url"),
            AliasPath("database", "connection_string"),
        ),
    )

    # Redis
    REDIS_HOST: str = Field(
        default="localhost",
        validation_alias=AliasChoices("REDIS_HOST", AliasPath("redis", "host")),
    )
    REDIS_PORT: int = Field(
        default=6379,
        validation_alias=AliasChoices("REDIS_PORT", AliasPath("redis", "port")),
    )
    REDIS_PASSWORD: str = Field(
        default="",
        validation_alias=AliasChoices("REDIS_PASSWORD", AliasPath("redis", "password")),
    )
    REDIS_DB: int = Field(
        default=0,
        validation_alias=AliasChoices("REDIS_DB", AliasPath("redis", "db")),
    )

    # HSM (vía hsm-service; este servicio nunca lo toca directamente)
    HSM_LIBRARY_PATH: str = Field(
        default="",
        validation_alias=AliasChoices(
            "HSM_LIBRARY_PATH", AliasPath("hsm", "library_path")
        ),
    )
    HSM_BACKEND: str = Field(
        default="",
        validation_alias=AliasChoices("HSM_BACKEND", AliasPath("hsm", "backend")),
    )
    HSM_SERVICE_BASE_URL: str = Field(
        default="",
        validation_alias=AliasChoices(
            "HSM_SERVICE_BASE_URL", AliasPath("hsm", "service_base_url")
        ),
    )
    HSM_SERVICE_TIMEOUT: str = Field(
        default="5s",
        validation_alias=AliasChoices(
            "HSM_SERVICE_TIMEOUT", AliasPath("hsm", "service_timeout")
        ),
    )
    HSM_SLOT: int = Field(
        default=0,
        validation_alias=AliasChoices("HSM_SLOT", AliasPath("hsm", "slot")),
    )
    HSM_PIN: str = Field(
        default="",
        validation_alias=AliasChoices("HSM_PIN", AliasPath("hsm", "pin")),
    )
    HSM_TOKEN_LABEL: str = Field(
        default="",
        validation_alias=AliasChoices(
            "HSM_TOKEN_LABEL", AliasPath("hsm", "token_label")
        ),
    )
    HSM_SESSION_TIMEOUT: str = Field(
        default="30s",
        validation_alias=AliasChoices(
            "HSM_SESSION_TIMEOUT", AliasPath("hsm", "session_timeout")
        ),
    )
    HSM_MAX_SESSIONS: int = Field(
        default=10,
        validation_alias=AliasChoices(
            "HSM_MAX_SESSIONS", AliasPath("hsm", "max_sessions")
        ),
    )

    # certificate-service (verify-pin, ADR-005)
    CERTIFICATE_SERVICE_BASE_URL: str = Field(
        default="",
        validation_alias=AliasChoices(
            "CERTIFICATE_SERVICE_BASE_URL",
            AliasPath("certificate_service", "base_url"),
        ),
    )
    CERTIFICATE_SERVICE_TIMEOUT: str = Field(
        default="5s",
        validation_alias=AliasChoices(
            "CERTIFICATE_SERVICE_TIMEOUT", AliasPath("certificate_service", "timeout")
        ),
    )
    CERTIFICATE_CHAIN_CACHE_TTL_HOURS: int = Field(
        default=24,
        validation_alias=AliasChoices(
            "CERTIFICATE_CHAIN_CACHE_TTL_HOURS",
            AliasPath("certificate_service", "chain_cache_ttl_hours"),
        ),
        description="How long an intermediate CA's PEM (fetched to embed in a "
        "PAdES signature's chain) is cached before being re-fetched. Long by "
        "design — it only changes if the CA itself rotates.",
    )

    # RFC 3161 timestamping, primary/secondary fallback chain (ADR-002,
    # signing-plan.md point 3). Both free, public, no account needed —
    # see fallback_timestamper.py's module docstring for why ANF AC
    # (the ADR's original primary) isn't configured here: no publicly
    # documented endpoint, contract-specific per its own TSA policy.
    TSA_PRIMARY_URL: str = Field(
        default="https://freetsa.org/tsr",
        validation_alias=AliasChoices(
            "TSA_PRIMARY_URL", AliasPath("tsa", "primary_url")
        ),
    )
    TSA_SECONDARY_URL: str = Field(
        default="http://time.certum.pl",
        validation_alias=AliasChoices(
            "TSA_SECONDARY_URL", AliasPath("tsa", "secondary_url")
        ),
    )
    TSA_TIMEOUT: str = Field(
        default="5s",
        validation_alias=AliasChoices("TSA_TIMEOUT", AliasPath("tsa", "timeout")),
    )

    # Signing-PIN session grace window (ADR-005)
    SIGNING_PIN_SESSION_TTL_MINUTES: int = Field(
        default=20,
        validation_alias=AliasChoices(
            "SIGNING_PIN_SESSION_TTL_MINUTES",
            AliasPath("signing_pin_session", "ttl_minutes"),
        ),
    )
    SIGNING_PIN_SESSION_MAX_SIGNATURES: int = Field(
        default=0,
        validation_alias=AliasChoices(
            "SIGNING_PIN_SESSION_MAX_SIGNATURES",
            AliasPath("signing_pin_session", "max_signatures"),
        ),
        description="0 = unbounded (only expires_at limits the session)",
    )

    # Audit
    AUDIT_ENABLED: bool = Field(
        default=True,
        validation_alias=AliasChoices("AUDIT_ENABLED", AliasPath("audit", "enabled")),
    )
    AUDIT_STRATEGY: str = Field(
        default="hybrid",
        validation_alias=AliasChoices("AUDIT_STRATEGY", AliasPath("audit", "strategy")),
    )
    AUDIT_HTTP_BASE_URL: str = Field(
        default="",
        validation_alias=AliasChoices(
            "AUDIT_HTTP_BASE_URL", AliasPath("audit", "http", "base_url")
        ),
    )
    AUDIT_HTTP_TIMEOUT: str = Field(
        default="5s",
        validation_alias=AliasChoices(
            "AUDIT_HTTP_TIMEOUT", AliasPath("audit", "http", "timeout")
        ),
    )
    AUDIT_HYBRID_MAX_FAILURES: int = Field(
        default=3,
        validation_alias=AliasChoices(
            "AUDIT_HYBRID_MAX_FAILURES",
            AliasPath("audit", "hybrid", "circuit_breaker", "max_failures"),
        ),
    )
    AUDIT_HYBRID_RESET_TIMEOUT: str = Field(
        default="30s",
        validation_alias=AliasChoices(
            "AUDIT_HYBRID_RESET_TIMEOUT",
            AliasPath("audit", "hybrid", "circuit_breaker", "reset_timeout"),
        ),
    )

    # Auth
    AUTH_MODE: str = Field(
        default="development",
        validation_alias=AliasChoices("AUTH_MODE", AliasPath("auth", "mode")),
    )
    AUTH_PUBLIC_KEY_PATH: str = Field(
        default="",
        validation_alias=AliasChoices(
            "AUTH_PUBLIC_KEY_PATH", AliasPath("auth", "public_key_path")
        ),
    )
    AUTH_JWKS_URL: str = Field(
        default="",
        validation_alias=AliasChoices("AUTH_JWKS_URL", AliasPath("auth", "jwks_url")),
    )
    AUTH_JWKS_CACHE_MINUTES: int = Field(
        default=60,
        validation_alias=AliasChoices(
            "AUTH_JWKS_CACHE_MINUTES", AliasPath("auth", "jwks_cache_minutes")
        ),
    )
    AUTH_ISSUER: str = Field(
        default="",
        validation_alias=AliasChoices("AUTH_ISSUER", AliasPath("auth", "issuer")),
    )
    AUTH_AUDIENCE: str = Field(
        default="",
        validation_alias=AliasChoices("AUTH_AUDIENCE", AliasPath("auth", "audience")),
    )
    AUTH_TOKEN_CACHE_ENABLED: bool = Field(
        default=False,
        validation_alias=AliasChoices(
            "AUTH_TOKEN_CACHE_ENABLED", AliasPath("auth", "token_cache_enabled")
        ),
    )
    AUTH_TOKEN_CACHE_STRICT: bool = Field(
        default=True,
        validation_alias=AliasChoices(
            "AUTH_TOKEN_CACHE_STRICT", AliasPath("auth", "token_cache_strict")
        ),
    )
    AUTH_TOKEN_CACHE_PREFIX: str = Field(
        default="token",
        validation_alias=AliasChoices(
            "AUTH_TOKEN_CACHE_PREFIX", AliasPath("auth", "token_cache_prefix")
        ),
    )
    AUTH_TOKEN_CACHE_TIMEOUT: str = Field(
        default="1s",
        validation_alias=AliasChoices(
            "AUTH_TOKEN_CACHE_TIMEOUT", AliasPath("auth", "token_cache_timeout")
        ),
    )

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls,
        init_settings,
        env_settings,
        dotenv_settings,
        file_secret_settings,
    ):
        return (
            init_settings,
            env_settings,
            _yaml_settings_source,
            dotenv_settings,
            file_secret_settings,
        )

    def build_database_url(self) -> str:
        if not self.DB_URL:
            raise ValueError("DB_URL/DATABASE_URL is required")
        return self._normalize_database_url(self.DB_URL)

    def _normalize_database_url(self, raw: str) -> str:
        ssl_true = "ssl=true"
        if raw.startswith("mysql+asyncmy://") or raw.startswith(
            "postgresql+asyncpg://"
        ):
            return self._strip_mysql_ssl_query(raw)

        if raw.startswith("mysql://"):
            normalized = raw.replace("mysql://", "mysql+asyncmy://", 1)
            normalized = normalized.replace("ssl-mode=REQUIRED", ssl_true)
            normalized = normalized.replace("ssl-mode=required", ssl_true)
            normalized = normalized.replace("ssl-mode=PREFERRED", ssl_true)
            normalized = normalized.replace("ssl-mode=preferred", ssl_true)
            return self._strip_mysql_ssl_query(normalized)

        if raw.startswith("postgresql://"):
            return raw.replace("postgresql://", "postgresql+asyncpg://", 1)

        dsn_match = re.match(
            r"(?P<user>[^:]+):(?P<password>[^@]+)@tcp\((?P<host>[^)]+)\)"
            r"/(?P<db>[^?]+)(?:\?(?P<params>.*))?",
            raw,
        )
        if dsn_match:
            params = dsn_match.group("params") or ""
            query = f"?{params}" if params else ""
            user = dsn_match.group("user")
            password = dsn_match.group("password")
            host = dsn_match.group("host")
            db = dsn_match.group("db")
            normalized = f"mysql+asyncmy://{user}:{password}@{host}/{db}{query}"
            return self._strip_mysql_ssl_query(normalized)
        return self._strip_mysql_ssl_query(raw)

    def mysql_ssl_required(self) -> bool:
        if not self.DB_URL:
            return False
        raw = self.DB_URL
        if not (raw.startswith("mysql://") or raw.startswith("mysql+asyncmy://")):
            return False
        parsed = urlparse(raw)
        query = dict(parse_qsl(parsed.query))
        return "ssl" in query or "ssl-mode" in query

    def _strip_mysql_ssl_query(self, url: str) -> str:
        if not url.startswith("mysql+asyncmy://"):
            return url
        parsed = urlparse(url)
        query_items = [
            (k, v) for k, v in parse_qsl(parsed.query) if k not in {"ssl", "ssl-mode"}
        ]
        new_query = urlencode(query_items)
        return urlunparse(parsed._replace(query=new_query))

    def ensure_database_config(self) -> None:
        if not self.DB_URL:
            raise ValueError("DB_URL/DATABASE_URL is required")


@lru_cache()
def get_settings() -> Settings:
    return Settings()
