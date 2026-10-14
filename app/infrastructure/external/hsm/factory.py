"""HSM client factory."""

from __future__ import annotations

from app.core.config import Settings
from app.domain.ports.output.HSMClient import HSMClient
from app.infrastructure.external.hsm.in_memory_client import InMemoryHSMClient
from app.infrastructure.external.hsm.http_client import RemoteHSMClient, RemoteHSMConfig


def create_hsm_client(settings: Settings) -> HSMClient:
    backend = settings.HSM_BACKEND.lower()
    if backend in {"memory", "in_memory", "in-memory"}:
        return InMemoryHSMClient()
    if backend in {"remote", "http", "hsm-service"}:
        timeout = _parse_seconds(settings.HSM_SERVICE_TIMEOUT, default=5.0)
        return RemoteHSMClient(
            RemoteHSMConfig(
                base_url=settings.HSM_SERVICE_BASE_URL,
                timeout_seconds=timeout,
            )
        )
    raise NotImplementedError(f"HSM backend not implemented: {settings.HSM_BACKEND}")


def _parse_seconds(value: str, default: float) -> float:
    if not value:
        return default
    raw = value.strip().lower()
    if raw.endswith("ms"):
        return float(raw[:-2]) / 1000.0
    if raw.endswith("s"):
        return float(raw[:-1])
    if raw.endswith("m"):
        return float(raw[:-1]) * 60.0
    return float(raw)
