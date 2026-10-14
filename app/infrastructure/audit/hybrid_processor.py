"""Hybrid audit processor (HTTP primary + DB fallback)."""

from __future__ import annotations

import inspect
import time
from dataclasses import dataclass, field
from threading import RLock
from typing import Any, Optional

from app.domain.entities.AuditEvent import AuditEvent
from app.domain.ports.input.AuditRecorder import AuditRecorder
from app.domain.ports.output.AuditStorage import AuditStorage
from app.domain.ports.output.AuditTransporter import AuditTransporter
from app.domain.valueobjects.AuditStrategy import AuditStrategy


@dataclass
class HybridProcessor(AuditRecorder):
    strategy: AuditStrategy
    primary: Optional[AuditTransporter]
    fallback: AuditStorage
    max_failures: int = 5
    reset_after_seconds: int = 30
    _failures: int = 0
    _last_failure_ts: float = 0.0
    _circuit_open: bool = False
    _lock: RLock = field(default_factory=RLock, init=False, repr=False)

    async def record_event(self, ctx: Any, event: AuditEvent) -> None:
        if self.strategy == AuditStrategy.DATABASE:
            await self._store(event)
            return

        if self.strategy == AuditStrategy.HTTP:
            if not self.primary:
                await self._store(event)
                return
            await self._send(ctx, event)
            return

        if self.strategy == AuditStrategy.HYBRID:
            if not self.primary or self._is_circuit_open():
                await self._store(event)
                return

            try:
                await self._send(ctx, event)
                self._reset_circuit()
                return
            except Exception:
                self._register_failure()
                await self._store(event)
                return

        await self._store(event)

    async def _send(self, ctx: Any, event: AuditEvent) -> None:
        result = self.primary.send(ctx, event)
        await _maybe_await(result)

    async def _store(self, event: AuditEvent) -> None:
        result = self.fallback.store_audit_record(event)
        await _maybe_await(result)

    def _is_circuit_open(self) -> bool:
        with self._lock:
            if not self._circuit_open:
                return False
            elapsed = time.monotonic() - self._last_failure_ts
            if elapsed >= self.reset_after_seconds:
                self._circuit_open = False
                self._failures = 0
                return False
            return True

    def _register_failure(self) -> None:
        with self._lock:
            self._failures += 1
            self._last_failure_ts = time.monotonic()
            if self._failures >= self.max_failures:
                self._circuit_open = True

    def _reset_circuit(self) -> None:
        with self._lock:
            self._failures = 0
            self._circuit_open = False
            self._last_failure_ts = 0.0


async def _maybe_await(result: Any) -> None:
    if inspect.isawaitable(result):
        await result
