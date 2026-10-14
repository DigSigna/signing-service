from abc import ABC, abstractmethod
from typing import Any

from app.domain.entities.AuditEvent import AuditEvent


class AuditRecorder(ABC):
    @abstractmethod
    async def record_event(self, ctx: Any, event: AuditEvent) -> None:
        """Registra un evento de auditoría."""
        raise NotImplementedError
