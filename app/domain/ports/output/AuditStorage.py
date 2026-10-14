from abc import ABC, abstractmethod
from app.domain.entities.AuditEvent import AuditEvent


class AuditStorage(ABC):
    @abstractmethod
    def store_audit_record(self, record: AuditEvent) -> None:
        """Store an audit record"""
        pass
