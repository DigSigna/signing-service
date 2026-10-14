from abc import ABC, abstractmethod
from app.domain.entities.AuditEvent import AuditEvent


# Client to send audit events to an external system (kafka, logstash, http
# endpoint, etc.)
class AuditTransporter(ABC):
    @abstractmethod
    def send(self, ctx, event: AuditEvent):
        """Envía un evento de auditoría a un sistema externo."""
        pass

    @abstractmethod
    def health_check(self, ctx):
        """Realiza una comprobación de salud del sistema externo."""
        pass
