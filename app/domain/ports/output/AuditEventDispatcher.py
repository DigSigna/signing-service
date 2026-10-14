from abc import ABC, abstractmethod
from typing import Any, Optional
from app.domain.valueobjects.AuditData import AuditData
from app.domain.valueobjects.IdentityContext import IdentityContext


class AuditEventDispatcher(ABC):
    @abstractmethod
    async def audit_operation(
        self, ctx: Any, data: AuditData, identity_context: Optional[IdentityContext]
    ) -> None:
        """Dispatch an audit event to the appropriate recorder(s).

        identity_context es opcional: operaciones a nivel de infraestructura
        (p. ej. un decorator de repositorio) no tienen un IdentityContext de
        request real — ver AuditedTenantCARepository.
        """
        pass

    @abstractmethod
    async def close(self) -> None:
        """Close any resources held by the dispatcher"""
        pass
