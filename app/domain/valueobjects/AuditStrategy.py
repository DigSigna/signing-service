from enum import Enum


class AuditStrategy(Enum):
    DATABASE = "database"
    HTTP = "http"
    HYBRID = "hybrid"
    MOCK = "mock"
    ASYNC = "async"

    @classmethod
    def is_valid(cls, value: str) -> bool:
        """Verifica si una cadena es una estrategia de auditoría válida."""
        return value in cls._value2member_map_
