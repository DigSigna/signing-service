from dataclasses import dataclass, field
from typing import Optional, Any, Dict

from app.domain.exceptions.domain_errors import (
    TenantRequiredError,
    OwnerIdRequiredError,
    InvalidOwnerTypeError,
)
from .OwnerType import OwnerType


@dataclass
class IdentityContext:
    tenant_id: str
    owner_type: OwnerType
    owner_id: str
    user_id: str
    cert_level: int
    max_cert_level: int
    can_certify: bool
    certification_path: str
    permissions: Dict[str, Any] = field(default_factory=dict)

    # Campos opcionales (punteros en Go)
    organization_id: Optional[str] = None
    parent_key_id: Optional[str] = None

    def validate(self) -> None:
        """Valida que los campos obligatorios sean correctos."""
        if not self.tenant_id:
            raise TenantRequiredError("Tenant ID es requerido")

        if not self.owner_id:
            raise OwnerIdRequiredError("Owner ID es requerido")

        # Verifica que owner_type sea un miembro válido del Enum.
        # Si se construyó correctamente como OwnerType, esto siempre es cierto.
        if not isinstance(self.owner_type, OwnerType):
            # Si por error se asignó un string, lanzamos excepción.
            raise InvalidOwnerTypeError(
                "OwnerType debe ser un miembro del Enum OwnerType"
            )

        # Nota: En Go también se llama a i.OwnerType.IsValid().
        # Como usamos Enum, los miembros siempre son válidos.
        # Si se desea validar explícitamente el valor (por si se usa un
        # string), se puede hacer:
        # if not OwnerType.is_valid(self.owner_type.value):
        #     raise InvalidOwnerTypeError("Valor de OwnerType no reconocido")
        # Pero con la garantía del tipo no es necesario.

    def can_certify_level(self, level: int) -> bool:
        """Determina si puede certificar un nivel específico."""
        return self.can_certify and self.max_cert_level >= level

    def has_permission(self, name: str) -> bool:
        """Chequea un flag de permissions boolean-ish (admin, etc.) —
        tolera bool/str/int igual que hsm-service's AdminAuthMiddleware
        (toBool). Único punto de verdad: tanto el dependency de ruta
        (require_admin) como las reglas de autorización dentro de un caso
        de uso (p. ej. CreateCAUseCase) llaman acá, nunca duplican esta
        lógica."""
        if not self.permissions:
            return False
        value = self.permissions.get(name)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in {"true", "1", "yes"}
        if isinstance(value, (int, float)):
            return value != 0
        return False
