"""Per-route permission guards.

Equivalente a hsm-service's AdminAuthMiddleware.RequireAdmin()
(internal/interfaces/http/middlewares/admin_auth_middleware.go), pero como
dependencia de FastAPI en vez de middleware global: se aplica solo a las
rutas sensibles que la necesitan (p. ej. POST /api/v1/cas), no a todas,
igual que Go la registra solo en el grupo /internal/hsm/* y no globalmente.
"""

from __future__ import annotations

from fastapi import Request

from app.domain.exceptions.domain_errors import AuthorizationError
from app.domain.valueobjects.IdentityContext import IdentityContext


def get_identity_context(request: Request) -> IdentityContext:
    """Extrae el identity_context que AuthMiddleware ya validó y adjuntó a
    request.state, sin exigir ningún permiso particular — para rutas cuya
    autorización es más rica que un solo flag (ver CreateCAUseCase, que
    acepta admin O can_certify_level según el caso) y que resuelven esa
    lógica ellas mismas en la capa de aplicación."""
    return request.state.identity_context


def require_admin(request: Request) -> IdentityContext:
    """Exige que la identidad autenticada tenga el permiso 'admin'.

    AuthMiddleware ya corre globalmente y deja identity_context en
    request.state; esta dependencia solo añade el chequeo de permiso
    adicional para las rutas que la declaren vía Depends(require_admin).
    """
    identity = get_identity_context(request)

    if not identity.has_permission("admin"):
        raise AuthorizationError(
            "Admin permission required", details={"tenant_id": identity.tenant_id}
        )

    return identity
