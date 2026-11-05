"""Shared authority check for voiding/superseding a signing_request
(Caso 3, Opción B) — mirrors certificate-service's
certificate_access.is_authorized_for_certificate rather than inventing a
new rule: a TENANT identity owns everything under its own tenant, an
ORGANIZATION identity owns whatever maps to its own organization_id, and
the request's own signer (user_id) always owns their own document.

identity_context.has_permission("admin") is checked too, for consistency
with certificate-service's own has_permission("admin") branches — but
per identification-service's docs/permissions_matrix.md §8, no role in
the real RBAC catalog ever grants the literal code "admin", so no real
JWT's `permissions` array can contain it today. This branch is
documented-dead against a real token right now; it is kept only so this
function doesn't silently diverge from the rest of the codebase's
established (if currently non-functional) pattern. The TENANT/ORGANIZATION
owner_type checks below are what actually authorizes a real admin call.
"""

from __future__ import annotations

from uuid import UUID

from app.domain.entities.SigningRequest import SigningRequest
from py_common.auth.identity_context import IdentityContext
from py_common.auth.owner_type import OwnerType


def is_authorized_to_void(
    identity_context: IdentityContext,
    signing_request: SigningRequest,
) -> bool:
    if identity_context.has_permission("admin"):
        return True

    if (
        signing_request.user_id is not None
        and str(signing_request.user_id) == identity_context.user_id
    ):
        return True  # the document's own signer

    owner_type = OwnerType(identity_context.owner_type)
    if owner_type == OwnerType.TENANT:
        return True  # tenant admin: everyone under its own tenant

    if (
        owner_type == OwnerType.ORGANIZATION
        and signing_request.organization_id is not None
        and UUID(identity_context.owner_id) == signing_request.organization_id
    ):
        return True  # org admin, for this specific organization's own request

    return False
