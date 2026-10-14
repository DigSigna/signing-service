from unittest.mock import MagicMock

import pytest

from app.domain.exceptions.domain_errors import AuthorizationError
from app.domain.valueobjects.IdentityContext import IdentityContext
from app.domain.valueobjects.OwnerType import OwnerType
from app.interfaces.auth.permissions import require_admin


def _identity(**permissions) -> IdentityContext:
    return IdentityContext(
        tenant_id="tenant-1",
        owner_type=OwnerType.TENANT,
        owner_id="owner-1",
        user_id="user-1",
        cert_level=0,
        max_cert_level=0,
        can_certify=False,
        certification_path="",
        permissions=permissions,
    )


def _request_with(identity: IdentityContext) -> MagicMock:
    request = MagicMock()
    request.state.identity_context = identity
    return request


def test_require_admin_passes_with_admin_permission():
    request = _request_with(_identity(admin=True))

    result = require_admin(request)

    assert result.tenant_id == "tenant-1"


def test_require_admin_rejects_without_permissions():
    request = _request_with(_identity())

    with pytest.raises(AuthorizationError):
        require_admin(request)


def test_require_admin_rejects_with_admin_false():
    request = _request_with(_identity(admin=False))

    with pytest.raises(AuthorizationError):
        require_admin(request)


def test_require_admin_accepts_string_true():
    request = _request_with(_identity(admin="true"))

    require_admin(request)
