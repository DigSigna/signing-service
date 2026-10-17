"""Shared AuditData construction for mutating use cases.

The same BUSINESS-event shape (actor_type derivation, duration,
success/error mapping) is needed by every mutating use case — built once
here instead of once per use case. service_name/resource_type are left as
required params rather than module constants: this file is shared
infrastructure reused across services (originally written for
certificate-service's CreateCA/IssueCertificate/RevokeCertificate), not
specific to any one resource type.
"""

from __future__ import annotations

import time
from typing import Any, Dict, Optional

from app.domain.exceptions.domain_errors import get_error_code
from py_common.audit import AuditData
from py_common.auth.identity_context import IdentityContext


def build_audit_data(
    *,
    service_name: str,
    resource_type: str,
    operation: str,
    resource_id: Optional[str],
    identity_context: IdentityContext,
    start: float,
    error: Optional[BaseException],
    metadata: Optional[Dict[str, Any]] = None,
) -> AuditData:
    return AuditData(
        service_name=service_name,
        event_type="BUSINESS",
        operation=operation,
        resource_id=resource_id or "",
        resource_type=resource_type,
        actor_type=str(
            getattr(identity_context.owner_type, "value", identity_context.owner_type)
        ),
        success=error is None,
        status_code=get_error_code(error),
        err_msg=str(error) if error else "",
        duration_ms=int((time.monotonic() - start) * 1000),
        metadata=metadata or {},
    )
