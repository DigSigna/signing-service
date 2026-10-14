"""Idempotency claim/replay helper for mutating use cases.

Equivalente a hsm-service's claimIdempotencyKey/finishIdempotencyClaim
(internal/application/services/idempotency.go) — ver su uso en
key_service.go. Cualquier caso de uso que acepte un request_id (idempotency
key) provisto por el cliente envuelve su trabajo con este par de funciones.
"""

from __future__ import annotations

from typing import NamedTuple, Optional

from app.core.logger import get_logger
from app.domain.exceptions.domain_errors import DuplicateRequestError
from app.domain.ports.output.IdempotencyRepository import (
    IdempotencyKeyExistsError,
    IdempotencyRepository,
)

logger = get_logger("idempotency-service")


class ClaimResult(NamedTuple):
    # claimed=True: el caller es dueño del claim; debe llamar a
    # finish_idempotency_claim al terminar (éxito o falla).
    claimed: bool
    # Si no es None: una llamada previa ya completó esta operación; hay que
    # reproducir ese recurso en vez de repetir el efecto secundario.
    existing_resource_id: Optional[str]


async def claim_idempotency_key(
    repo: Optional[IdempotencyRepository],
    tenant_id: str,
    request_id: Optional[str],
    operation: str,
) -> ClaimResult:
    """Reclama (tenant_id, request_id) para `operation` antes de hacer el
    trabajo real.

    request_id vacío (sin idempotency key provista por el cliente) o repo
    None saltea el chequeo por completo — claimed=False,
    existing_resource_id=None — para que callers sin un gateway que setee
    uno (p. ej. tests directos) no queden forzados por este camino.

    Lanza DuplicateRequestError cuando un duplicado concurrente todavía está
    en curso (sin recurso para reproducir todavía).
    """
    if not request_id or repo is None:
        return ClaimResult(claimed=False, existing_resource_id=None)

    try:
        await repo.claim(tenant_id, request_id, operation)
        return ClaimResult(claimed=True, existing_resource_id=None)
    except IdempotencyKeyExistsError:
        pass

    existing = await repo.find_by_request_id(tenant_id, request_id)
    if existing is None or not existing.resource_id:
        raise DuplicateRequestError(
            "A request with this idempotency key is already being processed",
            idempotency_key=request_id,
        ).with_detail("tenant_id", tenant_id)

    return ClaimResult(claimed=False, existing_resource_id=existing.resource_id)


async def finish_idempotency_claim(
    repo: Optional[IdempotencyRepository],
    tenant_id: str,
    request_id: str,
    resource_id: Optional[str],
    error: Optional[BaseException],
) -> None:
    """Completa o libera un claim hecho por claim_idempotency_key, según el
    resultado final de la operación.

    Best-effort: una falla acá no hace fallar el request — la operación real
    ya tuvo éxito o falló, y un claim atascado solo significa que el próximo
    retry va a ver DuplicateRequestError en vez de reproducir el recurso, no
    corrupción de datos silenciosa. A diferencia de la referencia en Go (que
    ignora el error de Release/Complete sin loguearlo), acá sí se loguea.
    """
    if repo is None:
        return
    try:
        if error is not None:
            await repo.release(tenant_id, request_id)
        else:
            await repo.complete(tenant_id, request_id, resource_id or "")
    except Exception as exc:
        logger.warning(
            "Failed to finish idempotency claim",
            action="idempotency_finish_failed",
            tenant_id=tenant_id,
            request_id=request_id,
            error=str(exc),
        )
