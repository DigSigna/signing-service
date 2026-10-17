from fastapi import APIRouter
from redis import Redis

from app.core.config import get_settings
from py_common.core.logger import get_logger
from app.infrastructure.database.session import ping_db
from app.interfaces.schemas.health import HealthResponse

router = APIRouter()
logger = get_logger("health-service")  # Se sobreescribirá por microservicio


async def check_database() -> bool:
    """Verifica conexión a base de datos"""
    return await ping_db()


def check_redis():
    """Verifica conexión a Redis"""
    settings = get_settings()
    try:
        redis_client = Redis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD or None,
            db=settings.REDIS_DB,
            socket_connect_timeout=1,
        )
        return redis_client.ping()
    except Exception:
        return False


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Reporta el estado del servicio y sus dependencias (DB, Redis). "
    "Sin autenticación — AuthMiddleware excluye esta ruta explícitamente.",
)
async def health_check():
    logger.info("Health check executed", action="health_check", endpoint="/health")

    health_status = {
        "status": "healthy",
        "version": get_settings().VERSION,
        "dependencies": {"database": await check_database(), "redis": check_redis()},
    }

    # Si alguna dependencia crítica falla, retornar error 503
    if not all(health_status["dependencies"].values()):
        health_status["status"] = "degraded"

    return health_status
