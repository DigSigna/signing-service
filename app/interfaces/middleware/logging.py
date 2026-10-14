import time
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
import uuid

from app.core.logger import get_logger

logger = get_logger("api-gateway")  # Este nombre se sobreescribirá por servicio
# logger = logging.getLogger(__name__)


class LoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # Generar correlation_id para todo el request
        correlation_id = request.headers.get("X-Correlation-ID", str(uuid.uuid4()))

        start_time = time.time()

        # Log de request entrante
        logger.info(
            f"Request started: {request.method} {request.url.path}",
            action="request_start",
            correlation_id=correlation_id,
            method=request.method,
            path=str(request.url.path),
            client_ip=request.client.host if request.client else None,
            user_agent=request.headers.get("user-agent"),
        )

        try:
            response = await call_next(request)
            process_time = time.time() - start_time

            # Log de response exitoso
            logger.info(
                f"Request completed: {request.method} {request.url.path}",
                action="request_complete",
                correlation_id=correlation_id,
                status_code=response.status_code,
                process_time_ms=round(process_time * 1000, 2),
            )

            # Agregar correlation_id al header de response
            response.headers["X-Correlation-ID"] = correlation_id

            return response

        except Exception as exc:
            process_time = time.time() - start_time

            # Log de error
            logger.error(
                f"Request failed: {request.method} {request.url.path} - {str(exc)}",
                action="request_error",
                correlation_id=correlation_id,
                error_type=type(exc).__name__,
                process_time_ms=round(process_time * 1000, 2),
            )
            raise
