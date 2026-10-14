from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.logger import get_logger
from app.core.request_context import get_context_values
from app.domain.exceptions.domain_errors import DomainError

logger = get_logger("signing-service")


class ErrorHandlingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request, call_next):
        try:
            return await call_next(request)
        except DomainError as exc:
            logger.warning(
                f"Domain error: {exc.code}",
                action="domain_error",
                correlation_id=get_context_values().correlation_id,
                path=str(request.url.path),
                error_code=exc.code,
            )
            return JSONResponse(
                status_code=exc.http_status, content={"error": exc.to_dict()}
            )
        except Exception as exc:
            logger.error(
                f"Unhandled exception: {exc}",
                action="unhandled_exception",
                correlation_id=get_context_values().correlation_id,
                path=str(request.url.path),
            )
            return JSONResponse(
                status_code=500,
                content={
                    "error": {
                        "code": "INTERNAL_ERROR",
                        "message": "Internal Server Error",
                        "details": {},
                    }
                },
            )
