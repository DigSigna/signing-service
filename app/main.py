from datetime import timedelta

from fastapi import FastAPI
from app.core.config import get_settings
from app.core.logger import get_logger
from app.infrastructure.database.session import AsyncSessionLocal, close_db, init_db
from app.interfaces.routes.health import router as health_router
from app.interfaces.routes.signing import router as signing_router
from app.interfaces.middleware.logging import LoggingMiddleware
from app.interfaces.middleware.error_handling import ErrorHandlingMiddleware
from app.interfaces.middleware.request_context import RequestContextMiddleware
from app.interfaces.middleware.auth import AuthMiddleware
from app.infrastructure.auth.key_manager_adapter import (
    KeyManagerAdapter,
    KeyManagerConfig,
)
from app.infrastructure.auth.validator_adapter import JWTValidatorAdapter
from app.infrastructure.external.hsm import create_hsm_client
from app.infrastructure.external.certificate.http_pin_verifier import (
    RemoteSigningPinVerifier,
    RemoteSigningPinVerifierConfig,
)
from app.infrastructure.external.certificate.http_certificate_client import (
    RemoteCertificateClient,
    RemoteCertificateClientConfig,
)
from app.infrastructure.external.certificate.intermediate_cache import (
    IntermediateCertificateCache,
)
from app.infrastructure.crypto.pyhanko_pades_signer import PyHankoPAdESSigner
from app.infrastructure.external.redis import TokenCache, TokenCacheConfig
from app.infrastructure.audit.audit_worker import AuditWorker
from app.infrastructure.audit.factory import new_audit_recorder
from app.infrastructure.database.repositories.audit_repository import (
    SQLAlchemyAuditRepository,
)
from app.domain.valueobjects.AuditStrategy import AuditStrategy

settings = get_settings()
logger = get_logger("signing-service")

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=(
        "API REST para firma digital de documentos, multi-tenant. No opera "
        "el HSM directamente — delega toda operación criptográfica a "
        "hsm-service vía HTTP (RemoteHSMClient), reenviando el JWT del caller "
        "original (servicios stateless, sin token de servicio fijo). Consume "
        "certificate-service para obtener/validar el certificado del firmante. "
        "El OpenAPI de esta página (`/openapi.json`) es importable directamente "
        "en Bruno (Import Collection → OpenAPI v3) para generar la colección de "
        "requests manuales."
    ),
    docs_url="/docs",
    redoc_url="/redoc",
)


def _build_token_cache(settings_obj):
    if not settings_obj.AUTH_TOKEN_CACHE_ENABLED:
        return None
    timeout = _parse_seconds(settings_obj.AUTH_TOKEN_CACHE_TIMEOUT, default=1.0)
    return TokenCache(
        TokenCacheConfig(
            host=settings_obj.REDIS_HOST,
            port=settings_obj.REDIS_PORT,
            password=settings_obj.REDIS_PASSWORD,
            db=settings_obj.REDIS_DB,
            prefix=settings_obj.AUTH_TOKEN_CACHE_PREFIX,
            socket_timeout=timeout,
        )
    )


def _parse_seconds(value: str, default: float) -> float:
    if not value:
        return default
    raw = value.strip().lower()
    if raw.endswith("ms"):
        return float(raw[:-2]) / 1000.0
    if raw.endswith("s"):
        return float(raw[:-1])
    if raw.endswith("m"):
        return float(raw[:-1]) * 60.0
    return float(raw)


# Middlewares
app.add_middleware(RequestContextMiddleware)
app.add_middleware(LoggingMiddleware)
app.add_middleware(ErrorHandlingMiddleware)
app.add_middleware(AuthMiddleware)

# Routers
app.include_router(health_router, prefix=settings.API_V1_STR, tags=["health"])
app.include_router(signing_router, prefix=settings.API_V1_STR, tags=["signing"])


@app.on_event("startup")
async def startup_event():
    await init_db()
    logger.info("Database connection established", action="db_startup")

    key_manager = KeyManagerAdapter(
        KeyManagerConfig(
            mode=settings.AUTH_MODE,
            public_key_path=settings.AUTH_PUBLIC_KEY_PATH,
            jwks_url=settings.AUTH_JWKS_URL,
            jwks_cache_minutes=settings.AUTH_JWKS_CACHE_MINUTES,
        )
    )
    validator = JWTValidatorAdapter(
        key_manager=key_manager,
        issuer=settings.AUTH_ISSUER or None,
        audience=settings.AUTH_AUDIENCE or None,
        token_cache=_build_token_cache(settings),
        token_cache_enabled=settings.AUTH_TOKEN_CACHE_ENABLED,
        token_cache_strict=settings.AUTH_TOKEN_CACHE_STRICT,
    )
    app.state.jwt_validator = validator
    logger.info("JWT validator initialized", action="auth_startup")

    app.state.hsm_client = create_hsm_client(settings)
    logger.info("HSM client initialized", action="hsm_startup")

    # None (not a crashed startup) when unset: lets /health and other
    # routes still come up in the standalone dev topology (HSM_BACKEND=
    # in_memory, no certificate-service running at all) — /sign fails
    # clearly via get_certificate_client/get_pin_verifier instead.
    if settings.CERTIFICATE_SERVICE_BASE_URL:
        certificate_timeout = _parse_seconds(settings.CERTIFICATE_SERVICE_TIMEOUT, 5.0)
        app.state.certificate_client = RemoteCertificateClient(
            RemoteCertificateClientConfig(
                base_url=settings.CERTIFICATE_SERVICE_BASE_URL,
                timeout_seconds=certificate_timeout,
            )
        )
        app.state.pin_verifier = RemoteSigningPinVerifier(
            RemoteSigningPinVerifierConfig(
                base_url=settings.CERTIFICATE_SERVICE_BASE_URL,
                timeout_seconds=certificate_timeout,
            )
        )
        app.state.intermediate_cache = IntermediateCertificateCache(
            app.state.certificate_client,
            ttl=timedelta(hours=settings.CERTIFICATE_CHAIN_CACHE_TTL_HOURS),
        )
        logger.info(
            "certificate-service clients initialized", action="certificate_startup"
        )
    else:
        logger.warning(
            "CERTIFICATE_SERVICE_BASE_URL not set — /sign will fail until it is",
            action="certificate_startup_skipped",
        )

    app.state.pades_signer = PyHankoPAdESSigner()
    logger.info("PAdES signer initialized", action="pades_signer_startup")

    if settings.AUDIT_ENABLED:
        audit_session = AsyncSessionLocal()
        audit_storage = SQLAlchemyAuditRepository(audit_session)
        try:
            strategy = AuditStrategy(settings.AUDIT_STRATEGY)
        except ValueError:
            strategy = AuditStrategy.DATABASE

        audit_recorder = new_audit_recorder(
            strategy=strategy,
            storage=audit_storage,
            http_base_url=settings.AUDIT_HTTP_BASE_URL,
        )
        audit_worker = AuditWorker(audit_recorder)
        app.state.audit_session = audit_session
        app.state.audit_worker = audit_worker
        logger.info("Audit worker initialized", action="audit_startup")


@app.on_event("shutdown")
async def shutdown_event():
    audit_worker = getattr(app.state, "audit_worker", None)
    if audit_worker is not None:
        await audit_worker.close()
        logger.info("Audit worker closed", action="audit_shutdown")

    audit_session = getattr(app.state, "audit_session", None)
    if audit_session is not None:
        await audit_session.close()
    await close_db()
    logger.info("Database connection closed", action="db_shutdown")
