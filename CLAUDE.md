# CLAUDE.md — Signing Service

Instrucciones para Claude Code trabajando en este repositorio. Este archivo es el equivalente para Claude Code de `AGENTS.md` — mismas reglas, mismo proyecto. Si divergen, `AGENTS.md` es la fuente canónica; abre un PR para corregir el otro.

## ⚠️ Antes de empezar

Este repositorio nació (2026-10-14) como una copia literal de `certificate-service` — mismo stack, misma arquitectura hexagonal — para no reconstruir desde cero la infraestructura que ambos servicios comparten (JWT/JWKS, auditoría híbrida, contexto de request, cliente HSM). Esa copia ya fue **recortada**: todo lo específico del dominio de certificados/CA se eliminó; solo quedó la infraestructura genérica. Ver el primer commit del repo (`chore: baseline copy from certificate-service`) si necesitás comparar contra el original sin recortar.

**Por eso, a diferencia de `hsm-service/CLAUDE.md` y `certificate-service/CLAUDE.md`, esta sección no tiene todavía una lista de "hallazgos ya identificados que no debes repetir" propia** — este repo no tiene historia propia más allá de hoy. Los patrones de seguridad de esos dos documentos (mismo espíritu, Go o Python según el servicio) aplican igual acá; si encontrás un hallazgo nuevo de la misma clase (secreto hardcodeado, excepción silenciada, stub vacío asumido como implementado), documentalo acá siguiendo el mismo formato que usan ellos, no lo dejes sin registrar.

**Qué se mantuvo de la copia (infraestructura genérica, ya wireada y funcionando):**
- `app/core/` completo: config (Pydantic Settings + YAML + expansión de env vars), logger JSON estructurado, request context (contextvars).
- Auth JWT: `app/interfaces/auth/`, `app/infrastructure/auth/{key_manager_adapter,validator_adapter}.py`, `AuthMiddleware` — corre sobre todas las requests salvo `/health`.
- Auditoría híbrida: `app/infrastructure/audit/{audit_worker,factory,hybrid_processor}.py` + `app/infrastructure/external/audit/http_audit_transporter.py` + `AuditEvent`/`SQLAlchemyAuditRepository` (tabla `audit_logs`, esquema compartido). Circuit breaker igual al de `hsm-service`.
- Cliente HSM: `app/domain/ports/output/HSMClient.py` + `RemoteHSMClient` (HTTP a `hsm-service`) + `InMemoryHSMClient` (stub de dev/tests) — este servicio **tampoco** opera el HSM directamente.
- `TenantRepository` (+ `AuditedTenantRepository`, decorador de auditoría) contra la tabla `tenants` compartida — lectura de `hsm_slot_id`/`mode`, nada de jerarquía CA.
- Idempotencia genérica: `IdempotencyRepository`/`IdempotencyRecord` + `claim_idempotency_key`/`finish_idempotency_claim` (`app/application/services/idempotency.py`) — para envolver cualquier caso de uso mutante futuro que acepte un `request_id` del cliente.
- `DomainError` (jerarquía base de dataclasses) + subclases genéricas (`ValidationError`, `NotFoundError`, `AuthorizationError`, `ConfigurationError`, `DuplicateRequestError`, `TenantRequiredError`, `OwnerIdRequiredError`, `InvalidOwnerTypeError`, `HsmError`/`HsmConnectionError`/`HsmOperationError`, `AuditError`/`AuditDispatchError`/`AuditStorageError`) — consumida por `ErrorHandlingMiddleware`.
- `require_admin`/`get_identity_context` (`app/interfaces/auth/permissions.py`) como dependencia de FastAPI, no middleware global.
- `/health` (DB + Redis, sin auth) — el único endpoint de negocio wireado hoy.

**Qué se eliminó (específico de certificados/CA, no aplica a firma de documentos):** entidad `Certificate` y sus value objects X.509 (`DistinguishedName`, `SerialNumber`, `RevocationInfo`, `KeyUsage`, `ExtendedKeyUsage`, `SubjectAlternativeNames`, `ValidityPeriod`, `CertificateStatus`), los casos de uso de emisión/revocación/listado/validación de cadena, `TenantCARepository`/`CertificateRepository` y sus adaptadores SQLAlchemy, `x509_builder.py`/`x509_verifier.py`/`hsm_backed_key.py` (construcción de certificados X.509 firmados por el HSM), las rutas `cas.py`/`certificates.py`/`internal_certificates.py` y sus schemas, el proxy público `/hsm/*` (este servicio llama a `RemoteHSMClient` internamente, no necesita exponer gestión de claves), y los errores de dominio específicos de CA/certificado. `Algorithm`/`KeyPurpose` se mantuvieron — son atributos genéricos de clave del `HSMClient`, no de X.509.

## Qué es este servicio

Signing Service: API REST en Python (FastAPI) para firma digital de documentos, multi-tenant, arquitectura hexagonal. Según el flujo documentado en `platform-docs` (DLT-015, `architecture/sprint-1.0/diagrams/flow/signatures/`): recibe un documento, calcula su hash, obtiene y valida el certificado del firmante vía `certificate-service` (`GET /certificates/{id}` + `POST /internal/certificates/validate-chain`), pide a `hsm-service` que firme el hash, construye el paquete de firma (PKCS#7/PAdES) y lo embebe en el documento; también valida firmas existentes. **No opera el HSM ni emite certificados directamente** — delega ambas cosas a sus servicios hermanos.

**Estado real del repositorio (no asumas que hay más de lo que hay):** hoy **no hay ningún caso de uso de firma/verificación implementado ni wireado**. `app/application/{use_cases,dto,mappers}/` están vacíos, `app/domain/events/` e `app/infrastructure/external/do_storage/` existen como carpetas vacías (ni `__init__.py`), y el único router registrado en `app/main.py` es `/health`. Lo que sí existe y funciona es la infraestructura listada arriba — construir la lógica de firma es el trabajo pendiente, no algo ya hecho que falte conectar.

Stack: Python 3.11, FastAPI, Pydantic v2 (`pydantic-settings`), SQLAlchemy 2.0 async (`asyncmy`), Redis (cache de tokens JWT), `cryptography` (usada hoy solo por `InMemoryHSMClient`/tests), PyJWT, Uvicorn.

## Estructura real del repositorio

`STRUCTURE.md` tiene el árbol completo — mantenelo sincronizado si agregás o quitás módulos.

```text
app/
  core/                                 # config, logger JSON, request context — igual a certificate-service/hsm-service
  domain/
    entities/                           # AuditEvent, IdempotencyRecord, Tenant (Pydantic) — sin Certificate
    events/                             # carpeta vacía hoy (ni __init__.py)
    exceptions/domain_errors.py         # jerarquía de excepciones genérica (sin subclases de CA/certificado)
    ports/{input,output}/               # AuditRecorder; AuditEventDispatcher/AuditStorage/AuditTransporter, HSMClient, IdempotencyRepository, JWTKeyProvider/JWTValidator, TenantRepository
    valueobjects/                       # ActorType, Algorithm, AuditData, AuditStrategy, IdentityContext, KeyPurpose, Owner(Type), PlanType, TenantMode, TenantStatus
  application/
    dto/, mappers/, use_cases/          # VACÍOS hoy — acá va la lógica de firma/verificación que falta
    services/                           # idempotency.py (claim/finish genérico), audit_helpers.py (build_audit_data, parametrizado por service_name/resource_type)
  infrastructure/
    audit/                              # audit_worker.py + factory.py + hybrid_processor.py — ya wireado si AUDIT_ENABLED
    crypto/                             # no existe todavía (se eliminó junto con x509_builder/verifier) — crealo cuando se implemente la firma real
    database/                           # sesión SQLAlchemy async; models/{base,tenant,audit_event,idempotency_key}.py; repositories/{tenant_repository,audit_repository,idempotency_repository}.py; adapters/audited_tenant_repository.py
    external/hsm/                       # factory + RemoteHSMClient + InMemoryHSMClient
    external/redis/                     # cache de tokens JWT
    external/audit/http_audit_transporter.py
    external/do_storage/                # carpeta vacía hoy (ni __init__.py)
  interfaces/
    auth/permissions.py                 # require_admin / get_identity_context
    middleware/                         # auth, logging, error_handling, request_context — las 4 ya registradas en main.py
    routes/health.py                    # único endpoint de negocio wireado hoy
    schemas/                            # errors.py, health.py — sin schemas de certificado/CA
config/config.yaml                      # config base (fusiona con .env y env vars vía pydantic-settings)
scripts/redis/, scripts/sonar/, scripts/docker/
bruno/                                  # colección de requests manuales (si existe)
tests/                                  # test_health, test_hsm_client, test_remote_hsm_client, test_idempotency_service, test_permissions, test_domain_errors — todos de infraestructura, cero de negocio (no hay negocio todavía)
```

## Comandos esenciales

Mismas dos topologías que `certificate-service` (comparten el mismo MySQL vía `hsm-network`). **No las corras en simultáneo** — ambas publican MySQL en el puerto 3306 del host.

**Opción A — standalone (`docker-compose.yml`), HSM stub en memoria:**
```bash
make infra-up         # MySQL propio + migraciones compartidas (ghcr.io/digsigna/migrations)
pip install -r requirements/base.txt -r requirements/dev.txt
# .env con HSM_BACKEND=in_memory, DB_URL=mysql://digsigna:digsigna@localhost:3306/digsigna
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload
curl http://localhost:8001/api/v1/health
make infra-down
```

**Opción B — integración real con `hsm-service` (`docker-compose.dev.yml`):**
```bash
cd ../hsm-service && make dev-up   # mysql + migrate + softhsm + hsm-service; crea la red externa "hsm-network"
cd ../signing-service && make up    # == make compose-dev-up — se une a hsm-network, HSM_BACKEND=remote, puerto 8001
make logs
make down
make restart
```
Puerto `8001` (no `8000`, el de `certificate-service`) — DLT-015 les asigna puertos distintos justamente para poder correr ambos servicios sobre la misma red/host sin chocar.

**Build de imagen:**
```bash
make build           # imagen de producción (Dockerfile, python:3.11-slim-bookworm, corre como usuario no-root)
make build-dev        # imagen de desarrollo (Dockerfile.dev)
```

**Calidad y seguridad — correr todos antes de cerrar una tarea:**
```bash
pytest -v --cov=app
bandit -r app/
safety check -r requirements/base.txt
flake8 app/ tests/
black --check app/ tests/
```

## Reglas de seguridad — NO NEGOCIABLES

Mismo espíritu que `hsm-service`/`certificate-service`, adaptado a este servicio. Repetilas mentalmente antes de tocar `app/domain/`, `app/infrastructure/external/hsm/`, `app/interfaces/auth/`, o `config/`:

1. **Nunca hardcodees credenciales, PINs o seeds** en `config/config.yaml`, `.env.example` ni código fuente — ni siquiera como "default de desarrollo". `Settings.ensure_database_config` (`app/core/config.py`) ya está escrito para fallar el arranque si `DB_URL` no está seteada — no le agregues un fallback funcional.
2. **Nunca loguees material criptográfico**: PINs, claves privadas, hashes de firma completos, JWTs completos. Usá `metadata` del logger solo para longitudes o hashes truncados.
3. **Cualquier generación aleatoria con fines criptográficos usa el módulo `secrets`**, nunca `random`.
4. **Nunca uses `print()` para logging** — usá `get_logger(...)`.
5. **No silencies excepciones de red/criptográficas con `except Exception: pass`** — como mínimo logueá el error.
6. **Este servicio no toca el HSM directamente** — todo pasa por `HSMClient` → `RemoteHSMClient`. No agregues un cliente PKCS#11 directo.
7. **El Dockerfile de producción corre como usuario no-root** (`USER app`) — no lo reviertas.
8. **No agregues dependencias nuevas** sin evaluar mantenimiento/licencia/seguridad — `safety check` después de cualquier cambio a `requirements/`.
9. Cambios en `app/domain/`, `app/infrastructure/external/hsm/`, `app/interfaces/auth/` requieren explicar el razonamiento de seguridad en el PR, no solo "funciona".

## Convenciones de código

- `black app/` antes de cualquier commit; `flake8 app/` no debe reportar nada nuevo.
- Manejo de errores: lanzar subclases de `DomainError` (`app/domain/exceptions/domain_errors.py`), no `ValueError`/`Exception` genéricas.
- Puertos como `ABC` en `domain/ports/{input,output}/` — adaptadores concretos en `infrastructure/`. No importes `infrastructure/` desde `domain/`.
- DTOs/schemas HTTP son modelos Pydantic en `interfaces/schemas/`, separados de las entidades de dominio.
- Async en toda la cadena. Una llamada bloqueante dentro de un handler async es un bug a evitar.
- Antes de escribir un helper nuevo, revisá `app/core/` y `app/application/services/` — correlation ID, logger, config e idempotencia ya están centralizados.

## Pruebas

- La capa HSM **siempre se mockea** en tests — usá `InMemoryHSMClient`, nunca apuntes un test a un `hsm-service` real.
- `pytest-asyncio` ya está configurado.
- Antes de dar por terminada una tarea: `pytest -v --cov=app`, `bandit -r app/`, y si tocaste `requirements/`, `safety check -r requirements/base.txt`.
- Si agregás el primer caso de uso de firma en `app/application/use_cases/`, agregá su test en el mismo PR — hoy la cobertura de negocio es cero porque no existe negocio todavía.

## Notas de entorno (Windows / Docker)

- PowerShell para operaciones nativas de Windows, Bash (Git Bash) para scripts POSIX.
- `keys/`, `.env`, `venv/` no están versionados — si faltan al clonar, es esperado.
- `config/config.yaml` **sí está versionado** — nunca pongas un secreto real ahí, ni siquiera temporalmente.

## Al terminar una tarea

- Si tu cambio toca endpoints HTTP o casos de uso, agregá o actualizá un test que valide el comportamiento esperado.
- Si tu cambio afecta la estructura del proyecto o los comandos esenciales, actualizá este archivo y `AGENTS.md` juntos — no dejes que diverjan.
- Si encontrás un hallazgo nuevo del mismo tipo que los ya documentados en `hsm-service`/`certificate-service` (secreto hardcodeado, excepción silenciada, stub vacío asumido como implementado), es razonable corregirlo en el mismo PR si es pequeño y aislado, o anotarlo en la sección "⚠️ Antes de empezar" de este archivo si es mayor y fuera del alcance de la tarea actual — esa sección todavía no tiene hallazgos propios, pero debería empezar a tenerlos en vez de quedar vacía para siempre.
