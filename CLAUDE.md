# CLAUDE.md — Signing Service

Instrucciones para Claude Code trabajando en este repositorio. Este archivo es el equivalente para Claude Code de `AGENTS.md` — mismas reglas, mismo proyecto. Si divergen, `AGENTS.md` es la fuente canónica; abre un PR para corregir el otro.

## ⚠️ Antes de empezar

Este repositorio nació (2026-10-14) como una copia literal de `certificate-service` — mismo stack, misma arquitectura hexagonal — para no reconstruir desde cero la infraestructura que ambos servicios comparten (JWT/JWKS, auditoría híbrida, contexto de request, cliente HSM). Esa copia ya fue **recortada**: todo lo específico del dominio de certificados/CA se eliminó; solo quedó la infraestructura genérica. Ver el primer commit del repo (`chore: baseline copy from certificate-service`) si necesitás comparar contra el original sin recortar.

Los patrones de seguridad de `hsm-service/CLAUDE.md` y `certificate-service/CLAUDE.md` (mismo espíritu, Go o Python según el servicio) aplican igual acá.

**Hallazgos ya identificados que no debes repetir:**
- `DomainError.to_dict()` (`app/domain/exceptions/domain_errors.py`, copiado tal cual de `certificate-service`) serializaba cualquier campo `datetime` de una subclase (p. ej. `SigningPinLockedError.locked_until`, agregado en esta misma tarea) sin convertirlo a string — `ErrorHandlingMiddleware` pasa ese dict directo a `JSONResponse(content=...)`, que llama a `json.dumps()` sin encoder para `datetime` y lanza `TypeError`. En la práctica, cualquier error de dominio que cargue un campo `datetime` nunca llegaría al caller como la respuesta HTTP limpia que se esperaba, sino como un error no manejado. **Ya corregido** (acá y en `certificate-service`, donde se encontró primero) con un helper `_jsonable()` que hace `.isoformat()` en cualquier `datetime` antes de meterlo en `details` — si agregás un nuevo campo `datetime` a una subclase de `DomainError`, no necesitás hacer nada especial, pero si agregás algún otro tipo no serializable por `json.dumps` (p. ej. `UUID`, `Decimal`), extendé `_jsonable()`, no asumas que `to_dict()` ya lo cubre.
- Los modelos SQLAlchemy de este servicio nunca declaran `ForeignKey` (mismo estilo minimalista que `Tenant`/`AuditEvent`/`IdempotencyKey`: columnas sueltas, sin metadata de FK). Eso es inofensivo mientras cada repositorio escriba una sola tabla — pero `SQLAlchemySignatureRecordRepository.create()` escribe `signing_requests` y `signatures` (1:1, con una FK real en la base hacia `signing_requests.id`) en la misma transacción, y sin esa metadata SQLAlchemy no tiene forma de saber que `Signature` depende de `SigningRequest` — el autoflush implícito de `session.add()` + `commit()` terminó mandando el INSERT de `signatures` primero, y la FK real de la base lo rechazó (`IntegrityError 1452`). **Ya corregido**: `await self._session.flush()` explícito entre ambos `add()`, forzando el orden sin necesidad de declarar `ForeignKey`. Si agregás un repositorio nuevo que escriba más de una tabla con una dependencia entre ellas, no asumas que el orden de tus `add()` alcanza — o declarás la `ForeignKey`, o flusheás explícitamente entre medio. Encontrado corriendo el repositorio contra la base de dev real (`hsm-service-mysql-1`), no en los tests unitarios (que mockean el repositorio, no SQLAlchemy).
- `PROJECT_NAME` (título del OpenAPI, `app/main.py`) puede venir de `.env` (alias plano `PROJECT_NAME`) o de `config/config.yaml` (`project.name`, vía `AliasPath`). Un `.env` local con un valor plano (p. ej. copiado sin editar de `certificate-service`) **siempre gana**, sin importar el orden de `settings_customise_sources`: `AliasChoices` prueba el alias plano primero contra el diccionario ya fusionado de todas las fuentes, y ese alias solo existe en `.env`/variables de entorno reales (`config.yaml` solo aporta la clave anidada `project.name`), así que no hay conflicto de prioridad entre fuentes que resolver — el alias plano simplemente está presente y el anidado no. No es un bug: es el comportamiento esperado para que un `.env` local pueda pisar cualquier default. Si el swagger muestra un título viejo, es tu `.env` local, no `config.yaml`.
- `docker-compose.dev.yml` necesitó `CERTIFICATE_SERVICE_BASE_URL`/`CERTIFICATE_SERVICE_TIMEOUT` agregados a mano al bloque `environment:` del contenedor — agregar la variable a `config.py`/`.env.example` no alcanza, el contenedor real corre con lo que compose le pasa explícitamente. Si agregás una env var nueva que un cliente HTTP necesita en runtime, agregala ahí también (mismo patrón que `HSM_SERVICE_BASE_URL`), o vas a ver "client not initialized" en vez del error que esperabas. **Ya corregido.**
- Agregar una dependencia nueva a `requirements/base.txt` (p. ej. `pyhanko`) no alcanza con reiniciar el contenedor (`up -d`) — `Dockerfile.dev` instala requirements en **build time**, así que hace falta `docker-compose -f docker-compose.dev.yml up -d --build` (o `make build-dev` y volver a levantar). Un restart simple deja el paquete viejo (o ausente) adentro del contenedor.
- `signatures.signature_format` es un ENUM de MySQL (`PKCS7`/`CMS`/`RAW`/`JWS`, migración 003) bajo `STRICT_TRANS_TABLES` — escribir cualquier valor fuera de esa lista (p. ej. `"PAdES-B"`, lo que el punto 1 de `signing-plan.md` realmente produce) hace fallar el `INSERT` directo, no lo trunca silenciosamente. **Esto estuvo roto desde el punto 1** — el smoke test de esa tarea usó el literal `"RAW"` a mano en vez de pasar por el flujo real con la constante que terminó en el código, así que nunca lo atrapó. **Ya corregido**: migración 025 amplía el ENUM con `PAdES-B`/`PAdES-T`. Si agregás un valor nuevo a cualquier columna `ENUM` de este esquema compartido, verificá la definición real de la columna (`information_schema.COLUMNS`) contra lo que el código va a escribir — no asumas que "es solo un string" alcanza para un `ENUM`.
- `signatures` tenía `UNIQUE KEY uk_signature_request (signing_request_id)` desde la migración 003 — una restricción 1:1 real en la base, no solo una convención de código. El punto 4 del plan (N firmantes) la viola por diseño: un `signing_request` necesita poder tener más de una fila en `signatures`, una por firmante. **Ya corregido**: migración 026 (`DROP INDEX uk_signature_request` + `ADD INDEX idx_signatures_signing_request`, verificada up→down→up contra la base de dev real). Si en el futuro agregás otra tabla con una FK hacia `signing_requests`/`signatures` asumiendo 1:1, revisá primero si esa restricción sigue siendo cierta — ya no lo es.
- `idempotency_keys.uk_idempotency_tenant_request` es único sobre `(tenant_id, request_id)` **solamente** (migración 019) — la columna `operation` es metadata, no parte de la clave. Un mismo `request_id` de cliente solo puede reclamar **una** idempotency key, nunca dos bajo operaciones distintas. Esto importa porque `POST /api/v1/sign` (azúcar sintáctica sobre `POST /signing-requests` + `POST /signing-requests/{id}/sign`, punto 4.3) no puede componerse llamando a `claim_idempotency_key` dos veces (una por cada paso interno) bajo el mismo `request_id` — la segunda llamada chocaría con el claim de la primera y leería mal su `resource_id`. **Ya corregido**: `app/application/services/signing_core.py` expone helpers que NO tocan idempotencia; cada caso de uso público (`CreateSigningRequestUseCaseImpl`, `SignIncrementUseCaseImpl`, y el propio `SignDocumentUseCaseImpl`) envuelve exactamente un claim/finish alrededor de los helpers que necesite. Si agregás un caso de uso nuevo que combine pasos de otros dos, no le pongas su propio claim interno a cada paso — un único claim en el nivel más externo.
- La migración 016 (`tsa_token`/`tsa_provider`/`tsa_sealed_at` en `signatures`) **no estaba aplicada en la base de dev compartida** pese a que `schema_migrations` reportaba versión 23 (limpia, sin "dirty"). `015`/`016` son los únicos dos archivos del repo `migrations` nombrados con un espacio después del número de versión (`016 add tsa evidence to signatures.up.sql`) en vez del guión bajo que usa el resto (`NNN_snake_case`) — causa probable, no confirmada, de por qué el histórico de esta base en particular la saltó. **No asumas que una migración documentada en el repo `migrations` ya está aplicada en la base que estás usando** — confirmá contra `DESCRIBE`/`information_schema.COLUMNS`, no contra `schema_migrations.version` ni contra la existencia del archivo. Ver `platform-docs/security/known-deviations.md` (KD-012) — no se renombró el archivo ni se tocó `schema_migrations` (riesgo real si otro entorno ya trackeó ese nombre), solo se aplicó la migración a mano en esta base de dev para destrabar la verificación.

**Qué se mantuvo de la copia (infraestructura genérica, ya wireada y funcionando):**
- `app/core/` completo: config (Pydantic Settings + YAML + expansión de env vars), logger JSON estructurado, request context (contextvars).
- Auth JWT: `app/interfaces/auth/`, `app/infrastructure/auth/{key_manager_adapter,validator_adapter}.py`, `AuthMiddleware` — corre sobre todas las requests salvo `/health`.
- Auditoría híbrida: `app/infrastructure/audit/{audit_worker,factory,hybrid_processor}.py` + `app/infrastructure/external/audit/http_audit_transporter.py` + `AuditEvent`/`SQLAlchemyAuditRepository` (tabla `audit_logs`, esquema compartido). Circuit breaker igual al de `hsm-service`.
- Cliente HSM: `app/domain/ports/output/HSMClient.py` + `RemoteHSMClient` (HTTP a `hsm-service`) + `InMemoryHSMClient` (stub de dev/tests) — este servicio **tampoco** opera el HSM directamente.
- `TenantRepository` (+ `AuditedTenantRepository`, decorador de auditoría) contra la tabla `tenants` compartida — lectura de `hsm_slot_id`/`mode`, nada de jerarquía CA.
- Idempotencia genérica: `IdempotencyRepository`/`IdempotencyRecord` + `claim_idempotency_key`/`finish_idempotency_claim` (`app/application/services/idempotency.py`) — para envolver cualquier caso de uso mutante futuro que acepte un `request_id` del cliente.
- `DomainError` (jerarquía base de dataclasses) + subclases genéricas (`ValidationError`, `NotFoundError`, `AuthorizationError`, `ConfigurationError`, `DuplicateRequestError`, `TenantRequiredError`, `OwnerIdRequiredError`, `InvalidOwnerTypeError`, `HsmError`/`HsmConnectionError`/`HsmOperationError`, `AuditError`/`AuditDispatchError`/`AuditStorageError`) — consumida por `ErrorHandlingMiddleware`.
- `require_admin`/`get_identity_context` (`app/interfaces/auth/permissions.py`) como dependencia de FastAPI, no middleware global.
- `/health` (DB + Redis, sin auth) — el único endpoint HTTP wireado hoy.

**Qué se agregó, propio de este servicio (ADR-005 — signing PIN, ver `platform-docs/architecture/ADR/ADR-004-...md`, numerado ADR-005 en su propio título):** el PIN en sí vive en `certificate-service` (dueño de la fila `certificates`); este servicio solo lo consume y además posee la ventana de gracia que el ADR le asigna explícitamente:
- `SigningPinVerifier` (puerto) + `RemoteSigningPinVerifier` (`app/infrastructure/external/certificate/http_pin_verifier.py`) — llama a `POST {CERTIFICATE_SERVICE_BASE_URL}/internal/certificates/{id}/verify-pin` reenviando el JWT del caller, y traduce los códigos de error de certificate-service (`SIGNING_PIN_INVALID`/`_LOCKED`/`_NOT_SET`/`_NOT_APPLICABLE`) a los `DomainError` locales equivalentes (`app/domain/exceptions/domain_errors.py`, sección "Signing PIN").
- `SigningSession` (entidad) + `SigningSessionRepository` (puerto) + `SQLAlchemySigningSessionRepository`, sobre la tabla propia `signing_pin_sessions` (migración 023 del repo `migrations`, mismo esquema compartido) — la ventana de gracia: tras un PIN verificado con éxito, una sesión permite firmar más documentos sin re-pedir el PIN, acotada por `expires_at` y/o `max_signatures`.
- `app/application/services/signing_pin_session.py`: `try_resume_session()` (reusa una sesión vigente, sin consumir nada), `start_session()` (verifica el PIN vía `SigningPinVerifier` y emite una sesión nueva) y `record_signature()` (consume una firma del cupo — se llama solo después de que hsm-service realmente firmó, nunca antes, para que un intento fallido no gaste cupo). Pensadas para ser compuestas por el futuro caso de uso de `/sign`, que todavía no existe (ver abajo).
- `CERTIFICATE_SERVICE_BASE_URL`/`CERTIFICATE_SERVICE_TIMEOUT` y `SIGNING_PIN_SESSION_TTL_MINUTES`/`SIGNING_PIN_SESSION_MAX_SIGNATURES` (`app/core/config.py`, `config/config.yaml`) — este último es `0` = sin límite de firmas (solo manda `expires_at`).
- El token de sesión es generado con `secrets.token_urlsafe` (nunca `random`) y solo se persiste su hash SHA-256 (`session_token_hash`) — el token crudo se devuelve una sola vez al caller y nunca se guarda en ningún lado, mismo razonamiento que `certificates.pin_hash`.

**`POST /api/v1/sign` (único endpoint de negocio wireado, además de `/health`):** hashea el documento (SHA-256, solo para el registro propio, `signing_requests.document_hash` — nunca lo que efectivamente se firma, ver abajo), obtiene y valida la cadena del certificado vía `certificate-service` (`CertificateClient`/`RemoteCertificateClient`, `app/infrastructure/external/certificate/http_certificate_client.py`: `GET /api/v1/certificates/{id}` + `POST /internal/certificates/validate-chain`), resuelve PIN/sesión (ADR-005, arriba) y produce una firma **PAdES-B real** (no un blob crudo) vía `PAdESSigner`/`PyHankoPAdESSigner` (`app/infrastructure/crypto/pyhanko_pades_signer.py`, signing-plan.md punto 1). Idempotente vía el mismo `claim_idempotency_key`/`finish_idempotency_claim` que usa `certificate-service` (clave: `X-Request-ID`). Persiste en las tablas compartidas `signing_requests`/`signatures` (migración 003 del repo `migrations`, **no 023/024** — esas tablas ya existían, de antes del patrón `Owner(type,id)`; por eso `signing_requests.user_id`/`organization_id` son FKs rígidas a `users`/`organizations`, no una columna polimórfica suelta como `certificates.owner_id`) a través de `SignatureRecord` (entidad aplanada 1:1) + `SignatureRecordRepository`/`SQLAlchemySignatureRecordRepository`.

- **`signature_format` es `"PAdES-T"` si un TSA real selló la firma, `"PAdES-B"` si no** — el artefacto es el PDF completo con la firma embebida vía *incremental update* (`signed_document_b64` en la respuesta), no una firma separada del documento. `signatures.signature_value` es `LONGBLOB` (migración 024 — el `BLOB` original de migración 003, 64KB, no entra un PDF firmado real), y `signature_format` es un ENUM ampliado por la migración 025 (ver hallazgo arriba).
- **Cadena embebida: hoja + intermedio, nunca la raíz** (signing-plan.md, decisión del punto 1). La raíz es el ancla de confianza del verificador, no algo que el documento deba cargar. El PEM del intermedio se obtiene de `certificate.issuer_certificate_id` y se cachea en `IntermediateCertificateCache` (`app/infrastructure/external/certificate/intermediate_cache.py`, TTL `CERTIFICATE_CHAIN_CACHE_TTL_HOURS`, default 24h) — la misma CA emite todos los certificados de un tenant, así que sin el cache cada firma pagaría un round-trip extra a `certificate-service` que casi nunca cambia de resultado.
- **Timestamp RFC 3161 de la firma (ADR-002/signing-plan.md punto 3), con fallback**: `FallbackChainTimeStamper` (`app/infrastructure/crypto/fallback_timestamper.py`), sobre `pyhanko.sign.timestamps.HTTPTimeStamper` (RFC 3161 real, nunca construido a mano). Primario FreeTSA.org, secundario Certum — **no ANF AC**, el primario que nombra el ADR: no tiene endpoint público documentado (su propia política de TSA dice que la URL es por contrato/suscripción), decisión tomada con el usuario durante esta tarea. Swapear ANF AC más adelante es cambiar `TSA_PRIMARY_URL`, no un rediseño. Ver `known-deviations.md` KD-011.
  - Se sella **el valor de la firma**, nunca el documento ni su hash — inherente a cómo pyHanko invoca al timestamper (después de que el signer ya produjo `signatureValue`), no algo que este servicio orquesta a mano.
  - Si los dos TSA fallan, no bloquea la firma: cae a un pseudo-timestamp local (`tsa_provider="local-pseudo"`, `tsa_token=None`, `signature_format="PAdES-B"`) — esa cadena es la marca para un futuro job de re-sellado, que explícitamente no se construyó (fuera de alcance del punto 3).
  - **Nunca reutilices una instancia de `FallbackChainTimeStamper` entre requests.** Guarda `last_provider`/`last_token_der` como estado de instancia (pyHanko no tiene otra forma de exponer cuál TSA respondió desde dentro de `async_sign_pdf()`), y pyHanko además llama al timestamper dos veces por firma (una para estimar tamaño vía `async_dummy_response`, otra real) con varios `await` entre medio — una instancia compartida entre requests concurrentes puede leer el resultado de otro request. Por eso `PyHankoPAdESSigner` recibe un `timestamper_factory` (callback) y construye uno nuevo por llamada a `sign_pdf()`, nunca uno fijo en `main.py`.
- **No hay DSS/VRI (PAdES-LTV)** — sin revocación (CRL/OCSP) embebida. Decisión consciente de alcance v1 (signing-plan.md punto 3), registrada en `platform-docs/security/known-deviations.md` (KD-010), no una laguna silenciosa.
- **`PyHankoPAdESSigner.async_sign_raw()` recibe los bytes crudos de los atributos firmados de pyHanko, no el documento ni un digest.** El contrato de `pyhanko.sign.signers.Signer.async_sign_raw(data, digest_algorithm, dry_run)` coincide exactamente con el de `HSMClient.sign_hash()` (ambos esperan datos sin hashear, hashean internamente) — por eso no hace falta ningún puente sync/async como el que `hsm_backed_key.py` necesitaba en `certificate-service` (eliminado de este repo durante el recorte inicial; `pyhanko`'s signer API es nativamente async). `dry_run=True` debe devolver bytes placeholder del tamaño exacto de la firma real (RSA: `key_size // 8`, exacto; ECDSA: estimado generoso, no hay certs ECDSA reales en este sistema todavía — ver comentario en el módulo).
- El `session_token` de la respuesta viene vacío (`None`) en un replay por idempotencia — no es recuperable ahí, solo se busca por su hash, nunca por `signing_request_id` (ver `SignDocumentUseCaseImpl`).

**N firmantes (signing-plan.md punto 4) — `POST /signing-requests`, `POST /signing-requests/{id}/sign`, `GET /signing-requests/{id}`:** `POST /api/v1/sign` de arriba es hoy azúcar sintáctica sobre este flujo (`signers_number=1`, crea y firma en la misma llamada — punto 4.3), no un camino de código paralelo. Migración 026 agrega `signers_number`/`signatures_count`/`document_blob`/`completed_at`/`version` a `signing_requests` y relaja `signatures` de 1:1 a 1:N (ver hallazgo arriba).

- Entidades/puertos nuevos: `SigningRequest` + `Signature` (`app/domain/entities/`) y `SigningRequestRepository` (`app/domain/ports/output/`, reemplaza a `SignatureRecordRepository`/`SignatureRecord`, eliminados — ya no describen el modelo real). `app/application/services/signing_core.py` tiene la lógica compartida (`create_signing_request_row`/`perform_signature_step`), deliberadamente sin tocar idempotencia (ver hallazgo arriba) — los tres casos de uso (`CreateSigningRequestUseCaseImpl`, `SignIncrementUseCaseImpl`, `SignDocumentUseCaseImpl`) la componen.
- **Concurrencia**: dos llamadas a `/signing-requests/{id}/sign` sobre el mismo id, en simultáneo, no deben poder pisarse (`document_blob`/`signatures_count` por last-write-wins perdería silenciosamente la firma de un firmante aunque hsm-service ya la hubiera producido). `signing_requests.version` es un token de concurrencia optimista: `SQLAlchemySigningRequestRepository.append_signature()` hace `UPDATE ... WHERE id=? AND version=?` y chequea `rowcount` — si pierde la carrera, no reintenta sola (podría re-disparar PIN/HSM/TSA para una firma que ya existe), lanza `SigningRequestConflictError` (409) para que el cliente reintente. Verificado contra la base de dev real, no solo con fakes (ver "Pruebas" más abajo) — con fakes que alían el mismo objeto Python entre `find_by_id` y el estado interno del repo, este bug es invisible (ver el propio `find_by_id` de los fakes en los tests, que devuelven una copia a propósito).
- **`signatures.signature_value` ya NO es el PDF completo para filas nuevas** (sí lo es para las viejas, pre-migración-026, de un solo firmante) — es solo el delta incremental que esa firma agregó (`nuevo_pdf[len(pdf_anterior):]`; los incremental updates de PDF son estrictamente append-only, así que es exactamente la contribución de ese firmante, sin librería extra). Decisión deliberada por el punto 5 del plan ("no construir snapshots por firmante"): el único PDF completo vigente vive en `signing_requests.document_blob`, y la única forma soportada de leerlo es `GET /signing-requests/{id}`. `SignDocumentResult`/`SignDocumentResponse` (la respuesta de `/sign`) siguen devolviendo el PDF completo — lo leen de `document_blob` después del paso de firma, no de `signature_value`.
- **El sellado TSA (punto 3) solo se intenta en la firma que completa el request** (punto 4.2) — `PAdESSigner.sign_pdf()` ahora recibe `apply_timestamp: bool`; en una firma intermedia es `False` y `tsa_provider`/`tsa_token` quedan en `None` (no `"local-pseudo"` — esa cadena específicamente significa "se intentó y todos los TSA fallaron", no "no se intentó"). Cada llamada también recibe un `field_name` distinto (`f"Signature{signatures_count+1}"`) — pyHanko necesita un nombre de campo único por firma dentro del mismo PDF.
- `key_id` en `signing_requests` es legacy (pre-026): un request de N firmantes no tiene "un" certificado hasta que cada firmante firma con el suyo — las filas nuevas siempre lo dejan en `NULL`; el certificado/clave de cada firmante vive en su propia fila de `signatures`.

**Qué se eliminó (específico de certificados/CA, no aplica a firma de documentos):** entidad `Certificate` y sus value objects X.509 (`DistinguishedName`, `SerialNumber`, `RevocationInfo`, `KeyUsage`, `ExtendedKeyUsage`, `SubjectAlternativeNames`, `ValidityPeriod`, `CertificateStatus`), los casos de uso de emisión/revocación/listado/validación de cadena, `TenantCARepository`/`CertificateRepository` y sus adaptadores SQLAlchemy, `x509_builder.py`/`x509_verifier.py`/`hsm_backed_key.py` (construcción de certificados X.509 firmados por el HSM), las rutas `cas.py`/`certificates.py`/`internal_certificates.py` y sus schemas, el proxy público `/hsm/*` (este servicio llama a `RemoteHSMClient` internamente, no necesita exponer gestión de claves), y los errores de dominio específicos de CA/certificado. `Algorithm`/`KeyPurpose` se mantuvieron — son atributos genéricos de clave del `HSMClient`, no de X.509.

## Qué es este servicio

Signing Service: API REST en Python (FastAPI) para firma digital de documentos, multi-tenant, arquitectura hexagonal. Según el flujo documentado en `platform-docs` (DLT-015, `architecture/sprint-1.0/diagrams/flow/signatures/`) y refinado en `docs/signing-plan.md`: recibe un documento, calcula su hash (registro propio), obtiene y valida el certificado del firmante vía `certificate-service` (`GET /certificates/{id}` + `POST /internal/certificates/validate-chain`), produce una firma PAdES real (hoja + intermedio embebidos, con intento de sello RFC 3161 — PAdES-T si un TSA responde, PAdES-B si no) vía `hsm-service` y la persiste. **No opera el HSM ni emite certificados directamente** — delega ambas cosas a sus servicios hermanos. Todavía no valida firmas existentes (`/verify`, pendiente).

**Estado real del repositorio (no asumas que hay más de lo que hay):** cuatro endpoints de negocio wireados end-to-end: `POST /api/v1/sign` (azúcar sobre el flujo de N firmantes), `POST /signing-requests`, `POST /signing-requests/{id}/sign`, `GET /signing-requests/{id}` — PAdES real + sello de tiempo con fallback + N firmantes (signing-plan.md puntos 1, 3 y 4 cerrados); **todavía no hay verificación de firmas** (`/verify` o similar no existe), ni DSS/VRI (PAdES-LTV completo, punto 3 lo deja fuera de alcance a propósito). `app/application/dto/` y `app/application/mappers/` siguen vacíos. `app/domain/events/` e `app/infrastructure/external/do_storage/` existen como carpetas vacías (ni `__init__.py`). Ver `docs/signing-plan.md` para el resto del plan (puntos 5-7; 1-4 cerrados) — este archivo no repite ese contenido, solo refleja qué de ahí ya está hecho.

Stack: Python 3.11, FastAPI, Pydantic v2 (`pydantic-settings`), SQLAlchemy 2.0 async (`asyncmy`), Redis (cache de tokens JWT), `cryptography>=48.0.0` (bumped para `pyhanko`; usada también por `InMemoryHSMClient`/tests), `pyhanko`/`pyhanko-certvalidator` (firma PAdES + timestamping RFC 3161 — signing-plan.md puntos 1 y 3), PyJWT, Uvicorn.

## Estructura real del repositorio

`STRUCTURE.md` tiene el árbol completo — mantenelo sincronizado si agregás o quitás módulos.

```text
app/
  core/                                 # config, logger JSON, request context — igual a certificate-service/hsm-service
  domain/
    entities/                           # AuditEvent, IdempotencyRecord, Signature, SigningRequest, SigningSession, Tenant — sin Certificate
    events/                             # carpeta vacía hoy (ni __init__.py)
    exceptions/domain_errors.py         # jerarquía de excepciones genérica + Signing PIN + CertificateClient + SigningRequest (sin subclases de CA/certificado)
    ports/{input,output}/               # SignDocumentUseCase, CreateSigningRequestUseCase, SignIncrementUseCase, GetSigningRequestUseCase; AuditRecorder; AuditEventDispatcher/AuditStorage/AuditTransporter, CertificateClient, HSMClient, IdempotencyRepository, JWTKeyProvider/JWTValidator, PAdESSigner (+ PAdESSignResult), SigningRequestRepository, SigningPinVerifier, SigningSessionRepository, TenantRepository
    valueobjects/                       # ActorType, Algorithm, AuditData, AuditStrategy, IdentityContext, KeyPurpose, Owner(Type), PlanType, SigningRequestStatus, TenantMode, TenantStatus
  application/
    dto/, mappers/                      # VACÍOS hoy
    use_cases/                          # sign_document.py (azúcar sobre el flujo de abajo — punto 4.3), create_signing_request.py, sign_increment.py, get_signing_request.py
    services/                           # idempotency.py, audit_helpers.py, signing_pin_session.py (ADR-005), signing_core.py (lógica de firma compartida, sin idempotencia — ver hallazgo)
  infrastructure/
    audit/                              # audit_worker.py + factory.py + hybrid_processor.py — ya wireado si AUDIT_ENABLED
    crypto/                              # recreada tras el recorte inicial (eliminó x509_builder/verifier, no relacionados)
      pyhanko_pades_signer.py            # PyHankoPAdESSigner — firma PAdES real (signing-plan.md punto 1)
      fallback_timestamper.py            # FallbackChainTimeStamper — RFC 3161 con fallback primario/secundario (ADR-002, punto 3)
    database/                           # sesión SQLAlchemy async; models/{base,tenant,audit_event,idempotency_key,signing_pin_session,signing_request,signature}.py (signing_request.py = agregado 026); repositories/{tenant_repository,audit_repository,idempotency_repository,signing_pin_session_repository,signing_request_repository}.py; adapters/audited_tenant_repository.py
    external/hsm/                       # factory + RemoteHSMClient + InMemoryHSMClient
    external/certificate/               # http_pin_verifier.py (RemoteSigningPinVerifier) + http_certificate_client.py (RemoteCertificateClient) + intermediate_cache.py (IntermediateCertificateCache) — todos a certificate-service
    external/redis/                     # cache de tokens JWT
    external/audit/http_audit_transporter.py
    external/do_storage/                # carpeta vacía hoy (ni __init__.py)
  interfaces/
    auth/permissions.py                 # require_admin / get_identity_context
    middleware/                         # auth, logging, error_handling, request_context — las 4 ya registradas en main.py
    routes/{health,signing}.py          # GET /health; POST /sign, POST /signing-requests, POST /signing-requests/{id}/sign, GET /signing-requests/{id} — los únicos endpoints HTTP wireados hoy
    schemas/                            # errors.py, health.py, signing.py — sin schemas de certificado/CA
config/config.yaml                      # config base (fusiona con .env y env vars vía pydantic-settings)
scripts/redis/, scripts/sonar/, scripts/docker/
docs/signing-plan.md                    # plan de diseño agregado por el usuario — puntos 5-7 son trabajo pendiente (1-4 cerrados), ver ahí
bruno/                                  # colección de requests manuales (si existe)
tests/                                  # test_health, test_hsm_client, test_remote_hsm_client, test_idempotency_service, test_permissions, test_domain_errors, test_remote_signing_pin_verifier, test_signing_pin_session_service, test_remote_certificate_client, test_intermediate_certificate_cache, test_pyhanko_pades_signer, test_sign_document_use_case, test_create_signing_request_use_case, test_sign_increment_use_case, test_get_signing_request_use_case — mockeado salvo test_pyhanko_pades_signer.py, que firma y valida un PDF real con pyHanko (sin mockear pyHanko) para probar la integración de verdad, no solo "no explotó". `SQLAlchemySigningRequestRepository` (bloqueo optimista vía `version`) se verificó aparte contra la base de dev real, no solo con fakes — ver el hallazgo de la UNIQUE KEY arriba
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
Si cambiaste `requirements/`, un `make restart`/`up -d` simple **no** alcanza — `Dockerfile.dev` instala requirements en build time. Hace falta `docker-compose -f docker-compose.dev.yml up -d --build` (o `make build-dev` y volver a levantar).

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
- Si agregás un caso de uso nuevo en `app/application/use_cases/` (p. ej. verificación de firmas), agregá su test en el mismo PR, igual que `test_sign_document_use_case.py` para `SignDocumentUseCaseImpl` — todo con fakes, nunca una conexión real.
- Un repositorio SQLAlchemy nuevo que escriba más de una tabla con una dependencia entre ellas: probalo contra una base real al menos una vez (no solo con fakes) — ver el hallazgo de ordenamiento de `flush()` arriba, que ningún test unitario iba a atrapar.
- Código que envuelve una librería de criptografía/PDF externa (p. ej. `PAdESSigner`): no te quedes en "no tiró excepción" — generá certificados de prueba reales con `cryptography` (ver `test_pyhanko_pades_signer.py`) y validá el resultado con el propio validador de la librería (`pyhanko.sign.validation`), contra un trust root que controlás. Si escribís un certificado de prueba a mano, acordate del `KeyUsage` (`content_commitment`/non-repudiation) — los certificados reales de `certificate-service` siempre lo tienen, y la política de validación de `pyhanko` lo exige; sin él, un test puede fallar por una razón que no tiene nada que ver con el código que estás probando.
- Tests de `FallbackChainTimeStamper`/TSA: nunca contra FreeTSA.org/Certum reales — usá `pyhanko.sign.timestamps.DummyTimeStamper` (identidad TSA autofirmada, produce un token RFC 3161 real y parseable sin red) para el caso "un TSA respondió", y un `TimeStamper` fake que siempre lanza `TimestampRequestError` para el caso "todos fallan". Ambos se inyectan como delegados directos de `FallbackChainTimeStamper` — no hace falta mockear HTTP.

## Notas de entorno (Windows / Docker)

- PowerShell para operaciones nativas de Windows, Bash (Git Bash) para scripts POSIX.
- `keys/`, `.env`, `venv/` no están versionados — si faltan al clonar, es esperado.
- `config/config.yaml` **sí está versionado** — nunca pongas un secreto real ahí, ni siquiera temporalmente.
- `/sign` necesita salida a internet para sellar con un TSA real (FreeTSA.org/Certum) — si el entorno no tiene salida (sandbox, red aislada), no rompe nada: cae a `tsa_provider="local-pseudo"` automáticamente, misma ruta que "ambos TSA caídos".

## Al terminar una tarea

- Si tu cambio toca endpoints HTTP o casos de uso, agregá o actualizá un test que valide el comportamiento esperado.
- Si tu cambio afecta la estructura del proyecto o los comandos esenciales, actualizá este archivo y `AGENTS.md` juntos — no dejes que diverjan.
- Si encontrás un hallazgo nuevo del mismo tipo que los ya documentados arriba o en `hsm-service`/`certificate-service` (secreto hardcodeado, excepción silenciada, stub vacío asumido como implementado), es razonable corregirlo en el mismo PR si es pequeño y aislado, o anotarlo en la sección "⚠️ Antes de empezar" si es mayor y fuera del alcance de la tarea actual.
