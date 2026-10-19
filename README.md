# Signing Service

API REST en Python (FastAPI) para firma digital de documentos, multi-tenant, arquitectura hexagonal (ports & adapters). **No opera el HSM ni emite certificados directamente** — delega la operación criptográfica a [`hsm-service`](../hsm-service) vía HTTP y obtiene/valida el certificado del firmante vía [`certificate-service`](../certificate-service) (`GET /certificates/{id}`, `POST /internal/certificates/validate-chain`), reenviando el JWT del caller original (servicios stateless, sin token de servicio fijo).

**Estado actual:** firma de documentos end-to-end con PAdES real — PAdES-T cuando un TSA (RFC 3161, ADR-002) responde, PAdES-B con fallback a pseudo-timestamp local si no — con PIN/sesión (ADR-005), certificate-service, hsm-service y persistencia, para uno (`POST /sign`) o varios firmantes (`POST /signing-requests` + `POST /signing-requests/{id}/sign`, una llamada por firmante). Ver `CLAUDE.md`/`AGENTS.md` y `docs/signing-plan.md` (sus 7 puntos ya están cerrados — es la bitácora de diseño, no trabajo pendiente). Todavía no hay verificación de firmas, ni XAdES/CAdES (DLT-011 los decide; v1 solo PAdES — ver KD-013).

## Características

- **Python**: 3.11
- **Framework**: FastAPI + Pydantic v2
- **Arquitectura**: Hexagonal (domain/application/infrastructure/interfaces)
- **Persistencia**: SQLAlchemy 2.0 async (MySQL, esquema compartido con `hsm-service`/`certificate-service`)
- **Auth**: JWT stateless, verificado contra JWKS/clave pública (`AuthMiddleware`, sin token de servicio fijo)
- **ASGI**: Uvicorn

## Endpoints

| Método | Ruta | Qué hace |
|---|---|---|
| `POST` | `/sign` | Firma un documento (PDF) con un certificado propio, un solo firmante (PIN o session_token vigente — ADR-005). Azúcar sobre el flujo de abajo (`signers_number=1`, crea y firma en una sola llamada). Devuelve el PDF firmado completo (`signed_document_b64`); `signature_format` es `PAdES-T` si un TSA selló la firma (RFC 3161, ADR-002, con fallback entre proveedores), o `PAdES-B` si ningún TSA respondió (`tsa_provider="local-pseudo"`) |
| `POST` | `/signing-requests` | Crea un `signing_request` para uno o varios firmantes — recibe el documento una sola vez (`document_b64`, `signers_number`), no firma nada todavía |
| `POST` | `/signing-requests/{id}/sign` | Agrega la firma incremental de un firmante sobre el estado actual del documento. Si completa `signers_number`, sella con TSA en la misma llamada y marca `status=COMPLETED` |
| `GET` | `/signing-requests/{id}` | Solo lectura — estado del request y, si ya está `COMPLETED`, el PDF final (`document_b64`) |
| `GET` | `/health` | Health check (DB + Redis), sin autenticación |

(La verificación de firmas se agregará acá cuando se implemente.)

## Decisiones de arquitectura (ADRs)

- **ADR-002** (`platform-docs/architecture/ADR/ADR-002-...md`): sellado de tiempo RFC 3161 vía un TSA externo, con fallback primario/secundario y degradación a pseudo-timestamp local si ambos fallan. Ver `FallbackChainTimeStamper`.
- **ADR-003** (`.../ADR-003-...md`): Saga orquestada con compensación explícita para escrituras multi-servicio — **excluye explícitamente la firma de documentos** de ese requisito ("Document signing... is not in scope here"). La idempotencia vía `Idempotency-Key` que este servicio sí implementa es un patrón adoptado por su propio mérito (igual que `certificate-service`), no un mandato de este ADR para este flujo.
- **ADR-005** (`.../ADR-004-application-level-signing-PIN-...md` — el archivo se llama `ADR-004` pero su título interno es `ADR-005`; no existe un ADR-004 separado en este repo, es una irregularidad de numeración documentada, no un documento faltante): PIN de firma a nivel aplicación + ventana de gracia. El PIN y su rate-limiting/lockout (backoff exponencial) viven en `certificate-service`; este servicio solo los consume.
- **DLT-011** (`architecture/sprint-0.1/decision-log/DLT-011-...md`): decide soporte para PAdES + XAdES + CAdES. **v1 de este servicio solo implementa PAdES** (PAdES-B/PAdES-T) — desviación consciente de alcance, documentada en `docs/signing-plan.md` (punto 1) y en `platform-docs/security/known-deviations.md` (KD-013).

## Estructura
[STRUCTURE.md](./STRUCTURE.md) para el árbol completo.

## Configuración

La app carga configuración con el siguiente orden de prioridad:
1. Variables de entorno
2. Archivo `config/config.yaml`
3. Archivo `.env`

Puedes cambiar la ruta del YAML usando `CONFIG_FILE` o `CONFIG_PATH`.

### Comenzando

Hay dos formas de correr este servicio en local, según si necesitás el HSM real o no.

**Opción A — standalone, sin `hsm-service` (HSM stub en memoria):**
```bash
export DIGSIGNA_COMMON_TOKEN=<PAT con acceso de lectura a github.com/DigSigna/py-common>
pip install -r requirements/base.txt -r requirements/dev.txt

make infra-up   # docker-compose.yml: MySQL propio + migraciones compartidas

# .env con HSM_BACKEND=in_memory y DB_URL=mysql://digsigna:digsigna@localhost:3306/digsigna (ver .env.example)
uvicorn app.main:app --host 0.0.0.0 --port 8001 --reload

curl http://localhost:8001/api/v1/health
```

**Opción B — integración real con `hsm-service`:**
```bash
cd ../hsm-service && make dev-up   # mysql + migrate + softhsm + hsm-service, crea la red "hsm-network"
cd ../signing-service && make up   # docker-compose.dev.yml: se une a hsm-network, HSM_BACKEND=remote

curl http://localhost:8001/api/v1/health
```
No corras `infra-up` (Opción A) y el stack de `hsm-service` (Opción B) al mismo tiempo: ambos publican MySQL en el puerto 3306 del host.

Si cambiaste `requirements/`, un restart simple no alcanza — `Dockerfile.dev` instala dependencias en build time. Usá `docker-compose -f docker-compose.dev.yml up -d --build`.

## Docker
```bash
docker build -t signing-service .
curl http://localhost:8001/api/v1/health
```

## Conexión a Base de Datos

Configurar variables de entorno en `.env` o en el entorno de ejecución (ver `config/config.yaml` y `Settings.ensure_database_config` en `app/core/config.py` — el default de `DB_URL` no provee ninguna credencial funcional, a propósito):

```env
ENVIRONMENT=development
DB_URL=mysql://USER:PASSWORD@HOST:PORT/DATABASE_NAME?ssl-mode=REQUIRED
```

## Dev Container (VS Code)

`.devcontainer/devcontainer.json` permite abrir el proyecto dentro del contenedor usando `docker-compose.dev.yml`.

## Makefile

Atajos para construir la imagen y levantar el compose de desarrollo — ver `Makefile`.

## Quality Gate
```bash
pytest -v --cov=app
black --check app/ tests/
flake8 app/ tests/
bandit -r app/
safety check -r requirements/base.txt
```

## CI/CD

`.github/workflows/ci.yml` — misma estructura que `hsm-service`/`certificate-service`: job `quality` (black/flake8/bandit/pytest, gatean el merge; `safety check` informativo) en cada push/PR, y job `publish` (build + push a `ghcr.io/<repo>`) solo en push a `main` si `quality` pasó. Requiere el secret `GHCR_TOKEN`.
