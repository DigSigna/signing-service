# Estructura del repositorio

Ver `CLAUDE.md`/`AGENTS.md` ("Estructura real del repositorio") para la versión comentada y siempre actualizada. Este archivo es solo el árbol, para referencia rápida.

```text
.
├── app/
│   ├── main.py
│   ├── core/                          # config (logger/request context ahora en py_common.core, extraído a
│   │                                   # DigSigna/py-common, 2026-10-17)
│   ├── domain/
│   │   ├── entities/                  # Signature, SigningRequest, SigningSession, Tenant
│   │   │                              # (AuditEvent/IdempotencyRecord ahora en py_common)
│   │   ├── events/                    # vacía hoy
│   │   ├── exceptions/domain_errors.py   # subclases propias — DomainError base en py_common.errors
│   │   ├── ports/{input,output}/      # interfaces ABC propias (incl. SignDocumentUseCase, CreateSigningRequestUseCase,
│   │   │                              # SignIncrementUseCase, GetSigningRequestUseCase, CancelSigningRequestUseCase
│   │   │                              # (Caso 2), VoidSigningRequestUseCase (Caso 3, Opción B), CertificateClient,
│   │   │                              # PAdESSigner, SigningRequestRepository — Audit*/JWT*/IdempotencyRepository
│   │   │                              # ahora en py_common)
│   │   └── valueobjects/              # (IdentityContext/OwnerType/ActorType/AuditStrategy ahora en py_common)
│   ├── application/
│   │   ├── dto/                       # vacía hoy
│   │   ├── mappers/                   # vacía hoy
│   │   ├── services/                  # audit_helpers.py, signing_pin_session.py, signing_core.py,
│   │   │                              # signing_request_access.py (autorización compartida de /void)
│   │   │                              # (idempotency.py ahora en py_common.idempotency)
│   │   └── use_cases/                 # sign_document.py, create_signing_request.py, sign_increment.py,
│   │                                   # get_signing_request.py, cancel_signing_request.py (Caso 2),
│   │                                   # void_signing_request.py (Caso 3, Opción B)
│   ├── infrastructure/
│   │   ├── crypto/{pyhanko_pades_signer,fallback_timestamper}.py   # PAdES real + sello RFC 3161 con fallback
│   │   ├── database/{models,repositories,adapters}/   # signing_request_repository.py (reemplaza signature_record_repository.py);
│   │   │                              # audit_event/idempotency_key ahora en py_common
│   │   └── external/{hsm,certificate,do_storage}/   # certificate/ incl. intermediate_cache.py
│   │                                   # (redis/, audit/ ahora en py_common.auth/py_common.audit)
│   └── interfaces/
│       ├── dependencies.py
│       ├── routes/{health,signing}.py   # /sign, /signing-requests, /signing-requests/{id}/sign,
│       │                               # /signing-requests/{id}/cancel, /signing-requests/{id}/void,
│       │                               # /signing-requests/{id}
│       └── schemas/
│                                       # (auth/permissions.py, middleware/ ahora en py_common.auth / py_common.middleware)
├── tests/
├── scripts/{redis,sonar,docker}/
├── config/config.yaml
├── docs/signing-plan.md               # plan de diseño — los 7 puntos cerrados, es bitácora
├── requirements/{base,dev}.txt
├── Dockerfile, Dockerfile.dev
├── docker-compose.yml, docker-compose.dev.yml
└── Makefile
```
