# Estructura del repositorio

Ver `CLAUDE.md`/`AGENTS.md` ("Estructura real del repositorio") para la versión comentada y siempre actualizada. Este archivo es solo el árbol, para referencia rápida.

```text
.
├── app/
│   ├── main.py
│   ├── core/                          # config, logger, request context
│   ├── domain/
│   │   ├── entities/                  # AuditEvent, IdempotencyRecord, Signature, SigningRequest, SigningSession, Tenant
│   │   ├── events/                    # vacía hoy
│   │   ├── exceptions/domain_errors.py
│   │   ├── ports/{input,output}/      # interfaces ABC (incl. SignDocumentUseCase, CreateSigningRequestUseCase, SignIncrementUseCase, GetSigningRequestUseCase, CertificateClient, PAdESSigner, SigningRequestRepository)
│   │   └── valueobjects/
│   ├── application/
│   │   ├── dto/                       # vacía hoy
│   │   ├── mappers/                   # vacía hoy
│   │   ├── services/                  # idempotency.py, audit_helpers.py, signing_pin_session.py, signing_core.py
│   │   └── use_cases/                 # sign_document.py, create_signing_request.py, sign_increment.py, get_signing_request.py
│   ├── infrastructure/
│   │   ├── audit/
│   │   ├── auth/
│   │   ├── crypto/{pyhanko_pades_signer,fallback_timestamper}.py   # PAdES real + sello RFC 3161 con fallback
│   │   ├── database/{models,repositories,adapters}/   # signing_request_repository.py (reemplaza signature_record_repository.py)
│   │   └── external/{hsm,certificate,redis,audit,do_storage}/   # certificate/ incl. intermediate_cache.py
│   └── interfaces/
│       ├── auth/permissions.py
│       ├── dependencies.py
│       ├── middleware/
│       ├── routes/{health,signing}.py   # /sign, /signing-requests, /signing-requests/{id}/sign, /signing-requests/{id}
│       └── schemas/
├── tests/
├── scripts/{redis,sonar,docker}/
├── config/config.yaml
├── docs/signing-plan.md               # plan de diseño — los 7 puntos cerrados, es bitácora
├── requirements/{base,dev}.txt
├── Dockerfile, Dockerfile.dev
├── docker-compose.yml, docker-compose.dev.yml
└── Makefile
```
