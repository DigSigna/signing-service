# Estructura del repositorio

Ver `CLAUDE.md`/`AGENTS.md` ("Estructura real del repositorio") para la versión comentada y siempre actualizada. Este archivo es solo el árbol, para referencia rápida.

```text
.
├── app/
│   ├── main.py
│   ├── core/                          # config, logger, request context
│   ├── domain/
│   │   ├── entities/                  # AuditEvent, IdempotencyRecord, SignatureRecord, SigningSession, Tenant
│   │   ├── events/                    # vacía hoy
│   │   ├── exceptions/domain_errors.py
│   │   ├── ports/{input,output}/      # interfaces ABC (incl. SignDocumentUseCase, CertificateClient, PAdESSigner)
│   │   └── valueobjects/
│   ├── application/
│   │   ├── dto/                       # vacía hoy
│   │   ├── mappers/                   # vacía hoy
│   │   ├── services/                  # idempotency.py, audit_helpers.py, signing_pin_session.py
│   │   └── use_cases/sign_document.py
│   ├── infrastructure/
│   │   ├── audit/
│   │   ├── auth/
│   │   ├── crypto/pyhanko_pades_signer.py   # PyHankoPAdESSigner (PAdES-B real)
│   │   ├── database/{models,repositories,adapters}/
│   │   └── external/{hsm,certificate,redis,audit,do_storage}/   # certificate/ incl. intermediate_cache.py
│   └── interfaces/
│       ├── auth/permissions.py
│       ├── dependencies.py
│       ├── middleware/
│       ├── routes/{health,signing}.py
│       └── schemas/
├── tests/
├── scripts/{redis,sonar,docker}/
├── config/config.yaml
├── docs/signing-plan.md               # plan de diseño (puntos 2-7 pendientes)
├── requirements/{base,dev}.txt
├── Dockerfile, Dockerfile.dev
├── docker-compose.yml, docker-compose.dev.yml
└── Makefile
```
