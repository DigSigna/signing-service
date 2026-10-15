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
│   │   ├── ports/{input,output}/      # interfaces ABC (incl. SignDocumentUseCase, CertificateClient)
│   │   └── valueobjects/
│   ├── application/
│   │   ├── dto/                       # vacía hoy
│   │   ├── mappers/                   # vacía hoy
│   │   ├── services/                  # idempotency.py, audit_helpers.py, signing_pin_session.py
│   │   └── use_cases/sign_document.py
│   ├── infrastructure/
│   │   ├── audit/
│   │   ├── auth/
│   │   ├── database/{models,repositories,adapters}/
│   │   └── external/{hsm,certificate,redis,audit,do_storage}/
│   └── interfaces/
│       ├── auth/permissions.py
│       ├── dependencies.py
│       ├── middleware/
│       ├── routes/{health,signing}.py
│       └── schemas/
├── tests/
├── scripts/{redis,sonar,docker}/
├── config/config.yaml
├── requirements/{base,dev}.txt
├── Dockerfile, Dockerfile.dev
├── docker-compose.yml, docker-compose.dev.yml
└── Makefile
```
