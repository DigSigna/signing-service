.PHONY: build build-dev up down logs ps restart compose-dev-up compose-dev-down infra-up infra-down cache-token cache-token-del

build:
	docker build -t signing-service .

build-dev:
	docker build -f Dockerfile.dev -t signing-service:dev .

# docker-compose.dev.yml se une a la red "hsm-network" y usa el MySQL
# compartido de hsm-service — levantá ese stack primero:
#   cd ../hsm-service && make dev-up
compose-dev-up:
	@echo "Requiere hsm-service corriendo (cd ../hsm-service && make dev-up) antes de continuar."
	docker-compose -f docker-compose.dev.yml up --build

compose-dev-down:
	docker-compose -f docker-compose.dev.yml down

up: compose-dev-up

down: compose-dev-down

# Infra standalone (docker-compose.yml): MySQL propio + migraciones, sin
# hsm-service. Pensado para correr con HSM_BACKEND=in_memory y uvicorn local
# (ver README). No lo corras junto con hsm-service: ambos publican MySQL en 3306.
infra-up:
	docker-compose -f docker-compose.yml up -d

infra-down:
	docker-compose -f docker-compose.yml down

logs:
	docker-compose -f docker-compose.dev.yml logs -f --tail=100

ps:
	docker-compose -f docker-compose.dev.yml ps

restart:
	docker-compose -f docker-compose.dev.yml restart

cache-token:
	@if [ -z "$(TOKEN_ID)" ]; then echo "TOKEN_ID is required"; exit 1; fi
	@python scripts/redis/cache_token.py --token-id "$(TOKEN_ID)" --ttl $(or $(TTL),3600)

cache-token-del:
	@if [ -z "$(TOKEN_ID)" ]; then echo "TOKEN_ID is required"; exit 1; fi
	@python scripts/redis/delete_token.py --token-id "$(TOKEN_ID)"
