from abc import ABC, abstractmethod
from uuid import UUID

from app.domain.valueobjects import Algorithm, KeyPurpose, Owner


class HSMClient(ABC):
    @abstractmethod
    async def create_key(
        self,
        tenant_id: UUID,
        name: str,
        algorithm: Algorithm,
        key_size: int,
        purpose: KeyPurpose,
        owner: Owner,
        bearer_token: str,
    ) -> UUID:
        """Crea un nuevo par de claves en el HSM y devuelve el key_id.

        bearer_token es el JWT del caller original (servicios stateless: sin
        token de servicio fijo, cada llamada se autentica con el JWT de
        quien originó el request; hsm-service deriva tenant_id/owner de ese
        mismo JWT, no del cuerpo de la request — ver RemoteHSMClient).
        """
        pass

    @abstractmethod
    async def get_public_key(self, key_id: UUID) -> bytes:
        """Obtiene la clave pública en formato DER (bytes) para un key_id.

        Público y sin autenticación por diseño en hsm-service (las claves
        públicas no son sensibles) — no requiere bearer_token.
        """
        pass

    @abstractmethod
    async def sign_hash(
        self, key_id: UUID, hash_bytes: bytes, bearer_token: str
    ) -> bytes:
        """Firma datos con la clave privada identificada por key_id.

        A pesar del nombre (heredado de la API de hsm-service), `hash_bytes`
        son los datos CRUDOS a firmar, no un digest pre-calculado: el hashing
        SHA-256 lo hace el HSM internamente (CKM_SHA256_RSA_PKCS en SoftHSM;
        ver internal/infrastructure/hsm/client_crypto.go). Pasar un digest ya
        calculado acá lo hashea dos veces y produce una firma inválida para
        cualquier verificador X.509 estándar (que hashea el TBS una sola vez).

        bearer_token: ver create_key.
        """
        pass
