"""Equivalente a hsm-service's output.JWTValidator + CustomClaims
(internal/domain/ports/output/jwt_validator.go). CustomClaims vive acá (no
en el adapter) porque es la forma que CUALQUIER implementación de este
puerto debe devolver, igual que en la referencia Go."""

from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class CustomClaims:
    token_id: Optional[str]
    tenant_id: str
    owner_type: str
    owner_id: str
    organization_id: Optional[str]
    parent_key_id: Optional[str]
    user_id: str
    cert_level: int
    max_cert_level: int
    can_certify: bool
    certification_path: str
    permissions: Dict[str, Any]


class JWTValidator(ABC):
    """Port for JWT token validation. Implementations validate tokens
    against configured issuer/audience and extract application-specific
    claims."""

    @abstractmethod
    def validate_token(self, token_string: str) -> CustomClaims:
        """Validates a JWT token string and returns its claims. Raises if
        the token is invalid, expired, or claims validation fails."""
        raise NotImplementedError
