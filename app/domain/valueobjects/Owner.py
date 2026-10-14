from dataclasses import dataclass
from uuid import UUID

from .OwnerType import OwnerType


@dataclass(frozen=True)
class Owner:
    type: OwnerType
    id: UUID
