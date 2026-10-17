from dataclasses import dataclass
from uuid import UUID

from py_common.auth.owner_type import OwnerType


@dataclass(frozen=True)
class Owner:
    type: OwnerType
    id: UUID
