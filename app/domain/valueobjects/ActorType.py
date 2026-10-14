from enum import Enum


class ActorType(str, Enum):
    USER = "USER"
    SERVICE = "SERVICE"
    SYSTEM = "SYSTEM"
    EXTERNAL = "EXTERNAL"
