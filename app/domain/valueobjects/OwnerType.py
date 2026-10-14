from enum import Enum


class OwnerType(str, Enum):
    TENANT = "TENANT"
    ORGANIZATION = "ORGANIZATION"
    USER = "USER"
