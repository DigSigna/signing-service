from enum import Enum


class TenantMode(str, Enum):
    """DLT-018: MANAGED -> CA bajo DigSigna Root (slot 0, compartido).
    INDEPENDENT -> Root CA propia (slot dedicado). Coincide con
    tenants.mode en el esquema compartido (migrations/001_base_tables.up.sql)."""

    MANAGED = "MANAGED"
    INDEPENDENT = "INDEPENDENT"
