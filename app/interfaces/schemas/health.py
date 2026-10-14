from __future__ import annotations

from typing import Dict

from pydantic import BaseModel, Field


class HealthResponse(BaseModel):
    status: str = Field(
        ...,
        description="'healthy' si todo responde, 'degraded' si algo falla",
    )
    version: str
    dependencies: Dict[str, bool] = Field(
        ..., description="Estado de cada dependencia (database, redis)"
    )
