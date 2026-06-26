"""Modelo base de parâmetros das operações.

Cada operação declara um subtipo de :class:`OperationParams`. Esse único schema
Pydantic alimenta validação, flags da CLI, corpo da API e export de JSON Schema.
"""

from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class OperationParams(BaseModel):
    """Parâmetros de uma operação. Proíbe campos extras para falhar cedo."""

    model_config = ConfigDict(extra="forbid", frozen=True)
