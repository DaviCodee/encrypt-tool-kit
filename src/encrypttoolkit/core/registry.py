"""Registro central de operações.

As operações se auto-registram via :func:`register`. Os adaptadores percorrem o
registro para expor todas as operações de forma uniforme.
"""

from __future__ import annotations

import importlib
from typing import Any

from encrypttoolkit.core.errors import CryptoToolkitError
from encrypttoolkit.core.operation import CryptoOperation

_REGISTRY: dict[str, CryptoOperation[Any]] = {}
_loaded = False


def register(operation_cls: type[CryptoOperation[Any]]) -> type[CryptoOperation[Any]]:
    """Decorator de classe que instancia e registra uma operação pelo seu ``name``."""
    instance = operation_cls()
    name = instance.name
    if name in _REGISTRY:
        raise CryptoToolkitError(f"operação duplicada no registro: {name!r}")
    _REGISTRY[name] = instance
    return operation_cls


def _ensure_loaded() -> None:
    global _loaded
    if not _loaded:
        _loaded = True
        importlib.import_module("encrypttoolkit.operations")


def get_operation(name: str) -> CryptoOperation[Any]:
    """Retorna a operação registrada com ``name`` ou levanta :class:`CryptoToolkitError`."""
    _ensure_loaded()
    try:
        return _REGISTRY[name]
    except KeyError:
        raise CryptoToolkitError(f"operação desconhecida: {name!r}") from None


def all_operations() -> list[CryptoOperation[Any]]:
    """Retorna todas as operações registradas, ordenadas por nome."""
    _ensure_loaded()
    return [_REGISTRY[name] for name in sorted(_REGISTRY)]
