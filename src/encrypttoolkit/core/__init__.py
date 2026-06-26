"""Núcleo do toolkit: contrato de operação, registro, params, io e erros.

Depende apenas da stdlib + Pydantic — sem arrastar a pilha criptográfica. As cifras
concretas vivem em ``encrypttoolkit.ciphers`` e só são importadas quando usadas.
"""

from encrypttoolkit.core.errors import (
    CryptoToolkitError,
    InvalidInputError,
    MissingDependencyError,
    OperationError,
    UnsupportedFormatError,
)
from encrypttoolkit.core.io import Artifact, DataInput, OperationResult
from encrypttoolkit.core.operation import CryptoOperation
from encrypttoolkit.core.registry import all_operations, get_operation, register

__all__ = [
    "Artifact",
    "CryptoOperation",
    "CryptoToolkitError",
    "DataInput",
    "InvalidInputError",
    "MissingDependencyError",
    "OperationError",
    "OperationResult",
    "UnsupportedFormatError",
    "all_operations",
    "get_operation",
    "register",
]
