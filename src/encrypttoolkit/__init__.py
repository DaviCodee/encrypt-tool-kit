"""encrypttoolkit — núcleo concentrador de operações de cifragem.

Expõe um registro de operações consumido pelos adaptadores (CLI, API e GUI futura).
As operações são genéricas (encrypt, decrypt, keygen, list-ciphers) e a cifra concreta
é escolhida por parâmetro, a partir de um catálogo de cifras.

O núcleo (``encrypttoolkit.core``) depende só de Pydantic; a pilha criptográfica
(``encrypttoolkit.ciphers``, sobre PyCA cryptography) só é importada quando usada.
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

__version__ = "0.1.0"

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
