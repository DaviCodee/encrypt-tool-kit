"""Operações do toolkit.

Importar este pacote registra todas as operações no registro central (efeito colateral
dos decoradores ``@register`` em cada módulo).
"""

from encrypttoolkit.operations import (  # noqa: F401
    crypt,
    inspect,
    keys,
)
