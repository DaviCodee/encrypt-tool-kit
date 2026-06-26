"""Operações de inspeção: list-ciphers."""

from __future__ import annotations

from collections.abc import Sequence

from encrypttoolkit.ciphers.catalog import all_ciphers
from encrypttoolkit.core.io import DataInput, OperationResult
from encrypttoolkit.core.operation import CryptoOperation
from encrypttoolkit.core.params import OperationParams
from encrypttoolkit.core.registry import register


class ListCiphersParams(OperationParams):
    """Sem parâmetros: lista o catálogo de cifras."""


@register
class ListCiphersOperation(CryptoOperation[ListCiphersParams]):
    name = "list-ciphers"
    category = "inspecionar"
    summary = "Lista todas as cifras do catálogo, com família e disponibilidade."
    params_model = ListCiphersParams
    min_inputs = 0
    max_inputs = 0

    def run(self, inputs: Sequence[DataInput], params: ListCiphersParams) -> OperationResult:
        ciphers = [
            {
                "name": cipher.name,
                "family": cipher.family,
                "available": cipher.available,
                "aead": cipher.is_aead,
                "key_sizes": list(cipher.key_sizes),
                "nonce_size": cipher.nonce_size,
                "summary": cipher.summary,
                "reason": cipher.reason,
            }
            for cipher in all_ciphers()
        ]
        return OperationResult(meta={"count": len(ciphers), "ciphers": ciphers})
