"""Operação de geração de chaves: keygen."""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import Field

from encrypttoolkit.ciphers.catalog import get_cipher
from encrypttoolkit.core.errors import InvalidInputError, UnsupportedFormatError
from encrypttoolkit.core.io import Artifact, DataInput, OperationResult
from encrypttoolkit.core.operation import CryptoOperation
from encrypttoolkit.core.params import OperationParams
from encrypttoolkit.core.registry import register
from encrypttoolkit.operations.material import render_key


class KeygenParams(OperationParams):
    """Parâmetros da geração de chave."""

    cipher: str = Field(min_length=1, description="cifra para a qual gerar a chave")
    size: int | None = Field(
        default=None,
        description="tamanho: bytes (simétrica) ou bits (RSA); usa o padrão se omitido",
    )
    key_format: str | None = Field(
        default=None, description="formato de saída da chave simétrica: hex|base64|base64url|text"
    )


@register
class KeygenOperation(CryptoOperation[KeygenParams]):
    name = "keygen"
    category = "chaves"
    summary = "Gera material de chave para uma cifra (chave simétrica ou par RSA)."
    params_model = KeygenParams
    min_inputs = 0
    max_inputs = 0

    def run(self, inputs: Sequence[DataInput], params: KeygenParams) -> OperationResult:
        cipher = get_cipher(params.cipher)
        if not cipher.available:
            raise UnsupportedFormatError(
                f"cifra {cipher.name!r} não suportada: {cipher.reason}"
            )
        generated = cipher.generate_key(params.size)

        if generated.private is not None and generated.public is not None:
            artifacts = [
                Artifact(generated.private, f"{cipher.name}-private.pem", "application/x-pem-file"),
                Artifact(generated.public, f"{cipher.name}-public.pem", "application/x-pem-file"),
            ]
            meta = {"cipher": cipher.name, **generated.meta}
            return OperationResult(artifacts=artifacts, meta=meta)

        if generated.key is None:  # pragma: no cover - backend mal-comportado
            raise InvalidInputError(f"keygen de {cipher.name!r} não produziu chave")

        fmt = params.key_format or cipher.key_format
        artifact = Artifact(generated.key, f"{cipher.name}.key", "application/octet-stream")
        meta = {"cipher": cipher.name, "key_format": fmt, "key": render_key(generated.key, fmt)}
        meta.update(generated.meta)
        return OperationResult(artifacts=[artifact], meta=meta)
