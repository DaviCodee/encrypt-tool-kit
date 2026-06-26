"""Empacotamento de chaves AES (AES-KW, RFC 3394/5649).

Diferente das demais, o "texto claro" aqui é **outra chave** a ser protegida pela chave
de empacotamento (KEK). Sem padding (``aes-kw``) o material precisa ser múltiplo de 8
bytes e ter ao menos 16; com padding (``aes-kw-pad``) qualquer tamanho serve.
"""

from __future__ import annotations

import os

from cryptography.hazmat.primitives.keywrap import (
    InvalidUnwrap,
    aes_key_unwrap,
    aes_key_unwrap_with_padding,
    aes_key_wrap,
    aes_key_wrap_with_padding,
)

from encrypttoolkit.ciphers.base import Cipher, CipherBackend, Encrypted, GeneratedKey
from encrypttoolkit.core.errors import InvalidInputError, OperationError


class _KeyWrapBackend(CipherBackend):
    family = "keywrap"
    needs_nonce = False
    key_sizes = (16, 24, 32)
    nonce_size = None

    def __init__(self, *, padded: bool) -> None:
        self._padded = padded

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        n = size if size is not None else 32
        if n not in self.key_sizes:
            raise InvalidInputError(
                f"tamanho de KEK inválido: {n} bytes (válidos: {self.key_sizes})"
            )
        return GeneratedKey(key=os.urandom(n), meta={"key_bytes": str(n)})

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        if len(key) not in self.key_sizes:
            raise InvalidInputError(
                f"KEK de {len(key)} bytes inválida (válidos: {self.key_sizes})"
            )
        if self._padded:
            wrapped = aes_key_wrap_with_padding(key, plaintext)
        else:
            if len(plaintext) < 16 or len(plaintext) % 8 != 0:
                raise InvalidInputError(
                    "aes-kw exige material múltiplo de 8 bytes e ≥16 (use aes-kw-pad)"
                )
            wrapped = aes_key_wrap(key, plaintext)
        return Encrypted(ciphertext=wrapped, meta={"wrapped_bytes": str(len(wrapped))})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        if len(key) not in self.key_sizes:
            raise InvalidInputError(
                f"KEK de {len(key)} bytes inválida (válidos: {self.key_sizes})"
            )
        try:
            if self._padded:
                return aes_key_unwrap_with_padding(key, ciphertext)
            return aes_key_unwrap(key, ciphertext)
        except InvalidUnwrap as exc:
            raise OperationError(
                "falha ao desempacotar: integridade inválida (KEK errada?)"
            ) from exc


def build_keywrap() -> list[Cipher]:
    """Constrói o catálogo de empacotamento de chaves."""
    return [
        Cipher(
            name="aes-kw",
            family="keywrap",
            summary="AES Key Wrap sem padding (RFC 3394).",
            backend=_KeyWrapBackend(padded=False),
        ),
        Cipher(
            name="aes-kw-pad",
            family="keywrap",
            summary="AES Key Wrap com padding (RFC 5649; aceita qualquer tamanho).",
            backend=_KeyWrapBackend(padded=True),
        ),
    ]
