"""Cifras autenticadas (AEAD) sobre PyCA ``cryptography``.

Em todas, o texto cifrado já embute a tag de autenticação. O nonce não é secreto, mas
**nunca deve repetir** com a mesma chave; quando o usuário não fornece um, a operação
gera um aleatório e o reporta nos metadados.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import cast

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import (
    AESCCM,
    AESGCM,
    AESGCMSIV,
    AESOCB3,
    AESSIV,
    ChaCha20Poly1305,
)

from encrypttoolkit.ciphers.base import Cipher, CipherBackend, Encrypted, GeneratedKey
from encrypttoolkit.core.errors import InvalidInputError, OperationError

# Construtor de uma instância AEAD a partir da chave (assinaturas variam só no detalhe).
_Factory = Callable[[bytes], object]


class _AeadBackend(CipherBackend):
    family = "aead"
    is_aead = True
    needs_nonce = True

    def __init__(
        self,
        factory: _Factory,
        *,
        key_sizes: tuple[int, ...],
        nonce_size: int,
        siv: bool = False,
    ) -> None:
        self._factory = factory
        self.key_sizes = key_sizes
        self.nonce_size = nonce_size
        # AES-SIV usa nonce como dado associado (lista), não como nonce posicional.
        self._siv = siv

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        n = size if size is not None else self.key_sizes[-1]
        if n not in self.key_sizes:
            raise InvalidInputError(
                f"tamanho de chave inválido: {n} bytes (válidos: {self.key_sizes})"
            )
        key = os.urandom(n)
        return GeneratedKey(key=key, meta={"key_bytes": str(n)})

    def _check_key(self, key: bytes) -> None:
        if len(key) not in self.key_sizes:
            raise InvalidInputError(
                f"chave de {len(key)} bytes inválida (válidos: {self.key_sizes})"
            )

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        self._check_key(key)
        aead = self._factory(key)
        if self._siv:
            associated = [aad] if aad is not None else []
            ciphertext = aead.encrypt(plaintext, associated)  # type: ignore[attr-defined]
            return Encrypted(ciphertext=ciphertext, meta={"mode": "siv"})
        used = nonce if nonce is not None else os.urandom(self.nonce_size or 12)
        if len(used) != self.nonce_size:
            raise InvalidInputError(
                f"nonce de {len(used)} bytes inválido (esperado {self.nonce_size})"
            )
        ciphertext = aead.encrypt(used, plaintext, aad)  # type: ignore[attr-defined]
        return Encrypted(ciphertext=ciphertext, meta={"nonce": used.hex()})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        self._check_key(key)
        aead = self._factory(key)
        try:
            if self._siv:
                associated = [aad] if aad is not None else []
                plaintext = aead.decrypt(ciphertext, associated)  # type: ignore[attr-defined]
            else:
                if nonce is None:
                    raise InvalidInputError("decrypt AEAD exige --nonce")
                plaintext = aead.decrypt(nonce, ciphertext, aad)  # type: ignore[attr-defined]
            return cast(bytes, plaintext)
        except InvalidTag as exc:
            raise OperationError("falha na autenticação: tag inválida (chave/nonce/aad?)") from exc


def build_aead() -> list[Cipher]:
    """Constrói o catálogo de cifras AEAD."""
    ciphers: list[Cipher] = []

    def add(name: str, summary: str, backend: CipherBackend) -> None:
        ciphers.append(Cipher(name=name, family="aead", summary=summary, backend=backend))

    for bits in (128, 192, 256):
        add(
            f"aes-{bits}-gcm",
            f"AES-{bits} em GCM (AEAD, nonce 12 bytes).",
            _AeadBackend(AESGCM, key_sizes=(bits // 8,), nonce_size=12),
        )
    for bits in (128, 192, 256):
        add(
            f"aes-{bits}-ccm",
            f"AES-{bits} em CCM (AEAD, nonce 12 bytes).",
            _AeadBackend(AESCCM, key_sizes=(bits // 8,), nonce_size=12),
        )
    for bits in (128, 256):
        add(
            f"aes-{bits}-gcm-siv",
            f"AES-{bits} em GCM-SIV (AEAD resistente a reuso de nonce).",
            _AeadBackend(AESGCMSIV, key_sizes=(bits // 8,), nonce_size=12),
        )
    for bits in (128, 192, 256):
        add(
            f"aes-{bits}-ocb3",
            f"AES-{bits} em OCB3 (AEAD, nonce 12 bytes).",
            _AeadBackend(AESOCB3, key_sizes=(bits // 8,), nonce_size=12),
        )
    add(
        "aes-256-siv",
        "AES-SIV (AEAD determinístico; chave 256/512 bits, nonce via aad).",
        _AeadBackend(AESSIV, key_sizes=(32, 64), nonce_size=0, siv=True),
    )
    add(
        "chacha20-poly1305",
        "ChaCha20-Poly1305 (AEAD, chave 256 bits, nonce 12 bytes).",
        _AeadBackend(ChaCha20Poly1305, key_sizes=(32,), nonce_size=12),
    )
    return ciphers
