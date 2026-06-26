"""Cifras "receita" de alto nível: Fernet.

Fernet embute versão, timestamp, IV e tag HMAC no próprio token — não há nonce externo.
A chave é a própria string base64 url-safe que ``Fernet`` consome direto, então o
``key_format`` é ``text`` (passa sem decodificar).
"""

from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

from encrypttoolkit.ciphers.base import Cipher, CipherBackend, Encrypted, GeneratedKey
from encrypttoolkit.core.errors import InvalidInputError, OperationError


class _FernetBackend(CipherBackend):
    family = "recipe"
    key_format = "text"
    needs_nonce = False
    key_sizes = (32,)

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        # Fernet.generate_key() devolve a chave já em base64 url-safe.
        token_key = Fernet.generate_key()
        return GeneratedKey(key=token_key, meta={"format": "base64-urlsafe", "key_bytes": "32"})

    def _fernet(self, key: bytes) -> Fernet:
        try:
            return Fernet(key)
        except (ValueError, TypeError) as exc:
            raise InvalidInputError(f"chave Fernet inválida: {exc}") from exc

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        token = self._fernet(key).encrypt(plaintext)
        return Encrypted(ciphertext=token, meta={"format": "fernet-token"})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        try:
            return self._fernet(key).decrypt(ciphertext)
        except InvalidToken as exc:
            raise OperationError("token Fernet inválido (chave errada ou adulterado)") from exc


def build_recipe() -> list[Cipher]:
    """Constrói o catálogo de cifras de alto nível."""
    return [
        Cipher(
            name="fernet",
            family="recipe",
            summary="Fernet (AES-128-CBC + HMAC-SHA256; token autocontido, chave base64).",
            backend=_FernetBackend(),
        )
    ]
