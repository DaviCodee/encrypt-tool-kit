"""Cifras AEAD do libsodium via PyNaCl (extra opcional ``nacl``).

PyNaCl é pesado (libsodium nativo) e por isso fica fora do núcleo. Quando o extra não
está instalado, estas cifras aparecem em ``list-ciphers`` como indisponíveis, com erro
claro pedindo a instalação.

Cobre o ``SecretBox`` (XSalsa20-Poly1305, nonce 24 bytes) e o AEAD
XChaCha20-Poly1305-IETF, ambos com chave de 256 bits.
"""

from __future__ import annotations

from encrypttoolkit.ciphers.base import Cipher, CipherBackend, Encrypted, GeneratedKey
from encrypttoolkit.core.errors import InvalidInputError, OperationError

_EXTRA_HINT = "instale o extra: pip install 'encrypttoolkit[nacl]'"

_NACL_NAMES = [
    ("xsalsa20-poly1305", "XSalsa20-Poly1305 (libsodium SecretBox; chave 256 bits, nonce 24)."),
    ("xchacha20-poly1305", "XChaCha20-Poly1305-IETF (libsodium; chave 256 bits, nonce 24)."),
]


def _have_nacl() -> bool:
    try:
        import nacl  # noqa: F401
    except ImportError:
        return False
    return True


class _SecretBoxBackend(CipherBackend):
    family = "aead"
    is_aead = True
    needs_nonce = True
    key_sizes = (32,)
    nonce_size = 24

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        from nacl import utils

        key = utils.random(32)
        return GeneratedKey(key=bytes(key), meta={"key_bytes": "32"})

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        from nacl import utils
        from nacl.secret import SecretBox

        if len(key) != 32:
            raise InvalidInputError(f"chave de {len(key)} bytes inválida (esperado 32)")
        used = nonce if nonce is not None else bytes(utils.random(24))
        if len(used) != 24:
            raise InvalidInputError(f"nonce de {len(used)} bytes inválido (esperado 24)")
        encrypted = SecretBox(key).encrypt(plaintext, used)
        # encrypted.ciphertext exclui o nonce (que já reportamos no meta).
        return Encrypted(ciphertext=bytes(encrypted.ciphertext), meta={"nonce": used.hex()})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        from nacl.exceptions import CryptoError
        from nacl.secret import SecretBox

        if nonce is None:
            raise InvalidInputError("decrypt XSalsa20-Poly1305 exige --nonce")
        try:
            return bytes(SecretBox(key).decrypt(ciphertext, nonce))
        except CryptoError as exc:
            raise OperationError("falha na autenticação (chave/nonce errados?)") from exc


class _XChaChaBackend(CipherBackend):
    family = "aead"
    is_aead = True
    needs_nonce = True
    key_sizes = (32,)
    nonce_size = 24

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        from nacl import utils

        return GeneratedKey(key=bytes(utils.random(32)), meta={"key_bytes": "32"})

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        from nacl import bindings, utils

        if len(key) != 32:
            raise InvalidInputError(f"chave de {len(key)} bytes inválida (esperado 32)")
        used = nonce if nonce is not None else bytes(utils.random(24))
        if len(used) != 24:
            raise InvalidInputError(f"nonce de {len(used)} bytes inválido (esperado 24)")
        ciphertext = bindings.crypto_aead_xchacha20poly1305_ietf_encrypt(
            plaintext, aad, used, key
        )
        return Encrypted(ciphertext=bytes(ciphertext), meta={"nonce": used.hex()})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        from nacl import bindings
        from nacl.exceptions import CryptoError

        if nonce is None:
            raise InvalidInputError("decrypt XChaCha20-Poly1305 exige --nonce")
        try:
            return bytes(
                bindings.crypto_aead_xchacha20poly1305_ietf_decrypt(
                    ciphertext, aad, nonce, key
                )
            )
        except CryptoError as exc:
            raise OperationError("falha na autenticação (chave/nonce/aad errados?)") from exc


def build_sodium() -> list[Cipher]:
    """Constrói o catálogo libsodium; indisponível sem o extra ``nacl``."""
    if not _have_nacl():
        return [
            Cipher.unsupported(name, "aead", summary, _EXTRA_HINT, missing_dep=True)
            for name, summary in _NACL_NAMES
        ]
    return [
        Cipher(
            name="xsalsa20-poly1305",
            family="aead",
            summary=_NACL_NAMES[0][1],
            backend=_SecretBoxBackend(),
        ),
        Cipher(
            name="xchacha20-poly1305",
            family="aead",
            summary=_NACL_NAMES[1][1],
            backend=_XChaChaBackend(),
        ),
    ]
