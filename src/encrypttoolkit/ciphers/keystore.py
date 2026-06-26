"""Proteção de chaves privadas em arquivo (keystore).

Implementa quatro formatos de armazenamento de chave privada protegida por senha:

- ``pkcs8-encrypted`` — PKCS#8 EncryptedPrivateKeyInfo em PEM (RFC 5958; padrão moderno).
- ``pem-encrypted-key`` — Chave PEM no formato TraditionalOpenSSL (legado; compatível com
  OpenSSL 1.x e muitos outros utilitários).
- ``pkcs12`` — PKCS#12 / PFX em DER binário (comum em Java, .NET e Windows).
- ``openssh-private-key`` — Chave privada OpenSSH cifrada com bcrypt + ChaCha20-Poly1305.

Modelo de dados neste toolkit:
  - A "chave" (parâmetro ``--key``) é a **senha de proteção** (``key_format = "text"``).
  - O "texto claro" de entrada (plaintext) é uma chave privada PEM **não cifrada**.
  - O "texto cifrado" de saída (ciphertext) é o arquivo de keystore protegido por senha.

Uso típico na CLI::

    ctk encrypt --cipher pkcs8-encrypted --key "s3nh4" --key-format text private.pem -o out/
    ctk decrypt --cipher pkcs8-encrypted --key "s3nh4" --key-format text \\
        out/private-pkcs8-encrypted.enc -o plain/
"""

from __future__ import annotations

import secrets
from typing import Any

from cryptography.hazmat.primitives.serialization import (
    BestAvailableEncryption,
    Encoding,
    NoEncryption,
    PrivateFormat,
    load_pem_private_key,
)

from encrypttoolkit.ciphers.base import Cipher, CipherBackend, Encrypted, GeneratedKey
from encrypttoolkit.core.errors import InvalidInputError, OperationError


def _random_passphrase() -> bytes:
    return secrets.token_urlsafe(24).encode("ascii")


def _load_pem_key(data: bytes) -> Any:
    try:
        return load_pem_private_key(data, password=None)
    except Exception as exc:
        raise InvalidInputError(
            f"chave privada PEM inválida ou já cifrada "
            f"(forneça uma chave PEM sem senha): {exc}"
        ) from exc


def _load_any_key(data: bytes) -> Any:
    """Carrega chave privada em PEM ou formato OpenSSH não cifrado."""
    try:
        return load_pem_private_key(data, password=None)
    except Exception:
        pass
    try:
        from cryptography.hazmat.primitives.serialization import load_ssh_private_key

        return load_ssh_private_key(data, password=None)
    except Exception as exc:
        raise InvalidInputError(
            f"chave privada inválida (forneça PEM sem senha ou chave OpenSSH não cifrada): {exc}"
        ) from exc


def _to_pkcs8_pem(key: Any) -> bytes:
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())  # type: ignore[no-any-return]


class _Pkcs8Backend(CipherBackend):
    """PKCS#8 EncryptedPrivateKeyInfo em PEM (RFC 5958)."""

    family = "keystore"
    key_format = "text"
    is_aead = False
    needs_nonce = False
    nonce_size: int | None = None
    key_sizes: tuple[int, ...] = ()

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        return GeneratedKey(key=_random_passphrase(), meta={"hint": "guarde esta senha"})

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        priv = _load_pem_key(plaintext)
        enc: bytes = priv.private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, BestAvailableEncryption(key)
        )
        return Encrypted(ciphertext=enc, meta={})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        try:
            priv = load_pem_private_key(ciphertext, password=key)
        except Exception as exc:
            raise OperationError(
                f"falha ao decifrar PKCS#8 (senha errada ou arquivo corrompido): {exc}"
            ) from exc
        return _to_pkcs8_pem(priv)


class _PemTraditionalBackend(CipherBackend):
    """PEM formato TraditionalOpenSSL (legado; compatível com OpenSSL 1.x)."""

    family = "keystore"
    key_format = "text"
    is_aead = False
    needs_nonce = False
    nonce_size: int | None = None
    key_sizes: tuple[int, ...] = ()

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        return GeneratedKey(key=_random_passphrase(), meta={"hint": "guarde esta senha"})

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        priv = _load_pem_key(plaintext)
        try:
            enc: bytes = priv.private_bytes(
                Encoding.PEM, PrivateFormat.TraditionalOpenSSL, BestAvailableEncryption(key)
            )
        except ValueError as exc:
            raise InvalidInputError(
                f"este tipo de chave não suporta o formato TraditionalOpenSSL "
                f"(use pkcs8-encrypted): {exc}"
            ) from exc
        return Encrypted(ciphertext=enc, meta={})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        try:
            priv = load_pem_private_key(ciphertext, password=key)
        except Exception as exc:
            raise OperationError(
                f"falha ao decifrar PEM tradicional (senha errada ou arquivo corrompido): {exc}"
            ) from exc
        return _to_pkcs8_pem(priv)


class _Pkcs12Backend(CipherBackend):
    """PKCS#12 / PFX em DER binário."""

    family = "keystore"
    key_format = "text"
    is_aead = False
    needs_nonce = False
    nonce_size: int | None = None
    key_sizes: tuple[int, ...] = ()

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        return GeneratedKey(key=_random_passphrase(), meta={"hint": "guarde esta senha"})

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        from cryptography.hazmat.primitives.serialization import pkcs12

        priv = _load_pem_key(plaintext)
        p12: bytes = pkcs12.serialize_key_and_certificates(
            name=b"key",
            key=priv,
            cert=None,
            cas=None,
            encryption_algorithm=BestAvailableEncryption(key),
        )
        return Encrypted(ciphertext=p12, meta={})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        from cryptography.hazmat.primitives.serialization import pkcs12

        try:
            priv, _, _ = pkcs12.load_key_and_certificates(ciphertext, password=key)
        except Exception as exc:
            raise OperationError(
                f"falha ao abrir PKCS#12 (senha errada ou arquivo inválido): {exc}"
            ) from exc
        if priv is None:
            raise OperationError("PKCS#12 não contém chave privada")
        return _to_pkcs8_pem(priv)


class _OpenSshBackend(CipherBackend):
    """Chave privada no formato OpenSSH cifrada com bcrypt."""

    family = "keystore"
    key_format = "text"
    is_aead = False
    needs_nonce = False
    nonce_size: int | None = None
    key_sizes: tuple[int, ...] = ()

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        return GeneratedKey(key=_random_passphrase(), meta={"hint": "guarde esta senha"})

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        priv = _load_any_key(plaintext)
        enc: bytes = priv.private_bytes(
            Encoding.PEM, PrivateFormat.OpenSSH, BestAvailableEncryption(key)
        )
        return Encrypted(ciphertext=enc, meta={})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        from cryptography.hazmat.primitives.serialization import load_ssh_private_key

        try:
            priv = load_ssh_private_key(ciphertext, password=key)
        except Exception as exc:
            raise OperationError(
                f"falha ao decifrar chave OpenSSH (senha errada?): {exc}"
            ) from exc
        return _to_pkcs8_pem(priv)


def build_keystore() -> list[Cipher]:
    """Constrói o catálogo de cifras de keystore (proteção de chave privada por senha)."""
    return [
        Cipher(
            name="pkcs8-encrypted",
            family="keystore",
            summary=(
                "PKCS#8 EncryptedPrivateKeyInfo em PEM (RFC 5958). "
                "Plaintext: chave privada PEM; senha via --key --key-format text."
            ),
            backend=_Pkcs8Backend(),
        ),
        Cipher(
            name="pem-encrypted-key",
            family="keystore",
            summary=(
                "PEM cifrado no formato TraditionalOpenSSL (legado; compatível com OpenSSL 1.x). "
                "Plaintext: chave privada PEM RSA/EC; senha via --key --key-format text."
            ),
            backend=_PemTraditionalBackend(),
        ),
        Cipher(
            name="pkcs12",
            family="keystore",
            summary=(
                "PKCS#12/PFX em DER binário. "
                "Plaintext: chave privada PEM; saída binária — use -o para gravar."
            ),
            backend=_Pkcs12Backend(),
        ),
        Cipher(
            name="openssh-private-key",
            family="keystore",
            summary=(
                "Chave privada OpenSSH cifrada com bcrypt+ChaCha20-Poly1305. "
                "Plaintext: chave privada PEM ou OpenSSH sem senha; --key-format text."
            ),
            backend=_OpenSshBackend(),
        ),
    ]
