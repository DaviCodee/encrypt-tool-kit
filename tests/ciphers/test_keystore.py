"""Testes de roundtrip para os backends de keystore (proteção de chave por senha)."""

from __future__ import annotations

import pytest
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    NoEncryption,
    PrivateFormat,
)

from encrypttoolkit.ciphers.catalog import get_cipher


def _rsa_pem() -> bytes:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


def _ec_pem() -> bytes:
    key = ec.generate_private_key(ec.SECP256R1())
    return key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())


PASSWORD = b"s3nh4-de-teste!"


@pytest.mark.parametrize("cipher_name", ["pkcs8-encrypted", "pem-encrypted-key", "pkcs12"])
def test_keystore_rsa_roundtrip(cipher_name: str) -> None:
    pem = _rsa_pem()
    cipher = get_cipher(cipher_name)
    assert cipher.available, f"{cipher_name} deveria estar disponível"

    encrypted = cipher.encrypt(PASSWORD, pem, nonce=None, aad=None)
    assert encrypted.ciphertext != pem

    recovered = cipher.decrypt(PASSWORD, encrypted.ciphertext, nonce=None, aad=None)
    assert b"PRIVATE KEY" in recovered


@pytest.mark.parametrize("cipher_name", ["pkcs8-encrypted", "pkcs12", "openssh-private-key"])
def test_keystore_ec_roundtrip(cipher_name: str) -> None:
    pem = _ec_pem()
    cipher = get_cipher(cipher_name)

    encrypted = cipher.encrypt(PASSWORD, pem, nonce=None, aad=None)
    recovered = cipher.decrypt(PASSWORD, encrypted.ciphertext, nonce=None, aad=None)
    assert b"PRIVATE KEY" in recovered


def test_openssh_roundtrip_rsa() -> None:
    pem = _rsa_pem()
    cipher = get_cipher("openssh-private-key")

    encrypted = cipher.encrypt(PASSWORD, pem, nonce=None, aad=None)
    assert b"OPENSSH PRIVATE KEY" in encrypted.ciphertext

    recovered = cipher.decrypt(PASSWORD, encrypted.ciphertext, nonce=None, aad=None)
    assert b"PRIVATE KEY" in recovered


def test_wrong_password_raises() -> None:
    pem = _rsa_pem()
    cipher = get_cipher("pkcs8-encrypted")
    encrypted = cipher.encrypt(PASSWORD, pem, nonce=None, aad=None)

    from encrypttoolkit.core.errors import OperationError

    with pytest.raises(OperationError):
        cipher.decrypt(b"senha-errada", encrypted.ciphertext, nonce=None, aad=None)


def test_generate_key_returns_passphrase() -> None:
    cipher = get_cipher("pkcs8-encrypted")
    gen = cipher.generate_key()
    assert gen.key is not None
    assert len(gen.key) > 0
    # deve ser texto ASCII válido
    gen.key.decode("ascii")


def test_pem_traditional_ec_unsupported_type() -> None:
    """Ed25519 não tem encoding TraditionalOpenSSL; deve levantar InvalidInputError."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    from encrypttoolkit.core.errors import InvalidInputError

    ed_key = Ed25519PrivateKey.generate()
    pem = ed_key.private_bytes(Encoding.PEM, PrivateFormat.PKCS8, NoEncryption())
    cipher = get_cipher("pem-encrypted-key")

    with pytest.raises(InvalidInputError):
        cipher.encrypt(PASSWORD, pem, nonce=None, aad=None)
