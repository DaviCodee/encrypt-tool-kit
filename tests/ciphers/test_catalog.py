"""Testes do catálogo de cifras: resolução de nomes, aliases e indisponíveis."""

from __future__ import annotations

import pytest

from encrypttoolkit.ciphers.catalog import all_ciphers, get_cipher
from encrypttoolkit.core.errors import (
    MissingDependencyError,
    UnsupportedFormatError,
)


def test_aliases_resolve_to_canonical():
    assert get_cipher("AES").name == "aes-256-gcm"
    assert get_cipher("AES-256").name == "aes-256-gcm"
    assert get_cipher("aes_gcm").name == "aes-256-gcm"
    assert get_cipher("3DES").name == "3des-cbc"
    assert get_cipher("RC4").name == "rc4"
    assert get_cipher("RSA").name == "rsa-oaep"


def test_unknown_cipher_errors():
    with pytest.raises(UnsupportedFormatError):
        get_cipher("cifra-que-nao-existe")


def test_available_set_has_core_ciphers():
    available = {c.name for c in all_ciphers() if c.available}
    for name in (
        "aes-256-gcm", "aes-256-cbc", "aes-256-ctr", "aes-256-xts",
        "chacha20-poly1305", "chacha20", "rsa-oaep", "fernet", "aes-kw",
    ):
        assert name in available, name


def test_unsupported_items_listed_but_error():
    by_name = {c.name: c for c in all_ciphers()}
    for name in ("tls-1.3", "wireguard", "ml-kem-768", "veracrypt", "ecdh"):
        cipher = by_name[name]
        assert cipher.available is False
        with pytest.raises(UnsupportedFormatError):
            cipher.encrypt(b"k", b"data", nonce=None, aad=None)


def test_des_is_unavailable_but_3des_available():
    by_name = {c.name: c for c in all_ciphers()}
    assert by_name["des"].available is False
    assert by_name["3des-cbc"].available is True


def test_sodium_family_listed():
    # Com ou sem o extra nacl, os nomes existem no catálogo.
    by_name = {c.name: c for c in all_ciphers()}
    cipher = by_name["xchacha20-poly1305"]
    if not cipher.available:
        with pytest.raises(MissingDependencyError):
            cipher.generate_key()
