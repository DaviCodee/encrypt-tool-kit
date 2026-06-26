"""Testes das cifras assimétricas (RSA) e de empacotamento/receita."""

from __future__ import annotations

import pytest

from encrypttoolkit.ciphers.catalog import get_cipher
from encrypttoolkit.core.errors import InvalidInputError, OperationError


@pytest.mark.parametrize("name", ["rsa-oaep", "rsa-pkcs1v15"])
def test_rsa_roundtrip(name):
    cipher = get_cipher(name)
    keys = cipher.generate_key(2048)
    assert keys.private is not None and keys.public is not None
    enc = cipher.encrypt(keys.public, b"chave-de-sessao", nonce=None, aad=None)
    out = cipher.decrypt(keys.private, enc.ciphertext, nonce=None, aad=None)
    assert out == b"chave-de-sessao"


def test_rsa_message_too_large():
    cipher = get_cipher("rsa-oaep")
    keys = cipher.generate_key(2048)
    assert keys.public is not None
    with pytest.raises(InvalidInputError):
        cipher.encrypt(keys.public, b"x" * 1000, nonce=None, aad=None)


def test_aes_kw_roundtrip():
    cipher = get_cipher("aes-kw")
    kek = cipher.generate_key()
    assert kek.key is not None
    target = b"0123456789abcdef0123456789abcdef"  # 32 bytes
    enc = cipher.encrypt(kek.key, target, nonce=None, aad=None)
    assert cipher.decrypt(kek.key, enc.ciphertext, nonce=None, aad=None) == target


def test_aes_kw_rejects_bad_length():
    cipher = get_cipher("aes-kw")
    kek = cipher.generate_key()
    assert kek.key is not None
    with pytest.raises(InvalidInputError):
        cipher.encrypt(kek.key, b"curto", nonce=None, aad=None)


def test_aes_kw_pad_any_length():
    cipher = get_cipher("aes-kw-pad")
    kek = cipher.generate_key()
    assert kek.key is not None
    enc = cipher.encrypt(kek.key, b"qualquer tamanho", nonce=None, aad=None)
    assert cipher.decrypt(kek.key, enc.ciphertext, nonce=None, aad=None) == b"qualquer tamanho"


def test_fernet_roundtrip():
    from encrypttoolkit.operations.material import decode_key

    cipher = get_cipher("fernet")
    gen = cipher.generate_key()
    assert gen.key is not None
    # A chave Fernet é o próprio texto base64; key_format "text" passa direto.
    key = decode_key(gen.key.decode(), cipher.key_format)
    enc = cipher.encrypt(key, b"segredo", nonce=None, aad=None)
    assert cipher.decrypt(key, enc.ciphertext, nonce=None, aad=None) == b"segredo"


def test_fernet_bad_token():
    cipher = get_cipher("fernet")
    gen = cipher.generate_key()
    assert gen.key is not None
    with pytest.raises(OperationError):
        cipher.decrypt(gen.key, b"token-invalido", nonce=None, aad=None)
