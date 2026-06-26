"""Round-trip (encrypt -> decrypt) das cifras simétricas/AEAD disponíveis."""

from __future__ import annotations

import pytest

from encrypttoolkit.ciphers.base import Cipher
from encrypttoolkit.ciphers.catalog import all_ciphers, get_cipher

# Famílias cujo round-trip é exercitável com uma única chave simétrica.
_SYMMETRIC = {"aead", "block", "stream"}

_AVAILABLE = [
    c.name for c in all_ciphers() if c.available and c.family in _SYMMETRIC
]


def _roundtrip(cipher: Cipher, plaintext: bytes, aad: bytes | None = None) -> None:
    generated = cipher.generate_key()
    assert generated.key is not None
    enc = cipher.encrypt(generated.key, plaintext, nonce=None, aad=aad)
    nonce_hex = enc.meta.get("nonce") or enc.meta.get("iv") or enc.meta.get("tweak")
    nonce = bytes.fromhex(nonce_hex) if nonce_hex else None
    out = cipher.decrypt(generated.key, enc.ciphertext, nonce=nonce, aad=aad)
    assert out == plaintext


@pytest.mark.parametrize("name", _AVAILABLE)
def test_symmetric_roundtrip(name):
    cipher = get_cipher(name)
    # XTS exige blocos com tamanho mínimo (>=16 bytes); use um payload generoso.
    _roundtrip(cipher, b"mensagem secreta de teste, com tamanho suficiente!! 1234")


@pytest.mark.parametrize("name", [n for n in _AVAILABLE if get_cipher(n).is_aead])
def test_aead_with_aad_roundtrip(name):
    cipher = get_cipher(name)
    _roundtrip(cipher, b"payload autenticado", aad=b"cabecalho")


def test_aead_detects_tampering():
    cipher = get_cipher("aes-256-gcm")
    generated = cipher.generate_key()
    assert generated.key is not None
    enc = cipher.encrypt(generated.key, b"intacto", nonce=None, aad=None)
    nonce = bytes.fromhex(enc.meta["nonce"])
    tampered = bytes([enc.ciphertext[0] ^ 0x01]) + enc.ciphertext[1:]
    from encrypttoolkit.core.errors import OperationError

    with pytest.raises(OperationError):
        cipher.decrypt(generated.key, tampered, nonce=nonce, aad=None)


def test_wrong_key_size_rejected():
    from encrypttoolkit.core.errors import InvalidInputError

    cipher = get_cipher("aes-256-gcm")
    with pytest.raises(InvalidInputError):
        cipher.encrypt(b"chave-curta", b"x", nonce=None, aad=None)
