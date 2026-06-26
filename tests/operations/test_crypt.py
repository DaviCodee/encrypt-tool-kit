"""Testes das operações encrypt/decrypt/keygen ponta a ponta."""

from __future__ import annotations

import pytest

from encrypttoolkit.core.errors import InvalidInputError, UnsupportedFormatError


def test_encrypt_autogenerates_key_and_decrypts(run_op, mensagem):
    enc = run_op("encrypt", [mensagem], cipher="aes-256-gcm")
    key = enc.meta["generated_key"]
    nonce = enc.meta["nonce"]
    ciphertext = enc.single.data

    dec = run_op("decrypt", [ciphertext], cipher="aes-256-gcm", key=key, nonce=nonce)
    assert dec.single.data == mensagem


def test_encrypt_with_explicit_key_cbc(run_op):
    keygen = run_op("keygen", [], cipher="aes-256-cbc")
    key = keygen.meta["key"]
    enc = run_op("encrypt", [b"bloco de dados"], cipher="aes-256-cbc", key=key)
    dec = run_op(
        "decrypt", [enc.single.data], cipher="aes-256-cbc", key=key, nonce=enc.meta["iv"]
    )
    assert dec.single.data == b"bloco de dados"


def test_encrypt_asymmetric_requires_key(run_op):
    with pytest.raises(InvalidInputError):
        run_op("encrypt", [b"x"], cipher="rsa-oaep")


def test_rsa_keygen_then_roundtrip(run_op):
    keys = run_op("keygen", [], cipher="rsa-oaep", size=2048)
    private = next(a.data for a in keys.artifacts if a.filename.endswith("private.pem"))
    public = next(a.data for a in keys.artifacts if a.filename.endswith("public.pem"))

    enc = run_op("encrypt", [b"chave"], cipher="rsa-oaep", key=public.decode(), key_format="pem")
    dec = run_op(
        "decrypt", [enc.single.data], cipher="rsa-oaep", key=private.decode(), key_format="pem"
    )
    assert dec.single.data == b"chave"


def test_encrypt_unavailable_cipher_errors(run_op):
    with pytest.raises(UnsupportedFormatError):
        run_op("encrypt", [b"x"], cipher="wireguard")


def test_keygen_unavailable_cipher_errors(run_op):
    with pytest.raises(UnsupportedFormatError):
        run_op("keygen", [], cipher="ml-kem-768")


def test_list_ciphers_counts(run_op):
    result = run_op("list-ciphers", [])
    assert result.meta["count"] > 50
    names = {c["name"] for c in result.meta["ciphers"]}
    assert "aes-256-gcm" in names and "tls-1.3" in names
