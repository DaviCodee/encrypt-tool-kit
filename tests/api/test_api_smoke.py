"""Smoke do adaptador de API (FastAPI)."""

from __future__ import annotations

import json

from fastapi.testclient import TestClient

from encrypttoolkit.api.app import app

client = TestClient(app)


def test_list_operations():
    resp = client.get("/operations")
    assert resp.status_code == 200
    names = {op["name"] for op in resp.json()}
    assert {"encrypt", "decrypt", "keygen", "list-ciphers"} <= names


def test_schema_endpoint():
    resp = client.get("/operations/encrypt/schema")
    assert resp.status_code == 200
    assert "cipher" in resp.json()["properties"]


def test_encrypt_decrypt_roundtrip():
    files = {"files": ("m.txt", b"segredo-http")}
    enc = client.post(
        "/operations/encrypt", files=files, data={"params": '{"cipher": "aes-256-gcm"}'}
    )
    assert enc.status_code == 200, enc.text
    meta = json.loads(enc.headers["X-Meta"])
    ciphertext = enc.content

    params = {
        "cipher": "aes-256-gcm",
        "key": meta["generated_key"],
        "nonce": meta["nonce"],
    }
    dec = client.post(
        "/operations/decrypt",
        files={"files": ("c.enc", ciphertext)},
        data={"params": json.dumps(params)},
    )
    assert dec.status_code == 200, dec.text
    assert dec.content == b"segredo-http"


def test_unknown_operation_404():
    resp = client.post("/operations/inexistente", data={"params": "{}"})
    assert resp.status_code == 404


def test_unsupported_cipher_422():
    # UnsupportedFormatError é subtipo de InvalidInputError -> 422 (entrada inválida).
    resp = client.post(
        "/operations/keygen", data={"params": '{"cipher": "ml-kem-768"}'}
    )
    assert resp.status_code == 422
