"""Smoke do adaptador de CLI (subcomandos por operação)."""

from __future__ import annotations

import json

from click.testing import CliRunner

from encrypttoolkit.cli.main import app

runner = CliRunner()


def test_list_shows_operations():
    result = runner.invoke(app, ["list"])
    assert result.exit_code == 0
    assert "encrypt" in result.output and "list-ciphers" in result.output


def test_schema_outputs_json():
    result = runner.invoke(app, ["schema", "encrypt"])
    assert result.exit_code == 0
    assert '"cipher"' in result.output


def test_list_ciphers_prints_table():
    result = runner.invoke(app, ["list-ciphers"])
    assert result.exit_code == 0
    assert "aes-256-gcm" in result.output
    assert "indisponível" in result.output


def test_encrypt_then_decrypt_roundtrip(tmp_path):
    enc = runner.invoke(
        app, ["encrypt", "--cipher", "aes-256-gcm", "--text", "segredo", "-o", str(tmp_path)]
    )
    assert enc.exit_code == 0, enc.output
    meta = json.loads(enc.output[enc.output.index("{") :])
    produced = list(tmp_path.glob("*.enc"))
    assert len(produced) == 1

    dec = runner.invoke(
        app,
        [
            "decrypt", "--cipher", "aes-256-gcm",
            "--key", meta["generated_key"], "--nonce", meta["nonce"],
            str(produced[0]), "-o", str(tmp_path / "out"),
        ],
    )
    assert dec.exit_code == 0, dec.output
    plain = next((tmp_path / "out").glob("*.dec"))
    assert plain.read_bytes() == b"segredo"


def test_keygen_outputs_key():
    result = runner.invoke(app, ["keygen", "--cipher", "aes-256-gcm"])
    assert result.exit_code == 0, result.output
    assert '"key"' in result.output


def test_unsupported_cipher_errors():
    result = runner.invoke(app, ["encrypt", "--cipher", "wireguard", "--text", "x"])
    assert result.exit_code != 0
    assert "não suportada" in result.output
