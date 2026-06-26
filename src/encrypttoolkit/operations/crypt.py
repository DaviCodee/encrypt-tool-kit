"""Operações de cifragem: encrypt, decrypt."""

from __future__ import annotations

from collections.abc import Sequence

from pydantic import Field

from encrypttoolkit.ciphers.catalog import get_cipher
from encrypttoolkit.core.errors import InvalidInputError, UnsupportedFormatError
from encrypttoolkit.core.io import Artifact, DataInput, OperationResult
from encrypttoolkit.core.operation import CryptoOperation
from encrypttoolkit.core.params import OperationParams
from encrypttoolkit.core.registry import register
from encrypttoolkit.core.validation import safe_filename
from encrypttoolkit.operations.material import decode_key, decode_nonce, render_key


def _ensure_available(cipher_name: str) -> None:
    cipher = get_cipher(cipher_name)
    if not cipher.available:
        raise UnsupportedFormatError(f"cifra {cipher.name!r} não suportada: {cipher.reason}")


def _outname(name: str, cipher: str, ext: str) -> str:
    safe = safe_filename(name)
    stem = safe.rpartition(".")[0] or safe
    return f"{stem}-{cipher}.{ext}"


class EncryptParams(OperationParams):
    """Parâmetros da cifragem."""

    cipher: str = Field(min_length=1, description="cifra a aplicar (ex.: aes-256-gcm)")
    key: str | None = Field(
        default=None, description="chave; se omitida (simétrica), uma é gerada e reportada"
    )
    key_format: str | None = Field(
        default=None, description="formato da chave: hex|base64|base64url|text|pem"
    )
    nonce: str | None = Field(default=None, description="nonce/IV hexadecimal (gerado se omitido)")
    aad: str | None = Field(default=None, description="dado associado autenticado (texto UTF-8)")


@register
class EncryptOperation(CryptoOperation[EncryptParams]):
    name = "encrypt"
    category = "cifrar"
    summary = "Cifra a entrada com a cifra escolhida (texto claro -> texto cifrado)."
    params_model = EncryptParams

    def run(self, inputs: Sequence[DataInput], params: EncryptParams) -> OperationResult:
        item = inputs[0]
        _ensure_available(params.cipher)
        cipher = get_cipher(params.cipher)
        fmt = params.key_format or cipher.key_format
        meta: dict[str, str] = {"cipher": cipher.name}

        if params.key is not None:
            key_bytes = decode_key(params.key, fmt)
        elif cipher.family == "asymmetric":
            raise InvalidInputError(
                f"encrypt {cipher.name!r} exige --key (PEM da chave pública); gere com 'keygen'"
            )
        else:
            generated = cipher.generate_key()
            assert generated.key is not None
            key_bytes = generated.key
            meta["generated_key"] = render_key(key_bytes, fmt)
            meta["key_format"] = fmt

        nonce = decode_nonce(params.nonce)
        aad = params.aad.encode("utf-8") if params.aad is not None else None
        encrypted = cipher.encrypt(key_bytes, item.data, nonce=nonce, aad=aad)
        meta.update(encrypted.meta)

        artifact = Artifact(
            data=encrypted.ciphertext,
            filename=_outname(item.name, cipher.name, "enc"),
            media_type="application/octet-stream",
        )
        return OperationResult(artifacts=[artifact], meta=meta)


class DecryptParams(OperationParams):
    """Parâmetros da decifragem."""

    cipher: str = Field(min_length=1, description="cifra usada na cifragem (ex.: aes-256-gcm)")
    key: str = Field(min_length=1, description="chave (mesma da cifragem; PEM privado p/ RSA)")
    key_format: str | None = Field(
        default=None, description="formato da chave: hex|base64|base64url|text|pem"
    )
    nonce: str | None = Field(default=None, description="nonce/IV hexadecimal usado na cifragem")
    aad: str | None = Field(default=None, description="dado associado autenticado (texto UTF-8)")


@register
class DecryptOperation(CryptoOperation[DecryptParams]):
    name = "decrypt"
    category = "cifrar"
    summary = "Decifra a entrada com a cifra escolhida (texto cifrado -> texto claro)."
    params_model = DecryptParams

    def run(self, inputs: Sequence[DataInput], params: DecryptParams) -> OperationResult:
        item = inputs[0]
        _ensure_available(params.cipher)
        cipher = get_cipher(params.cipher)
        fmt = params.key_format or cipher.key_format
        key_bytes = decode_key(params.key, fmt)
        nonce = decode_nonce(params.nonce)
        aad = params.aad.encode("utf-8") if params.aad is not None else None
        plaintext = cipher.decrypt(key_bytes, item.data, nonce=nonce, aad=aad)
        artifact = Artifact(
            data=plaintext,
            filename=_outname(item.name, cipher.name, "dec"),
        )
        return OperationResult(artifacts=[artifact], meta={"cipher": cipher.name})
