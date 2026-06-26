"""Codificação/decodificação de material de chave e nonce.

As chaves circulam como texto entre CLI/API e o catálogo. ``key_format`` define a
codificação: ``hex`` (simétricas), ``base64``/``base64url``, ``text`` (passa direto,
ex.: chave Fernet) e ``pem`` (chaves RSA). Nonce/IV são sempre hexadecimais.
"""

from __future__ import annotations

import base64
import binascii

from encrypttoolkit.core.errors import InvalidInputError

KEY_FORMATS = ("hex", "base64", "base64url", "text", "pem")


def decode_key(raw: str, fmt: str) -> bytes:
    """Converte a string de chave do usuário em bytes, conforme ``fmt``."""
    try:
        if fmt == "hex":
            return bytes.fromhex(raw.strip())
        if fmt == "base64":
            return base64.b64decode(raw.strip(), validate=True)
        if fmt == "base64url":
            return base64.urlsafe_b64decode(raw.strip())
        if fmt in ("text", "pem"):
            return raw.encode("utf-8")
    except (ValueError, binascii.Error) as exc:
        raise InvalidInputError(f"chave inválida para formato {fmt!r}: {exc}") from exc
    raise InvalidInputError(f"formato de chave desconhecido: {fmt!r} (use {KEY_FORMATS})")


def render_key(key: bytes, fmt: str) -> str:
    """Renderiza bytes de chave como texto, inverso de :func:`decode_key`."""
    if fmt == "hex":
        return key.hex()
    if fmt == "base64":
        return base64.b64encode(key).decode("ascii")
    if fmt == "base64url":
        return base64.urlsafe_b64encode(key).decode("ascii")
    if fmt in ("text", "pem"):
        return key.decode("utf-8")
    raise InvalidInputError(f"formato de chave desconhecido: {fmt!r} (use {KEY_FORMATS})")


def decode_nonce(raw: str | None) -> bytes | None:
    """Converte o nonce/IV hexadecimal em bytes (ou ``None`` se ausente)."""
    if raw is None:
        return None
    try:
        return bytes.fromhex(raw.strip())
    except ValueError as exc:
        raise InvalidInputError(f"nonce/IV deve ser hexadecimal: {exc}") from exc
