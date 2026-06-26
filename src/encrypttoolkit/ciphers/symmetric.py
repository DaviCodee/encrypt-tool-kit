"""Cifras simétricas clássicas sobre PyCA ``cryptography``.

Cobre cifras de bloco em modos CBC/CTR/CFB/OFB, AES-XTS e cifras de fluxo
(ChaCha20, RC4). Em CBC o backend aplica/retira padding PKCS#7; nos demais modos o
texto cifrado tem o mesmo tamanho do claro. O IV/nonce não é secreto, mas deve ser
único por mensagem; quando ausente, a operação gera um aleatório e o reporta.

Algoritmos legados (3DES, CAST5, Blowfish, IDEA, SEED, RC4) vivem no módulo
``decrepit`` da biblioteca; ficam disponíveis, porém marcados como legados no resumo.
"""

from __future__ import annotations

import os
from collections.abc import Callable
from typing import Any, cast

from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher as _CCipher
from cryptography.hazmat.primitives.ciphers import algorithms, modes

from encrypttoolkit.ciphers.base import Cipher, CipherBackend, Encrypted, GeneratedKey
from encrypttoolkit.core.errors import InvalidInputError

_AlgoFactory = Callable[..., Any]


def _resolve_algo(name: str) -> _AlgoFactory:
    """Resolve a classe de algoritmo, preferindo o módulo ``decrepit`` (sem warnings)."""
    cls = None
    try:
        from cryptography.hazmat.decrepit.ciphers import algorithms as legacy

        cls = getattr(legacy, name, None)
    except ImportError:  # pragma: no cover - versões antigas sem 'decrepit'
        pass
    if cls is None:
        cls = getattr(algorithms, name, None)
    if cls is None:  # pragma: no cover - depende da versão da lib
        raise InvalidInputError(f"algoritmo {name!r} indisponível nesta versão da cryptography")
    return cast(_AlgoFactory, cls)


def _resolve_mode(name: str) -> Any:
    """Resolve a classe de modo; CFB/OFB vêm do ``decrepit`` quando disponível."""
    if name in ("cfb", "ofb"):
        try:
            from cryptography.hazmat.decrepit.ciphers import modes as legacy

            cls = getattr(legacy, name.upper(), None)
            if cls is not None:
                return cls
        except ImportError:  # pragma: no cover - versões antigas sem 'decrepit'
            pass
    return getattr(modes, name.upper())


# nome do modo -> aplica padding PKCS#7 (só CBC).
_MODE_PADS = {"cbc": True, "ctr": False, "cfb": False, "ofb": False}


class _BlockBackend(CipherBackend):
    family = "block"

    def __init__(
        self,
        algo_name: str,
        mode_name: str,
        *,
        key_sizes: tuple[int, ...],
        block_size: int,
    ) -> None:
        self._algo = _resolve_algo(algo_name)
        self._mode_cls = _resolve_mode(mode_name)
        self._pad = _MODE_PADS[mode_name]
        self.key_sizes = key_sizes
        self.nonce_size = block_size
        self._block_bits = block_size * 8
        self.needs_nonce = True

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        n = size if size is not None else self.key_sizes[-1]
        if n not in self.key_sizes:
            raise InvalidInputError(
                f"tamanho de chave inválido: {n} bytes (válidos: {self.key_sizes})"
            )
        return GeneratedKey(key=os.urandom(n), meta={"key_bytes": str(n)})

    def _check(self, key: bytes, iv: bytes) -> None:
        if len(key) not in self.key_sizes:
            raise InvalidInputError(
                f"chave de {len(key)} bytes inválida (válidos: {self.key_sizes})"
            )
        if len(iv) != self.nonce_size:
            raise InvalidInputError(
                f"IV/nonce de {len(iv)} bytes inválido (esperado {self.nonce_size})"
            )

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        iv = nonce if nonce is not None else os.urandom(self.nonce_size or 16)
        self._check(key, iv)
        data = plaintext
        if self._pad:
            padder = padding.PKCS7(self._block_bits).padder()
            data = padder.update(plaintext) + padder.finalize()
        encryptor = _CCipher(self._algo(key), self._mode_cls(iv)).encryptor()
        ciphertext = encryptor.update(data) + encryptor.finalize()
        return Encrypted(ciphertext=ciphertext, meta={"iv": iv.hex()})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        if nonce is None:
            raise InvalidInputError("decrypt exige --nonce (o IV usado na cifragem)")
        self._check(key, nonce)
        decryptor = _CCipher(self._algo(key), self._mode_cls(nonce)).decryptor()
        data = decryptor.update(ciphertext) + decryptor.finalize()
        if self._pad:
            unpadder = padding.PKCS7(self._block_bits).unpadder()
            try:
                data = unpadder.update(data) + unpadder.finalize()
            except ValueError as exc:
                raise InvalidInputError("padding PKCS#7 inválido (chave/IV errados?)") from exc
        return data


class _XtsBackend(CipherBackend):
    family = "block"

    def __init__(self, key_sizes: tuple[int, ...]) -> None:
        self.key_sizes = key_sizes  # já é o dobro: 32 p/ AES-128, 64 p/ AES-256
        self.nonce_size = 16
        self.needs_nonce = True

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        n = size if size is not None else self.key_sizes[-1]
        if n not in self.key_sizes:
            raise InvalidInputError(
                f"tamanho de chave inválido: {n} bytes (válidos: {self.key_sizes})"
            )
        return GeneratedKey(key=os.urandom(n), meta={"key_bytes": str(n)})

    def _check(self, key: bytes, tweak: bytes) -> None:
        if len(key) not in self.key_sizes:
            raise InvalidInputError(
                f"chave de {len(key)} bytes inválida (válidos: {self.key_sizes})"
            )
        if len(tweak) != 16:
            raise InvalidInputError(f"tweak de {len(tweak)} bytes inválido (esperado 16)")

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        tweak = nonce if nonce is not None else os.urandom(16)
        self._check(key, tweak)
        encryptor = _CCipher(algorithms.AES(key), modes.XTS(tweak)).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        return Encrypted(ciphertext=ciphertext, meta={"tweak": tweak.hex()})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        if nonce is None:
            raise InvalidInputError("decrypt XTS exige --nonce (o tweak usado)")
        self._check(key, nonce)
        decryptor = _CCipher(algorithms.AES(key), modes.XTS(nonce)).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


class _StreamBackend(CipherBackend):
    family = "stream"

    def __init__(self, algo_name: str, *, key_sizes: tuple[int, ...], nonce_size: int) -> None:
        self._algo_name = algo_name
        self._algo = _resolve_algo(algo_name)
        self.key_sizes = key_sizes
        self.nonce_size = nonce_size if nonce_size else None
        self.needs_nonce = nonce_size > 0

    def _instance(self, key: bytes, nonce: bytes | None) -> Any:
        if self.needs_nonce:
            return self._algo(key, nonce)
        return self._algo(key)

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        n = size if size is not None else self.key_sizes[-1]
        if n not in self.key_sizes:
            raise InvalidInputError(
                f"tamanho de chave inválido: {n} bytes (válidos: {self.key_sizes})"
            )
        return GeneratedKey(key=os.urandom(n), meta={"key_bytes": str(n)})

    def _check(self, key: bytes, nonce: bytes | None) -> None:
        if len(key) not in self.key_sizes:
            raise InvalidInputError(
                f"chave de {len(key)} bytes inválida (válidos: {self.key_sizes})"
            )
        if self.needs_nonce and (nonce is None or len(nonce) != self.nonce_size):
            got = 0 if nonce is None else len(nonce)
            raise InvalidInputError(
                f"nonce de {got} bytes inválido (esperado {self.nonce_size})"
            )

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        used = nonce
        if self.needs_nonce and used is None:
            used = os.urandom(self.nonce_size or 16)
        self._check(key, used)
        encryptor = _CCipher(self._instance(key, used), mode=None).encryptor()
        ciphertext = encryptor.update(plaintext) + encryptor.finalize()
        meta = {"nonce": used.hex()} if used is not None else {}
        return Encrypted(ciphertext=ciphertext, meta=meta)

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        self._check(key, nonce)
        decryptor = _CCipher(self._instance(key, nonce), mode=None).decryptor()
        return decryptor.update(ciphertext) + decryptor.finalize()


# Configuração das cifras de bloco. Cada entrada gera uma cifra por (variante, modo),
# apenas com os modos que a versão instalada da cryptography suporta para o algoritmo.
#   canon, algo na lib, bloco (bytes), modos, variantes [(sufixo do nome, key_sizes)], rótulo
_BlockEntry = tuple[str, str, int, tuple[str, ...], list[tuple[str, tuple[int, ...]]], str]
_BLOCK_ALGOS: list[_BlockEntry] = [
    ("aes", "AES", 16, ("cbc", "ctr", "cfb", "ofb"),
     [("-128", (16,)), ("-192", (24,)), ("-256", (32,))], "AES"),
    ("camellia", "Camellia", 16, ("cbc", "cfb", "ofb"),
     [("-128", (16,)), ("-192", (24,)), ("-256", (32,))], "Camellia"),
    ("sm4", "SM4", 16, ("cbc", "ctr", "cfb", "ofb"), [("", (16,))], "SM4 (padrão chinês)"),
    ("aria", "ARIA", 16, ("cbc", "cfb", "ofb"),
     [("-128", (16,)), ("-192", (24,)), ("-256", (32,))], "ARIA"),
    ("seed", "SEED", 16, ("cbc", "cfb", "ofb"), [("", (16,))], "SEED (legado)"),
    ("3des", "TripleDES", 8, ("cbc", "cfb", "ofb"), [("", (16, 24))], "3DES (legado)"),
    ("cast5", "CAST5", 8, ("cbc", "cfb", "ofb"), [("", (16,))], "CAST5/CAST-128 (legado)"),
    ("blowfish", "Blowfish", 8, ("cbc", "cfb", "ofb"), [("", (16, 32))], "Blowfish (legado)"),
    ("idea", "IDEA", 8, ("cbc", "cfb", "ofb"), [("", (16,))], "IDEA (legado)"),
]


def build_symmetric() -> list[Cipher]:
    """Constrói o catálogo de cifras simétricas (bloco, stream, XTS).

    Algoritmos ausentes nesta versão da ``cryptography`` (ex.: ARIA conforme o build)
    entram como indisponíveis, com mensagem clara.
    """
    ciphers: list[Cipher] = []

    for canon, algo, block, block_modes, variants, label in _BLOCK_ALGOS:
        try:
            _resolve_algo(algo)
        except InvalidInputError as exc:
            for suffix, _sizes in variants:
                ciphers.append(
                    Cipher.unsupported(
                        f"{canon}{suffix}-cbc", "block", f"{label} em CBC.", str(exc)
                    )
                )
            continue
        for suffix, key_sizes in variants:
            for mode in block_modes:
                ciphers.append(
                    Cipher(
                        name=f"{canon}{suffix}-{mode}",
                        family="block",
                        summary=f"{label} em {mode.upper()} (bloco {block} bytes).",
                        backend=_BlockBackend(algo, mode, key_sizes=key_sizes, block_size=block),
                    )
                )

    # AES-XTS: chave dupla (cifra de disco).
    ciphers.append(
        Cipher(
            name="aes-128-xts",
            family="block",
            summary="AES-128 em XTS (cifra de setor; chave 256 bits = 2×128, tweak 16 bytes).",
            backend=_XtsBackend(key_sizes=(32,)),
        )
    )
    ciphers.append(
        Cipher(
            name="aes-256-xts",
            family="block",
            summary="AES-256 em XTS (cifra de setor; chave 512 bits = 2×256, tweak 16 bytes).",
            backend=_XtsBackend(key_sizes=(64,)),
        )
    )

    # Fluxo.
    ciphers.append(
        Cipher(
            name="chacha20",
            family="stream",
            summary="ChaCha20 puro (sem autenticação; chave 256 bits, nonce 16 bytes).",
            backend=_StreamBackend("ChaCha20", key_sizes=(32,), nonce_size=16),
        )
    )
    try:
        _resolve_algo("ARC4")
        ciphers.append(
            Cipher(
                name="rc4",
                family="stream",
                summary="RC4/ARC4 (legado e inseguro; chave 40–256 bits, sem nonce).",
                backend=_StreamBackend(
                    "ARC4", key_sizes=tuple(range(5, 33)), nonce_size=0
                ),
            )
        )
    except InvalidInputError as exc:  # pragma: no cover
        ciphers.append(Cipher.unsupported("rc4", "stream", "RC4/ARC4 (legado).", str(exc)))

    return ciphers
