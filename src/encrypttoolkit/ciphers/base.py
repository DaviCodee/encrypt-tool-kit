"""Modelo de uma cifra do catálogo.

Uma :class:`Cipher` casa metadados (família, tamanhos de chave, nonce, se é AEAD) com
um *backend* que sabe gerar chave, cifrar e decifrar. As operações genéricas
(``encrypt``/``decrypt``/``keygen``) consultam o catálogo por nome e delegam ao backend
— elas não conhecem algoritmos individuais.

Fronteira de dados (sempre bytes):

- ``encrypt(key, plaintext, *, nonce, aad) -> Encrypted`` devolve o texto cifrado e
  metadados (ex.: o nonce efetivamente usado).
- ``decrypt(key, ciphertext, *, nonce, aad) -> bytes`` devolve o texto claro.

Para AEAD o texto cifrado já embute a tag de autenticação. Para cifras de bloco em modo
CBC o backend aplica/retira o padding PKCS#7.

A *chave* chega ao backend como bytes já decodificados pela camada de operação
(``key_format`` indica como interpretar a string do usuário: ``hex``/``base64``/``pem``…).

Cifras indisponíveis (algoritmo não suportado, protocolo, container, serviço KMS,
dependência opcional ausente) ficam registradas com ``available=False`` e levantam
:class:`UnsupportedFormatError`/:class:`MissingDependencyError` ao serem usadas.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field

from encrypttoolkit.core.errors import (
    MissingDependencyError,
    UnsupportedFormatError,
)

# Famílias reconhecidas (documentação/UX; não restringe o catálogo).
FAMILIES = ("aead", "block", "stream", "keywrap", "asymmetric", "recipe")


@dataclass(slots=True)
class GeneratedKey:
    """Material de chave produzido por ``keygen``.

    Cifras simétricas devolvem uma única chave em ``key``. Cifras assimétricas devolvem
    o par em ``private``/``public`` (PEM). ``meta`` carrega rótulos legíveis.
    """

    key: bytes | None = None
    private: bytes | None = None
    public: bytes | None = None
    meta: dict[str, str] = field(default_factory=dict)


@dataclass(slots=True)
class Encrypted:
    """Resultado de uma cifragem: o texto cifrado e metadados (ex.: nonce usado)."""

    ciphertext: bytes
    meta: dict[str, str] = field(default_factory=dict)


class CipherBackend(ABC):
    """Implementação concreta de uma cifra."""

    family: str = "block"
    is_aead: bool = False
    needs_nonce: bool = False
    key_sizes: tuple[int, ...] = ()  # tamanhos de chave válidos, em bytes
    nonce_size: int | None = None  # tamanho do nonce/IV em bytes, se aplicável
    key_format: str = "hex"  # como interpretar a string de chave do usuário

    @abstractmethod
    def generate_key(self, size: int | None = None) -> GeneratedKey:
        """Gera material de chave novo para esta cifra."""

    @abstractmethod
    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        """Cifra ``plaintext`` e devolve o texto cifrado mais metadados."""

    @abstractmethod
    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        """Decifra ``ciphertext`` e devolve o texto claro."""


class _Unavailable(CipherBackend):
    """Backend de cifra listada mas indisponível: erra em qualquer uso."""

    def __init__(self, name: str, reason: str, *, missing_dep: bool) -> None:
        self._name = name
        self._reason = reason
        self._missing_dep = missing_dep

    def _raise(self) -> None:
        if self._missing_dep:
            raise MissingDependencyError(f"cifra {self._name!r} indisponível: {self._reason}")
        raise UnsupportedFormatError(f"cifra {self._name!r} não suportada: {self._reason}")

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        self._raise()
        raise AssertionError  # pragma: no cover

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        self._raise()
        raise AssertionError  # pragma: no cover

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        self._raise()
        raise AssertionError  # pragma: no cover


@dataclass(frozen=True, slots=True)
class Cipher:
    """Uma cifra do catálogo: metadados + backend."""

    name: str
    family: str
    summary: str
    backend: CipherBackend = field(repr=False)
    available: bool = True
    reason: str = ""

    @property
    def is_aead(self) -> bool:
        return self.backend.is_aead

    @property
    def needs_nonce(self) -> bool:
        return self.backend.needs_nonce

    @property
    def key_sizes(self) -> tuple[int, ...]:
        return self.backend.key_sizes

    @property
    def nonce_size(self) -> int | None:
        return self.backend.nonce_size

    @property
    def key_format(self) -> str:
        return self.backend.key_format

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        return self.backend.generate_key(size)

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        return self.backend.encrypt(key, plaintext, nonce=nonce, aad=aad)

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        return self.backend.decrypt(key, ciphertext, nonce=nonce, aad=aad)

    @classmethod
    def unsupported(
        cls, name: str, family: str, summary: str, reason: str, *, missing_dep: bool = False
    ) -> Cipher:
        """Cria uma cifra listada mas indisponível, que erra ao ser usada."""
        return cls(
            name=name,
            family=family,
            summary=summary,
            backend=_Unavailable(name, reason, missing_dep=missing_dep),
            available=False,
            reason=reason,
        )
