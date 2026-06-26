"""Cifragem assimétrica RSA sobre PyCA ``cryptography``.

A *chave* é fornecida em PEM: a chave **pública** para ``encrypt`` e a **privada** para
``decrypt`` (``key_format = "pem"``). ``keygen`` produz o par como dois artefatos PEM.

RSA cifra no máximo poucas dezenas/centenas de bytes (menos que o módulo) — na prática
serve para envelopar uma chave simétrica, não dados grandes.
"""

from __future__ import annotations

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.padding import AsymmetricPadding

from encrypttoolkit.ciphers.base import Cipher, CipherBackend, Encrypted, GeneratedKey
from encrypttoolkit.core.errors import InvalidInputError, OperationError


def _load_public(key: bytes) -> rsa.RSAPublicKey:
    try:
        loaded = serialization.load_pem_public_key(key)
    except ValueError as exc:
        raise InvalidInputError(f"chave pública PEM inválida: {exc}") from exc
    if not isinstance(loaded, rsa.RSAPublicKey):
        raise InvalidInputError("a chave fornecida não é uma chave pública RSA")
    return loaded


def _load_private(key: bytes) -> rsa.RSAPrivateKey:
    try:
        loaded = serialization.load_pem_private_key(key, password=None)
    except (ValueError, TypeError) as exc:
        raise InvalidInputError(f"chave privada PEM inválida: {exc}") from exc
    if not isinstance(loaded, rsa.RSAPrivateKey):
        raise InvalidInputError("a chave fornecida não é uma chave privada RSA")
    return loaded


class _RsaBackend(CipherBackend):
    family = "asymmetric"
    key_format = "pem"
    needs_nonce = False

    def __init__(self, *, oaep: bool) -> None:
        self._oaep = oaep

    def _padding(self) -> AsymmetricPadding:
        if self._oaep:
            return padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            )
        return padding.PKCS1v15()

    def generate_key(self, size: int | None = None) -> GeneratedKey:
        bits = size if size is not None else 2048
        if bits < 1024 or bits % 256 != 0:
            raise InvalidInputError("tamanho de chave RSA inválido (use 2048, 3072, 4096…)")
        private = rsa.generate_private_key(public_exponent=65537, key_size=bits)
        priv_pem = private.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_pem = private.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        return GeneratedKey(private=priv_pem, public=pub_pem, meta={"key_bits": str(bits)})

    def encrypt(
        self, key: bytes, plaintext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> Encrypted:
        public = _load_public(key)
        try:
            ciphertext = public.encrypt(plaintext, self._padding())
        except ValueError as exc:
            raise InvalidInputError(f"mensagem grande demais para a chave RSA: {exc}") from exc
        return Encrypted(ciphertext=ciphertext, meta={"key_bits": str(public.key_size)})

    def decrypt(
        self, key: bytes, ciphertext: bytes, *, nonce: bytes | None, aad: bytes | None
    ) -> bytes:
        private = _load_private(key)
        try:
            return private.decrypt(ciphertext, self._padding())
        except ValueError as exc:
            raise OperationError(
                "falha ao decifrar RSA (chave errada ou texto corrompido)"
            ) from exc


def build_asymmetric() -> list[Cipher]:
    """Constrói o catálogo de cifras assimétricas."""
    return [
        Cipher(
            name="rsa-oaep",
            family="asymmetric",
            summary="RSA-OAEP com SHA-256 (recomendado para envelopar chaves).",
            backend=_RsaBackend(oaep=True),
        ),
        Cipher(
            name="rsa-pkcs1v15",
            family="asymmetric",
            summary="RSAES-PKCS1-v1_5 (legado; preferir OAEP em projetos novos).",
            backend=_RsaBackend(oaep=False),
        ),
    ]
