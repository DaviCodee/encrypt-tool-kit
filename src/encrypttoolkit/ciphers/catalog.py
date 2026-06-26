"""Catálogo de cifras: monta o registro e resolve nomes/aliases.

Há dois registros no toolkit: o de operações (``core/registry.py``) e este, o de
*cifras*. As operações genéricas (encrypt/decrypt/keygen/list-ciphers) consultam
``get_cipher`` por nome.

Os algoritmos efetivamente suportados são construídos pelos módulos ``aead``,
``symmetric``, ``keywrap``, ``asymmetric``, ``recipe`` e ``sodium``. Os demais itens da
lista de referência (protocolos, formatos de mensagem, containers, serviços KMS,
algoritmos pós-quânticos e cifras não implementadas na PyCA cryptography) ficam
**listados mas indisponíveis**, com motivo claro.
"""

from __future__ import annotations

import re
from functools import cache

from encrypttoolkit.ciphers.aead import build_aead
from encrypttoolkit.ciphers.asymmetric import build_asymmetric
from encrypttoolkit.ciphers.base import Cipher
from encrypttoolkit.ciphers.keywrap import build_keywrap
from encrypttoolkit.ciphers.recipe import build_recipe
from encrypttoolkit.ciphers.sodium import build_sodium
from encrypttoolkit.ciphers.symmetric import build_symmetric
from encrypttoolkit.core.errors import UnsupportedFormatError

# Motivos recorrentes de indisponibilidade.
_R_NOT_IN_LIB = "algoritmo não implementado na PyCA cryptography"
_R_EXCHANGE = "acordo de chaves, não cifragem de dados (fora do escopo encrypt/decrypt)"
_R_FORMAT = "formato de mensagem/envelope não implementado neste toolkit"
_R_PROTOCOL = "protocolo de transporte, não uma cifra de blob isolada"
_R_CONTAINER = "container/volume cifrado; requer ferramenta dedicada"
_R_KMS = "serviço de gerenciamento de chaves remoto; requer SDK/credenciais"
_R_LIBRARY = "é uma biblioteca/framework, não um algoritmo específico"
_R_PQC = "KEM pós-quântico ainda não suportado pela pilha"
_R_KEYSTORE = "proteção de chave em arquivo; ainda não implementado"
_R_SODIUM_BOX = "requer par de chaves (cifragem de chave pública); fora do modelo de chave única"

# (nome canônico, família, resumo, motivo)
_UNAVAILABLE: list[tuple[str, str, str, str]] = [
    ("des", "block", "DES (56 bits, obsoleto).", "obsoleto e sem suporte; use 3des-cbc"),
    ("twofish", "block", "Twofish.", _R_NOT_IN_LIB),
    ("serpent", "block", "Serpent.", _R_NOT_IN_LIB),
    ("rc5", "block", "RC5.", _R_NOT_IN_LIB),
    ("rc6", "block", "RC6.", _R_NOT_IN_LIB),
    ("salsa20", "stream", "Salsa20 (fluxo puro).", _R_NOT_IN_LIB),
    ("xsalsa20", "stream", "XSalsa20 (fluxo puro).", _R_NOT_IN_LIB),
    ("xchacha20", "stream", "XChaCha20 (fluxo puro).", _R_NOT_IN_LIB),
    ("elgamal", "asymmetric", "ElGamal.", _R_NOT_IN_LIB),
    ("ecies", "asymmetric", "ECIES (cifragem híbrida com ECC).", _R_FORMAT),
    ("hpke", "asymmetric", "HPKE (RFC 9180).", _R_FORMAT),
    ("diffie-hellman", "exchange", "Diffie-Hellman.", _R_EXCHANGE),
    ("ecdh", "exchange", "ECDH.", _R_EXCHANGE),
    ("ecdhe", "exchange", "ECDHE (efêmero).", _R_EXCHANGE),
    ("ffdhe", "exchange", "FFDHE (DH em corpo finito).", _R_EXCHANGE),
    ("ecc", "exchange", "ECC (curvas elípticas, genérico).", _R_EXCHANGE),
    ("x25519", "exchange", "X25519 (Curve25519).", _R_EXCHANGE),
    ("x448", "exchange", "X448 (Curve448).", _R_EXCHANGE),
    ("secp256r1", "exchange", "ECDH em secp256r1 (P-256).", _R_EXCHANGE),
    ("secp384r1", "exchange", "ECDH em secp384r1 (P-384).", _R_EXCHANGE),
    ("secp521r1", "exchange", "ECDH em secp521r1 (P-521).", _R_EXCHANGE),
    ("nacl-box", "asymmetric", "NaCl box (Curve25519+XSalsa20-Poly1305).", _R_SODIUM_BOX),
    ("libsodium-sealed-box", "asymmetric", "libsodium sealed box.", _R_SODIUM_BOX),
    ("openpgp", "format", "OpenPGP (RFC 4880).", _R_FORMAT),
    ("pgp", "format", "PGP (mensagem).", _R_FORMAT),
    ("gnupg", "format", "GnuPG (ferramenta gpg).", _R_FORMAT),
    ("smime", "format", "S/MIME.", _R_FORMAT),
    ("cms-envelopeddata", "format", "CMS EnvelopedData (RFC 5652).", _R_FORMAT),
    ("openssl-cms", "format", "OpenSSL CMS.", _R_FORMAT),
    ("pkcs7", "format", "PKCS#7.", _R_FORMAT),
    ("jwe", "format", "JWE (RFC 7516).", _R_FORMAT),
    ("jwe-compact", "format", "JWE Compact Serialization.", _R_FORMAT),
    ("cose-encrypt", "format", "COSE_Encrypt (RFC 9052).", _R_FORMAT),
    ("age", "format", "age (formato/ferramenta).", _R_FORMAT),
    ("openssl-enc", "format", "OpenSSL enc (formato da CLI).", _R_FORMAT),
    ("tls-1.2", "protocol", "TLS 1.2.", _R_PROTOCOL),
    ("tls-1.3", "protocol", "TLS 1.3.", _R_PROTOCOL),
    ("dtls", "protocol", "DTLS.", _R_PROTOCOL),
    ("ipsec", "protocol", "IPsec.", _R_PROTOCOL),
    ("wireguard", "protocol", "WireGuard.", _R_PROTOCOL),
    ("openvpn", "protocol", "OpenVPN.", _R_PROTOCOL),
    ("ssh-transport", "protocol", "SSH transport encryption.", _R_PROTOCOL),
    ("openssh-private-key", "keystore", "OpenSSH private key encryption.", _R_KEYSTORE),
    ("pkcs8-encrypted", "keystore", "PKCS#8 EncryptedPrivateKeyInfo.", _R_KEYSTORE),
    ("pkcs12", "keystore", "PKCS#12 / PFX.", _R_KEYSTORE),
    ("pem-encrypted-key", "keystore", "PEM encrypted private key.", _R_KEYSTORE),
    ("tink", "library", "Google Tink.", _R_LIBRARY),
    ("libsodium", "library", "libsodium.", _R_LIBRARY),
    ("pyca-cryptography", "library", "PyCA cryptography.", _R_LIBRARY),
    ("web-crypto-api", "library", "Web Crypto API.", _R_LIBRARY),
    ("java-jca-jce", "library", "Java JCA/JCE.", _R_LIBRARY),
    ("nodejs-crypto", "library", "Node.js crypto.", _R_LIBRARY),
    ("aws-kms", "kms", "AWS KMS.", _R_KMS),
    ("azure-key-vault", "kms", "Azure Key Vault.", _R_KMS),
    ("gcp-kms", "kms", "Google Cloud KMS.", _R_KMS),
    ("vault-transit", "kms", "HashiCorp Vault Transit.", _R_KMS),
    ("veracrypt", "container", "VeraCrypt.", _R_CONTAINER),
    ("cryptomator", "container", "Cryptomator.", _R_CONTAINER),
    ("luks", "container", "LUKS.", _R_CONTAINER),
    ("dm-crypt", "container", "dm-crypt.", _R_CONTAINER),
    ("bitlocker", "container", "BitLocker.", _R_CONTAINER),
    ("filevault", "container", "FileVault.", _R_CONTAINER),
    ("zip-aes", "container", "ZIP AES.", _R_CONTAINER),
    ("7z-aes-256", "container", "7z AES-256.", _R_CONTAINER),
    ("pdf-encryption", "container", "PDF encryption.", _R_CONTAINER),
    ("rar5-encryption", "container", "RAR5 encryption.", _R_CONTAINER),
    ("ml-kem", "pqc", "ML-KEM (Kyber).", _R_PQC),
    ("ml-kem-512", "pqc", "ML-KEM-512.", _R_PQC),
    ("ml-kem-768", "pqc", "ML-KEM-768.", _R_PQC),
    ("ml-kem-1024", "pqc", "ML-KEM-1024.", _R_PQC),
]

# Aliases explícitos: forma alternativa -> nome canônico.
_ALIASES: dict[str, str] = {
    "aes": "aes-256-gcm",
    "aes-128": "aes-128-gcm",
    "aes-192": "aes-192-gcm",
    "aes-256": "aes-256-gcm",
    "aes-gcm": "aes-256-gcm",
    "aes-ccm": "aes-256-ccm",
    "aes-cbc": "aes-256-cbc",
    "aes-ctr": "aes-256-ctr",
    "aes-xts": "aes-256-xts",
    "aes-gcm-siv": "aes-256-gcm-siv",
    "aes-siv": "aes-256-siv",
    "aes-ocb3": "aes-256-ocb3",
    "aes-key-wrap": "aes-kw",
    "aeskw": "aes-kw",
    "camellia": "camellia-256-cbc",
    "sm4": "sm4-cbc",
    "seed": "seed-cbc",
    "aria": "aria-256-cbc",
    "3des": "3des-cbc",
    "triple-des": "3des-cbc",
    "tripledes": "3des-cbc",
    "cast5": "cast5-cbc",
    "cast-128": "cast5-cbc",
    "blowfish": "blowfish-cbc",
    "idea": "idea-cbc",
    "arc4": "rc4",
    "chacha20-ietf-poly1305": "chacha20-poly1305",
    "rsa": "rsa-oaep",
    "rsaes-oaep": "rsa-oaep",
    "rsaes-pkcs1-v1_5": "rsa-pkcs1v15",
    "rsa-pkcs1": "rsa-pkcs1v15",
    "rsa-pkcs1-v1_5": "rsa-pkcs1v15",
}


def _norm(name: str) -> str:
    """Normaliza um nome para busca: minúsculas, separadores -> '-'."""
    return re.sub(r"[\s_/]+", "-", name.strip().lower())


@cache
def _registry() -> dict[str, Cipher]:
    ciphers: dict[str, Cipher] = {}
    builders = (
        build_aead,
        build_symmetric,
        build_keywrap,
        build_asymmetric,
        build_recipe,
        build_sodium,
    )
    for build in builders:
        for cipher in build():
            ciphers[cipher.name] = cipher
    for name, family, summary, reason in _UNAVAILABLE:
        ciphers.setdefault(
            name, Cipher.unsupported(name, family, summary, reason)
        )
    return ciphers


@cache
def _lookup_index() -> dict[str, str]:
    """Mapa normalizado -> nome canônico (inclui variantes sem hífen e aliases)."""
    index: dict[str, str] = {}
    for canonical in _registry():
        normed = _norm(canonical)
        index.setdefault(normed, canonical)
        index.setdefault(normed.replace("-", ""), canonical)
    for alias, canonical in _ALIASES.items():
        index.setdefault(_norm(alias), canonical)
        index.setdefault(_norm(alias).replace("-", ""), canonical)
    return index


def get_cipher(name: str) -> Cipher:
    """Resolve ``name`` (canônico ou alias) para uma :class:`Cipher`."""
    index = _lookup_index()
    normed = _norm(name)
    canonical = index.get(normed) or index.get(normed.replace("-", ""))
    if canonical is None:
        raise UnsupportedFormatError(f"cifra desconhecida: {name!r}")
    return _registry()[canonical]


def all_ciphers() -> list[Cipher]:
    """Retorna todas as cifras do catálogo, ordenadas por nome."""
    registry = _registry()
    return [registry[name] for name in sorted(registry)]
