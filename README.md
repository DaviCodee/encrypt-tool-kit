# encrypttoolkit

Concentrador de operações de cifragem: um **núcleo leve** em Python que expõe um
registro de operações, consumido por adaptadores finos de **CLI** (`ctk`) e **API**
(FastAPI). A mesma operação, definida uma vez, fica disponível na linha de comando e
via HTTP.

O núcleo (`encrypttoolkit.core`) depende **apenas da stdlib + Pydantic**. A pilha
criptográfica fica em `encrypttoolkit.ciphers`, sobre a [PyCA `cryptography`], e só é
importada quando usada. Algoritmos clássicos (AES em GCM/CBC/CTR/…, ChaCha20(-Poly1305),
RSA-OAEP, AES Key Wrap, Fernet…) e proteção de chaves privadas por senha (PKCS#8
cifrado, PKCS#12/PFX, PEM TraditionalOpenSSL, OpenSSH cifrado) saem prontos da
biblioteca. Itens da lista de referência que **não são uma cifra de blob isolada** —
protocolos (TLS, WireGuard…), formatos de envelope (PGP, JWE, S/MIME…), containers
(LUKS, BitLocker, ZIP AES…), serviços de KMS, acordo de chaves (ECDH, X25519…) e KEMs
pós-quânticos (ML-KEM) — ficam **listados mas indisponíveis**, com erro claro.

[PyCA `cryptography`]: https://cryptography.io/

## Arquitetura

```
src/encrypttoolkit/
  core/        contrato (operation), registro, params (Pydantic), io, validação, erros
  ciphers/     catálogo de cifras: aead, symmetric, keywrap, asymmetric, recipe, sodium
  operations/  crypt (encrypt/decrypt), keys (keygen), inspect (list-ciphers)
  cli/         main.py  — Click, um subcomando por operação (ctk)
  api/         app.py   — FastAPI gerada a partir do registro
```

Cada operação é uma classe `CryptoOperation` com um modelo de parâmetros Pydantic. Esse
único schema alimenta a validação, as flags da CLI, o corpo da API e o export de JSON
Schema. Os adaptadores apenas percorrem o registro — não conhecem operações individuais.

Há **dois registros**: o de operações (`core/registry.py`, 4 operações) e o de **cifras**
(`ciphers/catalog.py`). As operações são genéricas e recebem a cifra por parâmetro,
resolvida pelo catálogo (com aliases, ex.: `AES`→`aes-256-gcm`, `3DES`→`3des-cbc`,
`RC4`→`rc4`).

## Instalação

```bash
pip install -e ".[cli,api]"          # núcleo + CLI + API
pip install -e ".[cli,api,nacl,dev]" # tudo, incluindo libsodium e testes/lint/type-check
```

| Extra  | Habilita                                                              |
|--------|-----------------------------------------------------------------------|
| `cli`  | comando `ctk`                                                         |
| `api`  | servidor FastAPI/uvicorn                                              |
| `nacl` | cifras do libsodium (XSalsa20/XChaCha20-Poly1305)                    |
| `dev`  | pytest, ruff, mypy, httpx                                             |

A pilha base (`cryptography` + `pydantic` + `bcrypt`) é sempre instalada. O `bcrypt` é
necessário para `openssh-private-key` (KDF do formato OpenSSH); o `nacl` (PyNaCl) é
opcional porque traz binário nativo maior.

## Operações

| Operação       | Categoria     | Resumo                                                   |
|----------------|---------------|----------------------------------------------------------|
| `encrypt`      | cifrar        | cifra a entrada (gera chave/nonce se omitidos)           |
| `decrypt`      | cifrar        | decifra a entrada (mesma chave/nonce da cifragem)        |
| `keygen`       | chaves        | gera chave simétrica ou par RSA (PEM)                    |
| `list-ciphers` | inspecionar   | lista o catálogo de cifras (família + disponibilidade)   |

## Catálogo de cifras

137 entradas, sendo **68 disponíveis** e 69 listadas-mas-indisponíveis.

Disponíveis (por família):

- **aead** (15): AES-128/192/256-GCM, AES-128/192/256-CCM, AES-128/256-GCM-SIV,
  AES-128/192/256-OCB3, AES-256-SIV, ChaCha20-Poly1305 e — com o extra `nacl` —
  XSalsa20-Poly1305 e XChaCha20-Poly1305.
- **block** (42): AES/Camellia/ARIA em 128/192/256 e SM4/SEED/3DES/CAST5/Blowfish/IDEA,
  nos modos suportados pela versão instalada (CBC/CTR/CFB/OFB) mais AES-128/256-XTS.
- **stream** (2): ChaCha20 puro e RC4 (legado).
- **keywrap** (2): AES Key Wrap com e sem padding (RFC 3394/5649).
- **asymmetric** (2): RSA-OAEP (SHA-256) e RSAES-PKCS1-v1_5.
- **recipe** (1): Fernet.
- **keystore** (4): proteção de chave privada por senha — PKCS#8 cifrado, PEM
  TraditionalOpenSSL, PKCS#12/PFX e OpenSSH cifrado (requer `bcrypt`).

Indisponíveis (listadas, erram com motivo claro ao serem usadas): formatos de envelope
(`openpgp`, `jwe`, `smime`, `cms-envelopeddata`, `cose-encrypt`, `age`…), protocolos
(`tls-1.3`, `dtls`, `ipsec`, `wireguard`, `openvpn`, `ssh-transport`), containers
(`luks`, `bitlocker`, `filevault`, `veracrypt`, `zip-aes`, `7z-aes-256`, `pdf-encryption`…),
serviços de KMS (`aws-kms`, `gcp-kms`, `azure-key-vault`, `vault-transit`), acordo de
chaves (`ecdh`, `x25519`, `diffie-hellman`, `secp256r1`…), KEMs pós-quânticos (`ml-kem-*`),
proteção de chaves em arquivo (`pkcs12`, `pkcs8-encrypted`…) e cifras fora da PyCA
cryptography (`twofish`, `serpent`, `rc5`, `rc6`, `salsa20`, `elgamal`, `des`…).

Veja todas com `ctk list-ciphers`.

## Uso (CLI)

```bash
ctk list                                            # lista as operações
ctk list-ciphers                                    # lista as cifras
ctk keygen --cipher aes-256-gcm                     # gera uma chave (hex)
ctk encrypt --cipher aes-256-gcm --text "segredo"   # chave/nonce gerados e reportados
ctk encrypt --cipher aes-256-cbc --key <hex> arquivo.bin -o out/
ctk decrypt --cipher aes-256-gcm --key <hex> --nonce <hex> arquivo.enc -o out/
ctk keygen --cipher rsa-oaep --size 3072 -o keys/   # par PEM (private/public)
ctk encrypt --cipher rsa-oaep --key "$(cat keys/rsa-oaep-public.pem)" --key-format pem --text "k"
ctk schema encrypt                                  # schema JSON dos parâmetros
```

A entrada vem de arquivos posicionais ou de `--text` (texto UTF-8). Sem `-o`, o
resultado vai para a saída padrão; com `-o`, é gravado como arquivo. Chaves e nonce
gerados são reportados no JSON de metadados — **guarde-os**, sem eles não há decifragem.

Formatos de chave (`--key-format`): `hex` (padrão das simétricas), `base64`,
`base64url`, `text` (ex.: chave Fernet) e `pem` (RSA). Nonce/IV é sempre hexadecimal.

## Uso (API)

```bash
uvicorn encrypttoolkit.api.app:app --reload
```

```
GET  /operations                  lista as operações
GET  /operations/{name}/schema    schema JSON dos parâmetros
POST /operations/{name}           executa (multipart: files + params JSON)
GET  /docs                        Swagger UI
```

Ao retornar um único artefato (o texto cifrado/claro), os metadados (nonce, chave
gerada…) vão no cabeçalho `X-Meta` como JSON.

## Uso como biblioteca

```python
from encrypttoolkit.ciphers import get_cipher

c = get_cipher("aes-256-gcm")
gen = c.generate_key()
enc = c.encrypt(gen.key, b"segredo", nonce=None, aad=None)   # nonce aleatório no meta
nonce = bytes.fromhex(enc.meta["nonce"])
c.decrypt(gen.key, enc.ciphertext, nonce=nonce, aad=None)    # b"segredo"
```

## Aviso

Ferramenta de uso geral/educacional. A segurança real depende de gestão de chaves,
unicidade de nonce e escolha de modo — prefira sempre cifras **AEAD** (GCM, ChaCha20-
Poly1305) e evite as marcadas como legadas (RC4, DES, IDEA, modos sem autenticação).

## Desenvolvimento

```bash
ruff check src tests   # lint
mypy                   # type-check (strict)
pytest                 # testes (chaves/dados gerados em runtime, nada binário commitado)
```
