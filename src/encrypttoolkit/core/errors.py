"""Hierarquia de erros do toolkit.

Os adaptadores traduzem essas exceções em códigos de saída (CLI) ou status HTTP (API).
"""

from __future__ import annotations


class CryptoToolkitError(Exception):
    """Raiz de todos os erros tratáveis do toolkit."""


class InvalidInputError(CryptoToolkitError):
    """Entrada inválida: chave de tamanho errado, nonce ausente, parâmetro fora de faixa…"""


class UnsupportedFormatError(InvalidInputError):
    """Cifra/algoritmo solicitado não é suportado por este toolkit (ou nem existe)."""


class OperationError(CryptoToolkitError):
    """Falha durante a execução de uma operação (ex.: tag de autenticação inválida)."""


class MissingDependencyError(CryptoToolkitError):
    """Funcionalidade requer uma dependência/binário opcional não instalado."""
