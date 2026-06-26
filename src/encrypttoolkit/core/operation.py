"""Contrato base de uma operação criptográfica.

Toda operação é uma classe que declara metadados (nome, categoria, resumo), o modelo
de parâmetros e quantas entradas aceita, além de implementar ``run``.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Sequence
from typing import ClassVar, Generic, TypeVar

from encrypttoolkit.core.errors import InvalidInputError
from encrypttoolkit.core.io import DataInput, OperationResult
from encrypttoolkit.core.params import OperationParams

P = TypeVar("P", bound=OperationParams)


class CryptoOperation(ABC, Generic[P]):
    """Unidade de trabalho do toolkit.

    Subclasses fixam o tipo de parâmetro via ``CryptoOperation[MeuParams]`` e definem
    os atributos de classe abaixo.
    """

    name: ClassVar[str]
    category: ClassVar[str]
    summary: ClassVar[str]
    params_model: ClassVar[type[OperationParams]]
    min_inputs: ClassVar[int] = 1
    max_inputs: ClassVar[int | None] = 1

    def check_inputs(self, inputs: Sequence[DataInput]) -> None:
        """Valida a quantidade de entradas."""
        count = len(inputs)
        if count < self.min_inputs:
            raise InvalidInputError(
                f"operação {self.name!r} exige ao menos {self.min_inputs} entrada(s), "
                f"recebeu {count}"
            )
        if self.max_inputs is not None and count > self.max_inputs:
            raise InvalidInputError(
                f"operação {self.name!r} aceita no máximo {self.max_inputs} entrada(s), "
                f"recebeu {count}"
            )

    @abstractmethod
    def run(self, inputs: Sequence[DataInput], params: P) -> OperationResult:
        """Executa a operação e devolve o resultado."""

    def execute(self, inputs: Sequence[DataInput], params: P) -> OperationResult:
        """Valida as entradas e chama :meth:`run`."""
        self.check_inputs(inputs)
        return self.run(inputs, params)
