"""Fixtures compartilhadas: dados gerados em runtime (nada binário é commitado)."""

from __future__ import annotations

from collections.abc import Callable

import pytest

from encrypttoolkit.core.io import DataInput, OperationResult
from encrypttoolkit.core.registry import get_operation


@pytest.fixture
def mensagem() -> bytes:
    return "olá, mundo — segredo 💡".encode()


@pytest.fixture
def run_op() -> Callable[..., OperationResult]:
    def _run(name: str, datas: list[bytes], **params: object) -> OperationResult:
        op = get_operation(name)
        return op.execute([DataInput(d) for d in datas], op.params_model(**params))

    return _run
