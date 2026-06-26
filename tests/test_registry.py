"""Testes do registro de operações."""

from __future__ import annotations

import pytest

from encrypttoolkit.core.errors import CryptoToolkitError
from encrypttoolkit.core.registry import all_operations, get_operation


def test_all_operations_present():
    names = {op.name for op in all_operations()}
    assert names == {"encrypt", "decrypt", "keygen", "list-ciphers"}


def test_get_operation_unknown():
    with pytest.raises(CryptoToolkitError):
        get_operation("inexistente")


def test_keygen_and_list_take_no_input():
    for name in ("keygen", "list-ciphers"):
        op = get_operation(name)
        assert op.min_inputs == 0
        assert op.max_inputs == 0
