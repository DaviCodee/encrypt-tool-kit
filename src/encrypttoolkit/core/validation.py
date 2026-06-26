"""Saneamento de nomes de arquivo de saída."""

from __future__ import annotations

import os
import re


def safe_filename(name: str, *, fallback: str = "saida.bin") -> str:
    """Reduz ``name`` ao componente base e remove caracteres perigosos."""
    base = os.path.basename(name or "").strip()
    base = base.replace("\x00", "")
    base = re.sub(r"[^A-Za-z0-9._-]+", "_", base).strip("._")
    return base or fallback


def with_suffix(name: str, suffix: str) -> str:
    """Insere ``suffix`` antes da extensão: ``a.bin`` + ``-out`` -> ``a-out.bin``."""
    safe = safe_filename(name)
    stem, dot, ext = safe.rpartition(".")
    if not dot:
        return f"{safe}{suffix}"
    return f"{stem}{suffix}.{ext}"


def replace_ext(name: str, ext: str, *, fallback_stem: str = "saida") -> str:
    """Troca a extensão de ``name`` por ``ext`` (sem ponto), saneando o nome."""
    safe = safe_filename(name)
    stem, dot, _ = safe.rpartition(".")
    base = stem if dot else safe
    base = base or fallback_stem
    return f"{base}.{ext}"
