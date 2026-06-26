"""CLI do toolkit, gerada a partir do registro de operações.

Cada operação registrada vira um subcomando próprio, com flags derivadas do seu modelo
de parâmetros Pydantic:

    ctk list                              lista as operações disponíveis
    ctk schema <operacao>                 mostra o schema JSON dos parâmetros
    ctk list-ciphers                      lista o catálogo de cifras
    ctk keygen --cipher aes-256-gcm       gera uma chave
    ctk encrypt --cipher aes-256-gcm --key <hex> --text "segredo"
    ctk decrypt --cipher aes-256-gcm --key <hex> --nonce <hex> arquivo.enc -o out/

A entrada vem de arquivos posicionais ou da flag ``--text`` (texto UTF-8). Sem ``-o`` o
resultado é impresso na saída padrão; com ``-o`` é gravado como arquivo.
"""

from __future__ import annotations

import json
import types
from pathlib import Path
from typing import Any, Literal, Union, get_args, get_origin

import click

from encrypttoolkit.core.errors import CryptoToolkitError
from encrypttoolkit.core.io import DataInput
from encrypttoolkit.core.operation import CryptoOperation
from encrypttoolkit.core.registry import all_operations, get_operation

_RESERVED = {"list", "schema"}
_PY_TYPES: dict[type, type] = {int: int, float: float, str: str}


@click.group(help="Concentrador de operações de cifragem.")
def app() -> None:
    pass


@app.command("list")
def list_command() -> None:
    """Lista todas as operações registradas."""
    for operation in all_operations():
        click.echo(f"{operation.name:<14} [{operation.category}] {operation.summary}")


@app.command("schema")
@click.argument("operation")
def schema_command(operation: str) -> None:
    """Mostra o schema JSON dos parâmetros de uma operação."""
    op = _lookup(operation)
    click.echo(json.dumps(op.params_model.model_json_schema(), indent=2, ensure_ascii=False))


def _unwrap_optional(annotation: Any) -> tuple[Any, bool]:
    origin = get_origin(annotation)
    if origin is Union or origin is types.UnionType:
        args = [arg for arg in get_args(annotation) if arg is not type(None)]
        return args[0], True
    return annotation, False


def _help_for(field: Any, fallback: str) -> str:
    return field.description or fallback


def _build_option(name: str, field: Any) -> click.Option:
    flag = "--" + name.replace("_", "-")
    annotation, _optional = _unwrap_optional(field.annotation)
    origin = get_origin(annotation)
    required = field.is_required()
    default = None if field.is_required() else field.default

    if annotation is bool:
        return click.Option(
            [f"{flag}/--no-{name.replace('_', '-')}", name],
            default=default, help=_help_for(field, ""),
        )
    if origin is Literal:
        choices = [str(value) for value in get_args(annotation)]
        return click.Option(
            [flag, name], type=click.Choice(choices), default=default,
            required=required, help=_help_for(field, ""),
        )
    return click.Option(
        [flag, name], type=_PY_TYPES.get(annotation, str), default=default,
        required=required, help=_help_for(field, ""),
    )


def _collect_params(
    op: CryptoOperation[Any], ctx: click.Context, raw: dict[str, Any]
) -> dict[str, Any]:
    fields = op.params_model.model_fields
    payload: dict[str, Any] = {}
    json_blob = raw.get("json_params")
    if json_blob:
        payload.update(json.loads(json_blob))
    for name in fields:
        if ctx.get_parameter_source(name) == click.core.ParameterSource.DEFAULT:
            continue
        payload[name] = raw[name]
    return payload


def _read_inputs(text: str | None, paths: tuple[str, ...]) -> list[DataInput]:
    if text is not None:
        return [DataInput(text.encode("utf-8"), "texto.txt")]
    return [DataInput(Path(p).expanduser().read_bytes(), Path(p).name) for p in paths]


def _make_operation_command(op: CryptoOperation[Any]) -> click.Command:
    def callback(**raw: Any) -> None:
        ctx = click.get_current_context()
        paths = raw.pop("inputs")
        out = raw.pop("out")
        text = raw.pop("text")
        try:
            payload = _collect_params(op, ctx, raw)
            params = op.params_model(**payload)
            inputs = _read_inputs(text, paths)
            result = op.execute(inputs, params)
        except (CryptoToolkitError, OSError, ValueError) as exc:
            raise click.ClickException(str(exc)) from exc
        _emit(result, out)

    params: list[click.Parameter] = [
        click.Argument(["inputs"], nargs=-1),
        click.Option(
            ["-o", "--out", "out"], type=click.Path(path_type=Path), help="diretório de saída"
        ),
        click.Option(["--text", "text"], help="texto UTF-8 como entrada (no lugar de arquivos)"),
        click.Option(["--json", "json_params"], help="parâmetros como objeto JSON"),
    ]
    params.extend(
        _build_option(name, field) for name, field in op.params_model.model_fields.items()
    )
    return click.Command(name=op.name, params=params, callback=callback, help=op.summary)


def _is_text(media_type: str) -> bool:
    """Heurística: o artefato é seguro para imprimir como texto no terminal?"""
    return media_type.startswith("text/") or "json" in media_type or "pem" in media_type


def _emit(result: Any, out: Path | None) -> None:
    if result.artifacts and out is not None:
        out.mkdir(parents=True, exist_ok=True)
        for artifact in result.artifacts:
            destination = out / artifact.filename
            destination.write_bytes(artifact.data)
            click.echo(f"escrito: {destination}")
    elif result.artifacts:
        # Sem -o: imprime artefatos de texto; para binários (chave, texto cifrado)
        # mostra só uma dica — a chave/nonce já vão no JSON de metadados abaixo.
        for artifact in result.artifacts:
            if _is_text(artifact.media_type):
                click.echo(artifact.data.decode("utf-8", errors="replace"))
            else:
                click.echo(
                    f"[{artifact.filename}: {len(artifact.data)} bytes — use -o para gravar]"
                )
    if "ciphers" in result.meta:
        _print_ciphers(result.meta["ciphers"])
    elif result.meta:
        click.echo(json.dumps(result.meta, indent=2, ensure_ascii=False))


def _print_ciphers(ciphers: list[dict[str, Any]]) -> None:
    for cipher in ciphers:
        status = "ok" if cipher["available"] else f"indisponível ({cipher['reason']})"
        click.echo(f"{cipher['name']:<22} [{cipher['family']:<11}] {status}")


def _lookup(name: str) -> CryptoOperation[Any]:
    try:
        return get_operation(name)
    except CryptoToolkitError as exc:
        raise click.ClickException(str(exc)) from exc


def _register_operation_commands() -> None:
    for operation in all_operations():
        if operation.name in _RESERVED:
            continue
        app.add_command(_make_operation_command(operation))


_register_operation_commands()


if __name__ == "__main__":  # pragma: no cover
    app()
