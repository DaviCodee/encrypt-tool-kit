"""API HTTP do toolkit, gerada a partir do registro de operações.

Rotas:
    GET  /operations                  lista as operações
    GET  /operations/{name}/schema    schema JSON dos parâmetros
    POST /operations/{name}           executa a operação (multipart: files + params)
"""

from __future__ import annotations

import json
import zipfile
from io import BytesIO
from typing import Any

from fastapi import FastAPI, File, Form, HTTPException, UploadFile
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import ValidationError

from encrypttoolkit.core.errors import (
    CryptoToolkitError,
    InvalidInputError,
    MissingDependencyError,
)
from encrypttoolkit.core.io import DataInput, OperationResult
from encrypttoolkit.core.operation import CryptoOperation
from encrypttoolkit.core.registry import all_operations, get_operation


def create_app() -> FastAPI:
    app = FastAPI(title="encrypttoolkit", version="0.1.0")

    @app.get("/operations")
    def list_operations() -> list[dict[str, str]]:
        return [
            {
                "name": op.name,
                "category": op.category,
                "summary": op.summary,
                "min_inputs": str(op.min_inputs),
                "max_inputs": "" if op.max_inputs is None else str(op.max_inputs),
            }
            for op in all_operations()
        ]

    @app.get("/operations/{name}/schema")
    def operation_schema(name: str) -> dict[str, Any]:
        return _lookup(name).params_model.model_json_schema()

    @app.post("/operations/{name}")
    async def run_operation(
        name: str,
        files: list[UploadFile] = File(default=[]),
        params: str = Form(default="{}"),
    ) -> Any:
        op = _lookup(name)
        try:
            payload = json.loads(params or "{}")
        except json.JSONDecodeError as exc:
            raise HTTPException(status_code=422, detail=f"params não é JSON válido: {exc}") from exc
        try:
            model = op.params_model(**payload)
        except ValidationError as exc:
            raise HTTPException(status_code=422, detail=json.loads(exc.json())) from exc

        inputs = [DataInput(await f.read(), f.filename or "entrada.bin") for f in files]
        try:
            result = op.execute(inputs, model)
        except MissingDependencyError as exc:
            raise HTTPException(status_code=501, detail=str(exc)) from exc
        except InvalidInputError as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        except CryptoToolkitError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc

        return _respond(result)

    return app


def _lookup(name: str) -> CryptoOperation[Any]:
    try:
        return get_operation(name)
    except CryptoToolkitError as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc


def _respond(result: OperationResult) -> Any:
    if not result.artifacts:
        return JSONResponse(result.meta)
    if len(result.artifacts) == 1:
        artifact = result.artifacts[0]
        return StreamingResponse(
            BytesIO(artifact.data),
            media_type=artifact.media_type,
            headers={
                "Content-Disposition": f'attachment; filename="{artifact.filename}"',
                "X-Meta": json.dumps(result.meta, ensure_ascii=False),
            },
        )
    buffer = BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for artifact in result.artifacts:
            archive.writestr(artifact.filename, artifact.data)
    buffer.seek(0)
    return StreamingResponse(
        buffer,
        media_type="application/zip",
        headers={"Content-Disposition": 'attachment; filename="resultado.zip"'},
    )


app = create_app()
