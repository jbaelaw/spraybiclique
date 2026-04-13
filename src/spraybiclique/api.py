from __future__ import annotations

import json
from typing import Any

from fastapi import FastAPI, HTTPException, Request

from .detect import scan_events
from .normalize import normalize_events, parse_jsonl_text
from .report import build_markdown_summary
from .schema import ScanConfig, ScanResponse

app = FastAPI(
    title="SprayBiclique",
    version="0.9.1",
    summary="Explainable biclique witness detection for distributed authentication abuse.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


async def _load_config(config_raw: object | None) -> ScanConfig:
    if config_raw is None:
        return ScanConfig()

    if isinstance(config_raw, str):
        raw_text = config_raw
    elif isinstance(config_raw, (bytes, bytearray)):
        raw_text = bytes(config_raw).decode("utf-8")
    elif hasattr(config_raw, "read"):
        raw_bytes = await config_raw.read()
        raw_text = raw_bytes.decode("utf-8")
    else:
        raise ValueError("config must be a JSON string or JSON file part")

    if not raw_text.strip():
        return ScanConfig()

    return ScanConfig.model_validate(json.loads(raw_text))


def _load_json_events(payload: Any) -> tuple[list[Any], ScanConfig]:
    if not isinstance(payload, dict):
        raise ValueError("JSON body must be an object")

    events = payload.get("events")
    if not isinstance(events, list):
        raise ValueError("JSON body must include an events array")

    config_payload = payload.get("config", {})
    config = ScanConfig.model_validate(config_payload)
    return events, config


@app.post("/scan", response_model=ScanResponse)
async def scan(request: Request) -> ScanResponse:
    content_type = request.headers.get("content-type", "")

    try:
        if "application/json" in content_type:
            payload = await request.json()
            raw_events, config = _load_json_events(payload)
            events = normalize_events(raw_events)
        elif "multipart/form-data" in content_type:
            form = await request.form()
            upload = form.get("file")
            if upload is None or not hasattr(upload, "read"):
                raise HTTPException(status_code=400, detail="multipart request must include a file field")

            config_raw = form.get("config")
            config = await _load_config(config_raw)

            raw_payload = await upload.read()
            records = parse_jsonl_text(raw_payload.decode("utf-8"))
            events = normalize_events(records)
        else:
            raise HTTPException(
                status_code=415,
                detail="Use application/json or multipart/form-data with a JSONL file",
            )
    except HTTPException:
        raise
    except (ValueError, json.JSONDecodeError) as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    alerts, stats = scan_events(events, config)
    return ScanResponse(
        stats=stats,
        alerts=alerts,
        markdown_summary=build_markdown_summary(alerts, stats),
    )
