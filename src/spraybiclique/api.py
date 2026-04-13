from __future__ import annotations

import json

from fastapi import FastAPI, HTTPException, Request

from .detect import scan_events
from .normalize import normalize_events, parse_jsonl_text
from .report import build_markdown_summary
from .schema import ScanConfig, ScanRequest, ScanResponse

app = FastAPI(
    title="SprayBiclique",
    version="0.9",
    summary="Biclique witness detection for distributed authentication abuse.",
)


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/scan", response_model=ScanResponse)
async def scan(request: Request) -> ScanResponse:
    content_type = request.headers.get("content-type", "")

    try:
        if "application/json" in content_type:
            payload = await request.json()
            scan_request = ScanRequest.model_validate(payload)
            events = normalize_events(scan_request.events)
            config = scan_request.config
        elif "multipart/form-data" in content_type:
            form = await request.form()
            upload = form.get("file")
            if upload is None or not hasattr(upload, "read"):
                raise HTTPException(status_code=400, detail="multipart request must include a file field")

            config = ScanConfig()
            config_raw = form.get("config")
            if isinstance(config_raw, str) and config_raw.strip():
                config = ScanConfig.model_validate(json.loads(config_raw))

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
