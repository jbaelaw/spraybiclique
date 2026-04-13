from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from spraybiclique.api import app
from spraybiclique.cli import main
from spraybiclique.meta import APP_NAME, VERSION


def _sample_path() -> Path:
    return Path(__file__).resolve().parents[1] / "examples" / "auth_sample.jsonl"


def test_root_endpoint_returns_metadata() -> None:
    client = TestClient(app)
    response = client.get("/")

    assert response.status_code == 200
    body = response.json()
    assert body["name"] == APP_NAME
    assert body["version"] == VERSION
    assert body["scan_url"] == "/scan"


def test_health_endpoint_returns_versioned_status() -> None:
    client = TestClient(app)
    response = client.get("/health")

    assert response.status_code == 200
    assert response.json() == {
        "status": "ok",
        "service": APP_NAME,
        "version": VERSION,
    }


def test_cli_scan_outputs_json(capsys) -> None:
    exit_code = main(["scan", str(_sample_path()), "--format", "json"])

    assert exit_code == 0
    captured = capsys.readouterr()
    body = json.loads(captured.out)
    assert body["stats"]["alerts_emitted"] == 1
    assert body["alerts"][0]["pattern"] == "fail_same_code"


def test_cli_scan_writes_markdown_report(tmp_path: Path) -> None:
    output_path = tmp_path / "report.md"

    exit_code = main(["scan", str(_sample_path()), "--output", str(output_path)])

    assert exit_code == 0
    rendered = output_path.read_text()
    assert "SprayBiclique Scan Summary" in rendered
    assert "Alert 1" in rendered
