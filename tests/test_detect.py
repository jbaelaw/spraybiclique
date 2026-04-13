from __future__ import annotations

import json
from pathlib import Path

from fastapi.testclient import TestClient

from spraybiclique.api import app
from spraybiclique.detect import scan_events
from spraybiclique.normalize import normalize_events, parse_jsonl_text
from spraybiclique.schema import AuthEvent, AuthResult, ScanConfig


def _attack_records() -> list[dict[str, str]]:
    return [
        {
            "timestamp": "2026-04-13T09:00:00Z",
            "src": "203.0.113.10",
            "user": "alice",
            "result": "failure",
            "failure_code": "INVALID_PASSWORD",
        },
        {
            "timestamp": "2026-04-13T09:00:30Z",
            "src": "203.0.113.11",
            "user": "alice",
            "result": "failure",
            "failure_code": "INVALID_PASSWORD",
        },
        {
            "timestamp": "2026-04-13T09:01:00Z",
            "src": "203.0.113.10",
            "user": "bob",
            "result": "failure",
            "failure_code": "INVALID_PASSWORD",
        },
        {
            "timestamp": "2026-04-13T09:01:30Z",
            "src": "203.0.113.11",
            "user": "bob",
            "result": "failure",
            "failure_code": "INVALID_PASSWORD",
        },
        {
            "timestamp": "2026-04-13T09:02:00Z",
            "src": "203.0.113.10",
            "user": "carol",
            "result": "failure",
            "failure_code": "INVALID_PASSWORD",
        },
        {
            "timestamp": "2026-04-13T09:02:30Z",
            "src": "203.0.113.11",
            "user": "carol",
            "result": "failure",
            "failure_code": "INVALID_PASSWORD",
        },
        {
            "timestamp": "2026-04-13T09:03:00Z",
            "src": "203.0.113.10",
            "user": "dave",
            "result": "failure",
            "failure_code": "INVALID_PASSWORD",
        },
        {
            "timestamp": "2026-04-13T09:03:30Z",
            "src": "203.0.113.11",
            "user": "dave",
            "result": "failure",
            "failure_code": "INVALID_PASSWORD",
        },
        {
            "timestamp": "2026-04-13T09:05:30Z",
            "src": "203.0.113.11",
            "user": "alice",
            "result": "success",
        },
    ]


def test_normalize_events_accepts_aliases() -> None:
    events = normalize_events(
        [
            {
                "time": "2026-04-13T09:00:00Z",
                "source_ip": "203.0.113.10",
                "username": "alice",
                "status": "FAILED",
                "reason": "invalid_password",
                "ua": "curl/8.0",
            }
        ]
    )

    assert events[0].src == "203.0.113.10"
    assert events[0].user == "alice"
    assert events[0].failure_code == "INVALID_PASSWORD"
    assert events[0].user_agent == "curl/8.0"


def test_auth_event_uppercases_failure_code() -> None:
    event = AuthEvent(
        timestamp="2026-04-13T09:00:00Z",
        src="203.0.113.10",
        user="alice",
        result=AuthResult.FAILURE,
        failure_code="unknown_user",
    )

    assert event.failure_code == "UNKNOWN_USER"


def test_scan_events_detects_distributed_witness() -> None:
    alerts, stats = scan_events(normalize_events(_attack_records()), ScanConfig())

    assert stats.witness_candidates == 1
    assert len(alerts) == 1
    alert = alerts[0]
    assert alert.pattern == "fail_same_code"
    assert alert.failure_code == "INVALID_PASSWORD"
    assert alert.sources == ["203.0.113.10", "203.0.113.11"]
    assert alert.accounts == ["alice", "bob", "carol", "dave"]
    assert alert.success_followups == 1
    assert alert.score >= 5.0
    assert alert.severity in {"medium", "high"}


def test_scan_events_suppresses_trusted_sources() -> None:
    config = ScanConfig(trusted_sources=["203.0.113.10"])
    alerts, stats = scan_events(normalize_events(_attack_records()), config)

    assert alerts == []
    assert stats.suppressed_candidates == 1


def test_api_scan_json() -> None:
    client = TestClient(app)
    response = client.post(
        "/scan",
        json={
            "config": {"window_minutes": 10, "min_shared_accounts": 4},
            "events": _attack_records(),
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["stats"]["alerts_emitted"] == 1
    assert payload["alerts"][0]["pattern"] == "fail_same_code"
    assert "SprayBiclique Scan Summary" in payload["markdown_summary"]


def test_api_scan_json_accepts_alias_fields() -> None:
    client = TestClient(app)
    response = client.post(
        "/scan",
        json={
            "events": [
                {
                    "time": "2026-04-13T09:00:00Z",
                    "source_ip": "203.0.113.10",
                    "username": "alice",
                    "status": "failed",
                    "reason": "invalid_password",
                },
                {
                    "time": "2026-04-13T09:00:30Z",
                    "source_ip": "203.0.113.11",
                    "username": "alice",
                    "status": "failed",
                    "reason": "invalid_password",
                },
                {
                    "time": "2026-04-13T09:01:00Z",
                    "source_ip": "203.0.113.10",
                    "username": "bob",
                    "status": "failed",
                    "reason": "invalid_password",
                },
                {
                    "time": "2026-04-13T09:01:30Z",
                    "source_ip": "203.0.113.11",
                    "username": "bob",
                    "status": "failed",
                    "reason": "invalid_password",
                },
                {
                    "time": "2026-04-13T09:02:00Z",
                    "source_ip": "203.0.113.10",
                    "username": "carol",
                    "status": "failed",
                    "reason": "invalid_password",
                },
                {
                    "time": "2026-04-13T09:02:30Z",
                    "source_ip": "203.0.113.11",
                    "username": "carol",
                    "status": "failed",
                    "reason": "invalid_password",
                },
                {
                    "time": "2026-04-13T09:03:00Z",
                    "source_ip": "203.0.113.10",
                    "username": "dave",
                    "status": "failed",
                    "reason": "invalid_password",
                },
                {
                    "time": "2026-04-13T09:03:30Z",
                    "source_ip": "203.0.113.11",
                    "username": "dave",
                    "status": "failed",
                    "reason": "invalid_password",
                },
            ]
        },
    )

    assert response.status_code == 200
    payload = response.json()
    assert payload["stats"]["alerts_emitted"] == 1
    assert payload["alerts"][0]["failure_code"] == "INVALID_PASSWORD"


def test_api_scan_jsonl_upload() -> None:
    client = TestClient(app)
    sample_path = Path(__file__).resolve().parents[1] / "examples" / "auth_sample.jsonl"
    payload = sample_path.read_text()
    response = client.post(
        "/scan",
        files={"file": ("auth_sample.jsonl", payload, "application/jsonl")},
        data={"config": json.dumps({"window_minutes": 10, "min_shared_accounts": 4})},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["stats"]["witness_candidates"] >= 1
    assert body["alerts"][0]["accounts"] == ["alice", "bob", "carol", "dave"]


def test_api_scan_jsonl_upload_honors_json_config_part() -> None:
    client = TestClient(app)
    sample_path = Path(__file__).resolve().parents[1] / "examples" / "auth_sample.jsonl"
    payload = sample_path.read_text()
    response = client.post(
        "/scan",
        files={
            "file": ("auth_sample.jsonl", payload, "application/jsonl"),
            "config": ("config.json", '{"window_minutes":10,"min_shared_accounts":5}', "application/json"),
        },
    )

    assert response.status_code == 200
    body = response.json()
    assert body["stats"]["alerts_emitted"] == 0
    assert body["stats"]["witness_candidates"] == 0


def test_parse_jsonl_text_reads_example_file() -> None:
    sample_path = Path(__file__).resolve().parents[1] / "examples" / "auth_sample.jsonl"
    records = parse_jsonl_text(sample_path.read_text())

    assert len(records) == 12
