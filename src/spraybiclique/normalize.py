from __future__ import annotations

import json
from collections.abc import Iterable
from typing import Any

from .schema import AuthEvent

TIMESTAMP_KEYS = ("timestamp", "time", "ts")
SOURCE_KEYS = ("src", "source", "source_ip", "ip", "client_ip")
USER_KEYS = ("user", "username", "account", "target_user", "principal")
RESULT_KEYS = ("result", "status", "outcome")
FAILURE_CODE_KEYS = ("failure_code", "code", "error_code", "reason")
USER_AGENT_KEYS = ("user_agent", "ua")
APP_KEYS = ("app", "application", "resource")


def parse_jsonl_text(payload: str) -> list[dict[str, Any]]:
    records: list[dict[str, Any]] = []
    for line_number, line in enumerate(payload.splitlines(), start=1):
        stripped = line.strip()
        if not stripped:
            continue
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ValueError(f"Invalid JSONL at line {line_number}: {exc.msg}") from exc
        if not isinstance(parsed, dict):
            raise ValueError(f"Line {line_number} must contain a JSON object")
        records.append(parsed)
    return records


def _first_present(record: dict[str, Any], keys: tuple[str, ...]) -> Any:
    for key in keys:
        if key in record and record[key] not in (None, ""):
            return record[key]
    return None


def normalize_record(record: dict[str, Any] | AuthEvent) -> AuthEvent:
    if isinstance(record, AuthEvent):
        return record

    timestamp = _first_present(record, TIMESTAMP_KEYS)
    src = _first_present(record, SOURCE_KEYS)
    user = _first_present(record, USER_KEYS)
    result = _first_present(record, RESULT_KEYS)

    if timestamp is None or src is None or user is None or result is None:
        raise ValueError(
            "Each record must include timestamp, src, user, and result fields "
            "(aliases like source_ip, username, status are accepted)."
        )

    failure_code = _first_present(record, FAILURE_CODE_KEYS)
    if isinstance(failure_code, str):
        failure_code = failure_code.strip().upper() or None

    user_agent = _first_present(record, USER_AGENT_KEYS)
    app = _first_present(record, APP_KEYS)

    consumed_keys = {
        *TIMESTAMP_KEYS,
        *SOURCE_KEYS,
        *USER_KEYS,
        *RESULT_KEYS,
        *FAILURE_CODE_KEYS,
        *USER_AGENT_KEYS,
        *APP_KEYS,
    }
    metadata = {key: value for key, value in record.items() if key not in consumed_keys}

    return AuthEvent(
        timestamp=timestamp,
        src=str(src),
        user=str(user),
        result=result,
        failure_code=failure_code,
        user_agent=str(user_agent) if user_agent is not None else None,
        app=str(app) if app is not None else None,
        metadata=metadata,
    )


def normalize_events(records: Iterable[dict[str, Any] | AuthEvent]) -> list[AuthEvent]:
    events = [normalize_record(record) for record in records]
    return sorted(events, key=lambda event: event.timestamp)
