from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AuthResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"


class AuthEvent(BaseModel):
    """Canonical event shape used by the detector."""

    model_config = ConfigDict(extra="allow", str_strip_whitespace=True)

    timestamp: datetime
    src: str = Field(..., description="Source IP, device, or source bucket")
    user: str = Field(..., description="Target account identifier")
    result: AuthResult
    failure_code: str | None = Field(
        default=None,
        description="Auth failure code or category when result=failure",
    )
    user_agent: str | None = None
    app: str | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)

    @field_validator("result", mode="before")
    @classmethod
    def normalize_result(cls, value: Any) -> Any:
        if isinstance(value, str):
            normalized = value.strip().lower()
            if normalized in {"ok", "succeeded"}:
                return AuthResult.SUCCESS
            if normalized in {"fail", "failed", "error"}:
                return AuthResult.FAILURE
            return normalized
        return value

    @field_validator("failure_code", mode="before")
    @classmethod
    def normalize_failure_code(cls, value: Any) -> Any:
        if value is None:
            return None
        normalized = str(value).strip()
        return normalized.upper() or None


class ScanConfig(BaseModel):
    window_minutes: int = Field(default=10, ge=1, le=60)
    min_shared_accounts: int = Field(default=4, ge=2, le=20)
    max_source_degree: int = Field(
        default=12,
        ge=2,
        le=100,
        description="Ignore sources that already touch too many unique accounts in-window",
    )
    followup_success_minutes: int = Field(default=15, ge=1, le=120)
    min_alert_score: float = Field(default=5.0, ge=0, le=100)
    trusted_sources: list[str] = Field(default_factory=list)


class ScanRequest(BaseModel):
    events: list[AuthEvent]
    config: ScanConfig = Field(default_factory=ScanConfig)


class DetectionStats(BaseModel):
    event_count: int
    window_count: int
    witness_candidates: int
    alerts_emitted: int
    suppressed_candidates: int


class SprayAlert(BaseModel):
    window_start: datetime
    window_end: datetime
    pattern: str
    failure_code: str | None = None
    sources: list[str]
    accounts: list[str]
    score: float
    severity: str
    explanation: str
    success_followups: int = 0
    suppressed: bool = False
    suppression_reasons: list[str] = Field(default_factory=list)


class ScanResponse(BaseModel):
    stats: DetectionStats
    alerts: list[SprayAlert]
    markdown_summary: str
