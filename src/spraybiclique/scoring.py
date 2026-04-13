from __future__ import annotations

import math
from datetime import datetime


def source_rarity_component(source_degrees: list[int]) -> float:
    if not source_degrees:
        return 0.0
    components = [max(0.0, 3.5 - math.log2(max(2, degree))) for degree in source_degrees]
    return round(sum(components) / len(components), 2)


def temporal_tightness_component(
    first_seen: datetime,
    last_seen: datetime,
    *,
    window_minutes: int,
) -> float:
    span_seconds = max(0.0, (last_seen - first_seen).total_seconds())
    max_seconds = max(60.0, float(window_minutes * 60))
    ratio = min(1.0, span_seconds / max_seconds)
    return round(2.0 * (1.0 - ratio), 2)


def success_followup_component(success_followups: int) -> float:
    return min(2.0, success_followups * 0.75)


def trusted_proxy_penalty(sources: list[str], trusted_sources: set[str]) -> tuple[float, list[str]]:
    matched = sorted(source for source in sources if source in trusted_sources)
    if not matched:
        return 0.0, []
    reasons = [f"trusted source matched: {', '.join(matched)}"]
    return 4.0, reasons


def severity_for_score(score: float) -> str:
    if score >= 8.0:
        return "high"
    if score >= 5.0:
        return "medium"
    return "low"
