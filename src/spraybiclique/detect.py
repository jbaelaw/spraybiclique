from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from itertools import combinations

from .schema import AuthEvent, AuthResult, DetectionStats, ScanConfig, SprayAlert
from .scoring import (
    severity_for_score,
    source_rarity_component,
    success_followup_component,
    temporal_tightness_component,
    trusted_proxy_penalty,
)

UNKNOWN_USER_CODES = {
    "USER_NOT_FOUND",
    "UNKNOWN_USER",
    "NO_SUCH_USER",
    "0XC0000064",
}


def _bucket_start(timestamp: datetime, window_minutes: int) -> datetime:
    minute = timestamp.minute - (timestamp.minute % window_minutes)
    return timestamp.replace(minute=minute, second=0, microsecond=0)


def _pattern_for_event(event: AuthEvent) -> tuple[str, str | None] | None:
    if event.result != AuthResult.FAILURE:
        return None

    if event.failure_code in UNKNOWN_USER_CODES:
        return "fail_unknown_user", event.failure_code

    if event.failure_code:
        return "fail_same_code", event.failure_code

    return "fail_unspecified", None


def _count_followup_successes(
    failure_times: dict[tuple[str, str], list[datetime]],
    success_times: dict[tuple[str, str], list[datetime]],
    *,
    followup_minutes: int,
) -> int:
    followup_delta = timedelta(minutes=followup_minutes)
    followups = 0

    for key, timestamps in failure_times.items():
        success_candidates = success_times.get(key, [])
        if not success_candidates:
            continue

        first_failure = min(timestamps)
        deadline = first_failure + followup_delta
        if any(first_failure < success_time <= deadline for success_time in success_candidates):
            followups += 1

    return followups


def scan_events(events: list[AuthEvent], config: ScanConfig) -> tuple[list[SprayAlert], DetectionStats]:
    if not events:
        return (
            [],
            DetectionStats(
                event_count=0,
                window_count=0,
                witness_candidates=0,
                alerts_emitted=0,
                suppressed_candidates=0,
            ),
        )

    trusted_sources = set(config.trusted_sources)
    window_groups: dict[datetime, list[AuthEvent]] = defaultdict(list)
    success_times: dict[tuple[str, str], list[datetime]] = defaultdict(list)

    for event in events:
        window_groups[_bucket_start(event.timestamp, config.window_minutes)].append(event)
        if event.result == AuthResult.SUCCESS:
            success_times[(event.src, event.user)].append(event.timestamp)

    alerts: list[SprayAlert] = []
    witness_candidates = 0
    suppressed_candidates = 0

    for window_start, window_events in sorted(window_groups.items()):
        window_end = window_start + timedelta(minutes=config.window_minutes)

        source_degree: dict[str, set[str]] = defaultdict(set)
        edges_by_pattern: dict[tuple[str, str | None], dict[str, set[str]]] = defaultdict(
            lambda: defaultdict(set)
        )
        failure_times: dict[tuple[tuple[str, str | None], str, str], list[datetime]] = defaultdict(list)

        for event in window_events:
            if event.result == AuthResult.FAILURE:
                source_degree[event.src].add(event.user)
                pattern = _pattern_for_event(event)
                if pattern is None:
                    continue
                edges_by_pattern[pattern][event.src].add(event.user)
                failure_times[(pattern, event.src, event.user)].append(event.timestamp)

        for (pattern_name, failure_code), source_map in edges_by_pattern.items():
            candidate_sources = sorted(
                source
                for source, users in source_map.items()
                if len(users) >= config.min_shared_accounts
                and len(source_degree[source]) <= config.max_source_degree
            )

            for source_a, source_b in combinations(candidate_sources, 2):
                shared_accounts = sorted(source_map[source_a] & source_map[source_b])
                if len(shared_accounts) < config.min_shared_accounts:
                    continue

                witness_candidates += 1

                relevant_failures: dict[tuple[str, str], list[datetime]] = {}
                flattened_times: list[datetime] = []
                for source in (source_a, source_b):
                    for account in shared_accounts:
                        key = ((pattern_name, failure_code), source, account)
                        timestamps = failure_times.get(key)
                        if not timestamps:
                            continue
                        relevant_failures[(source, account)] = timestamps
                        flattened_times.extend(timestamps)

                if not flattened_times:
                    continue

                success_followups = _count_followup_successes(
                    relevant_failures,
                    success_times,
                    followup_minutes=config.followup_success_minutes,
                )

                score = float(len(shared_accounts))
                score += source_rarity_component(
                    [
                        len(source_degree[source_a]),
                        len(source_degree[source_b]),
                    ]
                )
                score += temporal_tightness_component(
                    min(flattened_times),
                    max(flattened_times),
                    window_minutes=config.window_minutes,
                )
                score += success_followup_component(success_followups)
                penalty, suppression_reasons = trusted_proxy_penalty(
                    [source_a, source_b],
                    trusted_sources,
                )
                score -= penalty
                score = round(score, 2)

                if score < config.min_alert_score:
                    suppression_reasons = [*suppression_reasons, "score below alert threshold"]

                suppressed = bool(suppression_reasons)
                if suppressed:
                    suppressed_candidates += 1

                explanation = (
                    f"{source_a} and {source_b} touched {len(shared_accounts)} shared accounts "
                    f"with pattern {pattern_name}"
                )
                if failure_code:
                    explanation += f" ({failure_code})"
                if success_followups:
                    explanation += f"; {success_followups} success follow-up(s) strengthened severity"

                alert = SprayAlert(
                    window_start=window_start,
                    window_end=window_end,
                    pattern=pattern_name,
                    failure_code=failure_code,
                    sources=[source_a, source_b],
                    accounts=shared_accounts,
                    score=score,
                    severity=severity_for_score(score),
                    explanation=explanation,
                    success_followups=success_followups,
                    suppressed=suppressed,
                    suppression_reasons=suppression_reasons,
                )

                if not suppressed:
                    alerts.append(alert)

    alerts.sort(key=lambda alert: (alert.score, len(alert.accounts)), reverse=True)
    stats = DetectionStats(
        event_count=len(events),
        window_count=len(window_groups),
        witness_candidates=witness_candidates,
        alerts_emitted=len(alerts),
        suppressed_candidates=suppressed_candidates,
    )
    return alerts, stats
