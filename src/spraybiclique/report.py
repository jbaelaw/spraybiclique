from __future__ import annotations

from .schema import DetectionStats, SprayAlert


def build_markdown_summary(alerts: list[SprayAlert], stats: DetectionStats) -> str:
    lines = [
        "# SprayBiclique Scan Summary",
        "",
        f"- Events scanned: {stats.event_count}",
        f"- Windows scanned: {stats.window_count}",
        f"- Witness candidates: {stats.witness_candidates}",
        f"- Alerts emitted: {stats.alerts_emitted}",
        f"- Suppressed candidates: {stats.suppressed_candidates}",
        "",
    ]

    if not alerts:
        lines.extend(
            [
                "## Alerts",
                "",
                "No alert crossed the configured threshold.",
            ]
        )
        return "\n".join(lines)

    lines.extend(["## Alerts", ""])
    for index, alert in enumerate(alerts[:10], start=1):
        lines.extend(
            [
                f"### Alert {index}",
                f"- Window: {alert.window_start.isoformat()} -> {alert.window_end.isoformat()}",
                f"- Severity: {alert.severity}",
                f"- Score: {alert.score}",
                f"- Pattern: {alert.pattern}",
                f"- Sources: {', '.join(alert.sources)}",
                f"- Accounts: {', '.join(alert.accounts)}",
                f"- Explanation: {alert.explanation}",
                "",
            ]
        )

    return "\n".join(lines).strip()
