from __future__ import annotations

import argparse
import json
from pathlib import Path

import uvicorn

from .api import app
from .detect import scan_events
from .meta import VERSION
from .normalize import normalize_events, parse_jsonl_text
from .report import build_markdown_summary
from .schema import ScanConfig


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="spraybiclique",
        description="Scan authentication logs for distributed biclique witnesses.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {VERSION}")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a JSONL file and print JSON or Markdown results.",
    )
    scan_parser.add_argument("input_path", help="Path to a JSONL authentication log file")
    scan_parser.add_argument(
        "--format",
        choices=("markdown", "json"),
        default="markdown",
        help="Output format",
    )
    scan_parser.add_argument("--output", help="Optional path to write the result")
    scan_parser.add_argument("--window-minutes", type=int, default=10)
    scan_parser.add_argument("--min-shared-accounts", type=int, default=4)
    scan_parser.add_argument("--max-source-degree", type=int, default=12)
    scan_parser.add_argument("--followup-success-minutes", type=int, default=15)
    scan_parser.add_argument("--min-alert-score", type=float, default=5.0)
    scan_parser.add_argument(
        "--trusted-source",
        action="append",
        default=[],
        help="Trusted source to down-rank or suppress",
    )
    scan_parser.set_defaults(handler=_run_scan)

    serve_parser = subparsers.add_parser(
        "serve",
        help="Run the local HTTP API.",
    )
    serve_parser.add_argument("--host", default="127.0.0.1")
    serve_parser.add_argument("--port", type=int, default=8000)
    serve_parser.add_argument("--reload", action="store_true")
    serve_parser.set_defaults(handler=_run_serve)

    return parser


def _build_scan_config(args: argparse.Namespace) -> ScanConfig:
    return ScanConfig(
        window_minutes=args.window_minutes,
        min_shared_accounts=args.min_shared_accounts,
        max_source_degree=args.max_source_degree,
        followup_success_minutes=args.followup_success_minutes,
        min_alert_score=args.min_alert_score,
        trusted_sources=args.trusted_source,
    )


def _render_scan_output(args: argparse.Namespace) -> str:
    input_path = Path(args.input_path)
    payload = input_path.read_text(encoding="utf-8")
    records = parse_jsonl_text(payload)
    events = normalize_events(records)
    config = _build_scan_config(args)
    alerts, stats = scan_events(events, config)

    if args.format == "json":
        body = {
            "stats": stats.model_dump(mode="json"),
            "alerts": [alert.model_dump(mode="json") for alert in alerts],
            "markdown_summary": build_markdown_summary(alerts, stats),
        }
        return json.dumps(body, indent=2)

    return build_markdown_summary(alerts, stats)


def _run_scan(args: argparse.Namespace) -> int:
    rendered = _render_scan_output(args)
    if args.output:
        Path(args.output).write_text(rendered + ("\n" if not rendered.endswith("\n") else ""), encoding="utf-8")
    else:
        print(rendered)
    return 0


def _run_serve(args: argparse.Namespace) -> int:
    uvicorn.run(app, host=args.host, port=args.port, reload=args.reload)
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.handler(args)


if __name__ == "__main__":
    raise SystemExit(main())
