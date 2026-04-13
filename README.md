# SprayBiclique

[![CI](https://github.com/jbaelaw/spraybiclique/actions/workflows/ci.yml/badge.svg)](https://github.com/jbaelaw/spraybiclique/actions/workflows/ci.yml)

Explainable biclique witness detection for distributed authentication abuse.

Maintained by `Team JRTI`. Current release target: `0.10.0`.

## Overview

`SprayBiclique` is a small local API that detects distributed password spray and related authentication abuse by searching for a minimum witness structure instead of relying on per-source volume thresholds.

The detector uses a Ramsey-style graph heuristic in an operational sense. Authentication traffic is noisy and naturally forms some structure, so the scanner only emits an alert when two low-degree sources create a homogeneous witness over a shared set of accounts. In the current release that witness is a `K2,4`-style biclique: two sources, four or more shared accounts, and one consistent failure pattern.

## Detection Model

`SprayBiclique` processes each short time window as a source-account bipartite graph.

- Nodes:
  - Source nodes represent IPs, devices, or upstream source buckets.
  - Account nodes represent target identities.
- Edge patterns:
  - `fail_same_code`
  - `fail_unknown_user`
  - `fail_unspecified`
- Witness rule:
  - Raise a candidate when two low-degree sources share at least four accounts under one edge pattern.
- Score components:
  - witness size
  - source rarity
  - temporal tightness
  - optional `success_after_fail` follow-up boost
  - trusted-source suppression

This project does not attempt formal Ramsey-bound computation. The practical contribution is the alert boundary: a homogeneous witness subgraph that is small, explainable, and suitable for investigation.

## Why It Is Different

- Traditional password spray analytics usually focus on one source touching many accounts.
- `SprayBiclique` focuses on multiple low-volume sources touching the same account set in the same way.
- Each alert is directly explainable as a witness subgraph instead of a black-box anomaly score.

## Interfaces

`SprayBiclique` can be used in two ways.

- CLI
  - scan a JSONL file directly from the terminal
  - write JSON or Markdown results to stdout or a file
- HTTP API
  - run a local FastAPI service for integrations or ad hoc uploads

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

## CLI

### Scan a JSONL file

```bash
spraybiclique scan examples/auth_sample.jsonl
```

### Emit JSON instead of Markdown

```bash
spraybiclique scan examples/auth_sample.jsonl --format json
```

### Write scan output to a file

```bash
spraybiclique scan examples/auth_sample.jsonl --output report.md
```

### Run the API service

```bash
spraybiclique serve --host 127.0.0.1 --port 8000
```

## API

### Endpoints

- `GET /`
  - Returns service metadata, version, and useful endpoint paths.
- `GET /health`
  - Returns service status, service name, and version.
- `POST /scan`
  - Accepts either JSON events or a JSONL file upload.
  - Returns structured alert data plus a Markdown summary.

### Supported Request Types

- `application/json`
  - Body shape: `{ "events": [...], "config": {...} }`
  - Event aliases are accepted in this path.
- `multipart/form-data`
  - Required form field: `file`
  - Optional form field: `config`
  - `config` may be submitted as a text JSON string or as a JSON part.

## Input Schema

Each event must contain the following fields, either in canonical form or through one of the accepted aliases.

- `timestamp`
  - aliases: `time`, `ts`
- `src`
  - aliases: `source`, `source_ip`, `client_ip`, `ip`
- `user`
  - aliases: `username`, `account`, `target_user`, `principal`
- `result`
  - aliases: `status`, `outcome`
  - accepted normalized values include `success`, `failure`, `ok`, `failed`

Optional fields:

- `failure_code`
- `user_agent`
- `app`

Example event:

```json
{
  "timestamp": "2026-04-13T09:00:00Z",
  "src": "203.0.113.10",
  "user": "alice",
  "result": "failure",
  "failure_code": "INVALID_PASSWORD",
  "user_agent": "curl/8.0",
  "app": "vpn"
}
```

## Output

The `POST /scan` response contains three top-level fields.

- `stats`
  - counts for scanned events, windows, witness candidates, emitted alerts, and suppressed candidates
- `alerts`
  - the final unsuppressed witness alerts
- `markdown_summary`
  - a ready-to-share text summary of the scan

Sample alert:

```json
{
  "window_start": "2026-04-13T09:00:00Z",
  "window_end": "2026-04-13T09:10:00Z",
  "pattern": "fail_same_code",
  "failure_code": "INVALID_PASSWORD",
  "sources": ["203.0.113.10", "203.0.113.11"],
  "accounts": ["alice", "bob", "carol", "dave"],
  "score": 7.55,
  "severity": "medium",
  "explanation": "203.0.113.10 and 203.0.113.11 touched 4 shared accounts with pattern fail_same_code (INVALID_PASSWORD); 1 success follow-up(s) strengthened severity"
}
```

## Quick Start

```bash
spraybiclique serve --host 127.0.0.1 --port 8000
```

The API is then available at `http://127.0.0.1:8000`.

### Scan With JSON

```bash
curl -X POST "http://127.0.0.1:8000/scan" \
  -H "Content-Type: application/json" \
  -d '{
    "config": {
      "window_minutes": 10,
      "min_shared_accounts": 4,
      "trusted_sources": ["198.51.100.10"]
    },
    "events": [
      {
        "time": "2026-04-13T09:00:00Z",
        "source_ip": "203.0.113.10",
        "username": "alice",
        "status": "failed",
        "reason": "invalid_password"
      }
    ]
  }'
```

### Scan With JSONL Upload

```bash
curl -X POST "http://127.0.0.1:8000/scan" \
  -F "file=@examples/auth_sample.jsonl" \
  -F 'config={"window_minutes":10,"min_shared_accounts":4}'
```

## Operational Notes

- Shared proxies, NAT gateways, and SSO outages can still create misleading structure if they are not allowlisted.
- The current release is intentionally narrow: `K2,4` witnesses, a small set of failure patterns, and short-window batch analysis.
- This service is designed as a triage aid, not a replacement for full SIEM correlation or identity analytics.

## Development

Run the local test suite with:

```bash
source .venv/bin/activate
pytest
```

## Continuous Integration

GitHub Actions runs the test suite on Python `3.11`, `3.12`, and `3.13` for pushes and pull requests targeting `main`.

## Repository Layout

```text
CHANGELOG.md
.github/workflows/ci.yml
src/spraybiclique/api.py
src/spraybiclique/cli.py
src/spraybiclique/meta.py
src/spraybiclique/schema.py
src/spraybiclique/normalize.py
src/spraybiclique/detect.py
src/spraybiclique/scoring.py
src/spraybiclique/report.py
examples/auth_sample.jsonl
tests/test_detect.py
```
