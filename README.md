# SprayBiclique

`SprayBiclique` is a small local API for spotting distributed authentication abuse by looking for a minimum witness structure instead of relying on per-IP thresholds.

Maintained by `Team JRTI`. Current release target: `0.9`.

The detector uses a Ramsey-style graph heuristic: noisy authentication traffic always contains some structure, so the tool only raises an alert when two rare sources form a same-pattern witness over a shared account set. In the first release that witness is a `K2,4`-style biclique: two sources, four or more shared accounts, and one homogeneous failure pattern.

## Why This Is Different

- Most password spray detections ask whether one source touched many accounts.
- `SprayBiclique` asks whether multiple low-volume sources touched the same account set in the same way.
- Each alert is explainable as a concrete subgraph witness instead of a black-box anomaly score.

The project uses a practical Ramsey-style heuristic rather than formal Ramsey-bound calculations. The focus is operational value: use homogeneous witness subgraphs as the alert boundary.

## MVP Features

- Vendor-neutral JSONL authentication schema
- `K2,4` witness detection for `fail_same_code`, `fail_unknown_user`, and `fail_unspecified`
- Severity boosts for `success_after_fail`
- Trusted source suppression for shared proxies or known infrastructure
- FastAPI endpoint that returns JSON plus a Markdown summary

## Input Schema

Each JSONL record must provide these canonical fields or one of their accepted aliases:

- `timestamp` (`time`, `ts`)
- `src` (`source`, `source_ip`, `client_ip`, `ip`)
- `user` (`username`, `account`, `target_user`, `principal`)
- `result` (`status`, `outcome`) with values like `success`, `failure`, `ok`, `failed`

Optional fields:

- `failure_code`
- `user_agent`
- `app`

Example:

```json
{"timestamp":"2026-04-13T09:00:00Z","src":"203.0.113.10","user":"alice","result":"failure","failure_code":"INVALID_PASSWORD","user_agent":"curl/8.0"}
```

## Run Locally

```bash
python -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
uvicorn spraybiclique.api:app --reload
```

The API will be available at `http://127.0.0.1:8000`.

## Scan With JSON

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
        "timestamp": "2026-04-13T09:00:00Z",
        "src": "203.0.113.10",
        "user": "alice",
        "result": "failure",
        "failure_code": "INVALID_PASSWORD"
      }
    ]
  }'
```

## Scan With JSONL Upload

```bash
curl -X POST "http://127.0.0.1:8000/scan" \
  -F "file=@examples/auth_sample.jsonl" \
  -F 'config={"window_minutes":10,"min_shared_accounts":4};type=application/json'
```

## Sample Alert Shape

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

## Detection Logic

1. Normalize incoming auth events into a common schema.
2. Slice events into short windows.
3. Color each failure edge by a coarse auth pattern.
4. Build a source-account bipartite graph per window.
5. Emit an alert when two low-degree sources share at least four accounts under one homogeneous pattern.

## Repository Layout

```text
src/spraybiclique/api.py
src/spraybiclique/schema.py
src/spraybiclique/normalize.py
src/spraybiclique/detect.py
src/spraybiclique/scoring.py
src/spraybiclique/report.py
examples/auth_sample.jsonl
tests/test_detect.py
```
