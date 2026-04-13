# Changelog

All notable changes to this project are documented in this file.

## 0.9.1 - 2026-04-13

- Fixed JSON request parsing so aliased event fields such as `source_ip`, `username`, and `status` are accepted on the `POST /scan` endpoint.
- Fixed multipart configuration parsing so JSON config parts are applied correctly instead of silently falling back to default settings.
- Normalized `failure_code` values to uppercase consistently across direct model use and normalized record ingestion.
- Expanded automated coverage for JSON aliases, multipart JSON config parts, and failure-code normalization.
- Reworked repository documentation and package metadata for a clearer public release.

## 0.9 - 2026-04-13

- Initial public MVP release with `K2,4` witness detection, JSON and JSONL scan endpoints, sample data, and focused unit tests.
