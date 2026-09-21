"""Shared helpers for connector-specific fetch modules."""

from __future__ import annotations

import datetime as dt
import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from http_fetch import _extract_events
from http_transport import open_secure_request
from text_log_parser import parse_log_lines

REPO_ROOT = Path(__file__).resolve().parents[4]


def auth_headers(credentials: dict[str, Any]) -> dict[str, str]:
    token = credentials.get("token") or credentials.get("access_token") or credentials.get("api_key")
    if not token:
        return {}
    scheme = credentials.get("auth_scheme") or "Bearer"
    return {"Authorization": f"{scheme} {token}"}


def post_json(
    url: str,
    payload: dict[str, Any],
    credentials: dict[str, Any],
    *,
    timeout: int,
    transport_config: dict[str, Any] | None = None,
    label: str = "external executor endpoint",
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """POST JSON without forwarding connector credentials across redirects."""
    headers = {"Accept": "application/json", "Content-Type": "application/json"}
    headers.update(auth_headers(credentials))
    data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    request = urllib.request.Request(url, data=data, headers=headers, method="POST")
    try:
        with open_secure_request(
            request,
            timeout=timeout,
            config=transport_config,
            label=label,
        ) as response:
            raw = response.read().decode("utf-8")
            status = response.status
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {err_body[:500]}") from exc

    try:
        body = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"response is not JSON: {raw[:200]}") from exc

    events = _extract_events(body)
    return events, {"url": url, "http_status": status, "rows_returned": len(events)}


def json_bytes(payload: Any) -> bytes:
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def http_request(
    url: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: bytes | None = None,
    timeout: int,
    transport_config: dict[str, Any] | None = None,
    label: str = "connector endpoint",
) -> tuple[int, bytes]:
    """Issue one non-redirecting HTTPS or loopback HTTP request."""
    request = urllib.request.Request(url, data=body, headers=headers or {}, method=method)
    try:
        with open_secure_request(
            request,
            timeout=timeout,
            config=transport_config,
            label=label,
        ) as response:
            return response.status, response.read()
    except urllib.error.HTTPError as exc:
        err_body = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"HTTP {exc.code}: {err_body[:500]}") from exc


def http_json_request(
    url: str,
    payload: dict[str, Any] | None = None,
    *,
    method: str = "POST",
    headers: dict[str, str] | None = None,
    timeout: int,
    transport_config: dict[str, Any] | None = None,
    label: str = "connector endpoint",
) -> tuple[dict[str, Any], int]:
    body = json_bytes(payload or {}) if payload is not None else None
    provided_headers = headers or {}
    provided_lower = {key.lower() for key in provided_headers}
    request_headers: dict[str, str] = {}
    if "accept" not in provided_lower:
        request_headers["Accept"] = "application/json"
    if body is not None and "content-type" not in provided_lower:
        request_headers["Content-Type"] = "application/json"
    request_headers.update(provided_headers)
    status, raw = http_request(
        url,
        method=method,
        headers=request_headers,
        body=body,
        timeout=timeout,
        transport_config=transport_config,
        label=label,
    )
    text = raw.decode("utf-8", errors="replace")
    try:
        parsed = json.loads(text) if text else {}
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"response is not JSON: {text[:200]}") from exc
    if not isinstance(parsed, dict):
        raise RuntimeError(f"response JSON root is not an object: {text[:200]}")
    return parsed, status


def int_value(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def request_timeout(connector: dict[str, Any], default: int = 60) -> int:
    return int_value((connector.get("constraints") or {}).get("request_timeout_sec"), default)


def max_rows(connector: dict[str, Any], params: dict[str, Any], default: int = 1000) -> int:
    return int_value(params.get("limit") or (connector.get("constraints") or {}).get("max_records_per_request"), default)


def time_to_datetime(value: Any, default: dt.datetime) -> dt.datetime:
    text = str(value or "").strip()
    if not text:
        return default
    if text.isdigit():
        number = int(text)
        if number > 10_000_000_000:
            number //= 1000
        return dt.datetime.fromtimestamp(number, tz=dt.timezone.utc)
    try:
        parsed = dt.datetime.fromisoformat(text.replace("Z", "+00:00"))
    except ValueError:
        return default
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed.astimezone(dt.timezone.utc)


def epoch_seconds(value: Any, default: dt.datetime) -> int:
    return int(time_to_datetime(value, default).timestamp())


def epoch_millis(value: Any, default: dt.datetime) -> int:
    return epoch_seconds(value, default) * 1000


def time_defaults(params: dict[str, Any]) -> tuple[dt.datetime, dt.datetime]:
    now = dt.datetime.now(dt.timezone.utc)
    start = time_to_datetime(params.get("time_start"), now - dt.timedelta(hours=1))
    end = time_to_datetime(params.get("time_end"), now)
    return start, end


def first_non_empty(*values: Any) -> str:
    for value in values:
        text = str(value or "").strip()
        if text:
            return text
    return ""


def public_config(config: dict[str, Any]) -> dict[str, Any]:
    blocked = ("secret", "password", "token", "key")
    return {k: v for k, v in config.items() if not any(word in k.lower() for word in blocked)}


def external_executor_endpoint(config: dict[str, Any]) -> str:
    return str(config.get("executor_endpoint") or config.get("external_endpoint") or "").rstrip("/")


def planned_meta(
    connector: dict[str, Any],
    query: str,
    params: dict[str, Any],
    note: str,
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    return [], {
        "mode": "planned",
        "backend": connector.get("connector_type"),
        "query": query,
        "params": {k: params.get(k) for k in ("time_start", "time_end", "limit")},
        "note": note,
    }


def resolve_repo_path(value: Any) -> Path | None:
    text = str(value or "").strip()
    if not text:
        return None
    path = Path(text)
    if not path.is_absolute():
        path = REPO_ROOT / path
    return path.resolve()


def candidate_sample_paths(config: dict[str, Any]) -> list[Path]:
    paths: list[Path] = []
    for key in ("sample_file", "sample_path", "path"):
        path = resolve_repo_path(config.get(key))
        if path:
            paths.append(path)
    for key in ("sample_dir", "base_path"):
        path = resolve_repo_path(config.get(key))
        if path:
            paths.append(path)
    bucket = resolve_repo_path(config.get("bucket"))
    prefix = str(config.get("prefix") or "").strip()
    if bucket and bucket.exists():
        paths.append((bucket / prefix).resolve() if prefix else bucket)
    return paths


def iter_sample_files(paths: list[Path]) -> list[Path]:
    files: list[Path] = []
    suffixes = {".json", ".jsonl", ".ndjson", ".log", ".txt"}
    for path in paths:
        if path.is_file():
            files.append(path)
        elif path.is_dir():
            files.extend(sorted(item for item in path.rglob("*") if item.is_file() and item.suffix.lower() in suffixes))
    return files


def event_matches_params(event: dict[str, Any], params: dict[str, Any]) -> bool:
    src_ip = params.get("src_ip") or params.get("client_ip") or params.get("ip")
    if src_ip:
        values = {str(event.get(key) or "") for key in ("src_ip", "client_ip", "sourceIPAddress", "source_ip", "ip")}
        if str(src_ip) not in values and str(src_ip) not in json.dumps(event, ensure_ascii=False):
            return False
    host = params.get("host") or params.get("host_ip") or params.get("host_name")
    if host and str(host) not in {str(event.get(key) or "") for key in ("host", "host_ip", "hostname", "host_name")}:
        if str(host) not in json.dumps(event, ensure_ascii=False):
            return False
    return True


def parse_sample_file(path: Path, connector: dict[str, Any]) -> list[dict[str, Any]]:
    raw = path.read_text(encoding="utf-8", errors="replace")
    if path.suffix.lower() == ".json":
        try:
            payload = json.loads(raw)
        except json.JSONDecodeError:
            payload = None
        if payload is not None:
            return _extract_events(payload)
    events: list[dict[str, Any]] = []
    for line in raw.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            events.append(parsed)
        else:
            events.extend(parse_log_lines(text, asset={"text_parser": "raw_only"}, host=str((connector.get("config") or {}).get("host") or "sample")))
    return events


def parse_text_payload(raw: str, connector: dict[str, Any], *, source: str = "") -> list[dict[str, Any]]:
    stripped = raw.strip()
    if not stripped:
        return []
    try:
        payload = json.loads(stripped)
    except json.JSONDecodeError:
        payload = None
    if payload is not None:
        return _extract_events(payload)

    events: list[dict[str, Any]] = []
    for line in raw.splitlines():
        text = line.strip()
        if not text:
            continue
        try:
            parsed = json.loads(text)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            row = dict(parsed)
            if source:
                row.setdefault("_source", source)
            events.append(row)
        else:
            events.extend(
                parse_log_lines(
                    text,
                    asset={"text_parser": "raw_only"},
                    host=str((connector.get("config") or {}).get("host") or source or "log"),
                )
            )
    return events


def fetch_local_samples(
    connector: dict[str, Any],
    query: str,
    params: dict[str, Any],
) -> tuple[list[dict[str, Any]], dict[str, Any]] | None:
    config = connector.get("config") or {}
    files = iter_sample_files(candidate_sample_paths(config))
    if not files:
        return None
    row_limit = max_rows(connector, params)
    events: list[dict[str, Any]] = []
    for path in files:
        for event in parse_sample_file(path, connector):
            if event_matches_params(event, params):
                row = dict(event)
                row.setdefault("_sample_file", str(path))
                events.append(row)
                if len(events) >= row_limit:
                    return events, {
                        "mode": "local_sample",
                        "backend": connector.get("connector_type"),
                        "query": query,
                        "sample_files": [str(item) for item in files],
                        "rows_returned": len(events),
                    }
    return events, {
        "mode": "local_sample",
        "backend": connector.get("connector_type"),
        "query": query,
        "sample_files": [str(item) for item in files],
        "rows_returned": len(events),
    }
