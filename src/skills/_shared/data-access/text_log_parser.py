"""Config-driven text log line parsing (no user Python edits)."""

from __future__ import annotations

import json
import re
from datetime import datetime
from functools import lru_cache
from typing import Any

from dataasset_paths import DATAASSET_ROOT

BUILTIN_CATALOG = DATAASSET_ROOT / "configure" / "text-log-parsers.json"
CUSTOM_PARSERS_DIR = DATAASSET_ROOT / "parsers"

# Reuse battle-tested builtins from ssh_fetch (selected by config id only)
from ssh_fetch import parse_auth_line, parse_nginx_line  # noqa: E402

BUILTIN_HANDLERS = {
    "syslog_auth": lambda line, host, **_: parse_auth_line(line, host=host),
    "nginx_combined": lambda line, host, **_: parse_nginx_line(line, host=host),
}


@lru_cache(maxsize=1)
def load_builtin_catalog() -> dict[str, Any]:
    if not BUILTIN_CATALOG.is_file():
        return {"parsers": {}}
    with BUILTIN_CATALOG.open(encoding="utf-8") as f:
        return json.load(f)


def load_custom_parser(parser_id: str) -> dict[str, Any] | None:
    path = CUSTOM_PARSERS_DIR / f"{parser_id}.json"
    if not path.is_file():
        return None
    with path.open(encoding="utf-8") as f:
        data = json.load(f)
    if data.get("parser_id") != parser_id:
        data = {**data, "parser_id": parser_id}
    return data


def resolve_text_parser_id(
    asset: dict[str, Any],
    *,
    asset_type: str = "",
    log_path: str = "",
) -> str:
    """Parser id from asset.text_parser, else legacy path/asset_type inference."""
    tp = asset.get("text_parser")
    if isinstance(tp, str) and tp.strip():
        return tp.strip()
    if isinstance(tp, dict):
        pid = tp.get("parser_id")
        if pid:
            return str(pid)

    asset_type = asset_type or asset.get("asset_type", "")
    if asset_type == "ssh_auth" or "auth.log" in log_path or log_path.endswith("/secure"):
        return "syslog_auth"
    if asset_type == "web_access_log" or "nginx" in log_path or "access.log" in log_path:
        return "nginx_combined"
    return "raw_only"


def _parse_custom_regex(line: str, spec: dict[str, Any], *, host: str) -> dict[str, Any] | None:
    pattern = spec.get("line_regex")
    if not pattern:
        return None
    match = re.match(pattern, line.strip())
    if not match:
        return None
    event = {k: v for k, v in match.groupdict().items() if v is not None}
    ts_field = spec.get("timestamp_field")
    if ts_field and ts_field in event:
        for fmt in spec.get("timestamp_formats") or []:
            try:
                event[ts_field] = datetime.strptime(str(event[ts_field]), fmt).astimezone().isoformat()
                break
            except ValueError:
                continue
    event.setdefault("host", host)
    event["raw_line"] = line.strip()
    return event


def _parse_json_object(text: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(text)
    except json.JSONDecodeError:
        return None
    if isinstance(obj, dict):
        return obj
    return None


def _maybe_parse_nested_json_object(value: Any) -> dict[str, Any] | None:
    if isinstance(value, dict):
        return value
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8")
        except UnicodeDecodeError:
            return None
    if not isinstance(value, str):
        return None

    text = value.strip()
    if not (text.startswith("{") and text.endswith("}")):
        return None
    return _parse_json_object(text)


def _expand_json_object_fields(
    event: dict[str, Any],
    *,
    prefix: str = "",
    target: dict[str, Any] | None = None,
) -> dict[str, Any]:
    target = event if target is None else target
    for key, value in list(event.items()):
        if not isinstance(key, str):
            continue
        path = f"{prefix}.{key}" if prefix else key
        nested = _maybe_parse_nested_json_object(value)
        if nested is None:
            continue
        for nested_key, nested_value in nested.items():
            if not isinstance(nested_key, str):
                continue
            flat_key = f"{path}.{nested_key}"
            target.setdefault(flat_key, nested_value)
        _expand_json_object_fields(nested, prefix=path, target=target)
    return target


def parse_text_line(
    line: str,
    *,
    parser_id: str,
    host: str,
    asset: dict[str, Any] | None = None,
) -> dict[str, Any]:
    text = line.strip()
    if not text:
        return {"host": host, "raw_line": ""}

    if parser_id in {"json_lines", "json_lines2"}:
        obj = _parse_json_object(text)
        if obj is not None:
            obj.setdefault("host", host)
            obj.setdefault("raw_line", text)
            if parser_id == "json_lines2":
                _expand_json_object_fields(obj)
            return obj
        return {"host": host, "timestamp": None, "raw_line": text}

    handler = BUILTIN_HANDLERS.get(parser_id)
    if handler:
        parsed = handler(text, host)
        if parsed:
            return parsed
        return {"host": host, "timestamp": None, "raw_line": text}

    if parser_id == "raw_only":
        return {"host": host, "timestamp": None, "raw_line": text}

    custom = load_custom_parser(parser_id)
    if custom:
        parsed = _parse_custom_regex(text, custom, host=host)
        if parsed:
            return parsed

    # Inline regex on asset (discovery phase draft)
    if asset and isinstance(asset.get("text_parser"), dict):
        inline = dict(asset["text_parser"])
        if inline.get("line_regex"):
            parsed = _parse_custom_regex(text, inline, host=host)
            if parsed:
                return parsed

    return {"host": host, "timestamp": None, "raw_line": text}


def parse_log_lines(
    raw_output: str,
    *,
    asset: dict[str, Any],
    host: str,
    log_path: str = "",
) -> list[dict[str, Any]]:
    parser_id = resolve_text_parser_id(asset, log_path=log_path)
    events: list[dict[str, Any]] = []
    for line in raw_output.splitlines():
        if not line.strip():
            continue
        events.append(
            parse_text_line(line, parser_id=parser_id, host=host, asset=asset)
        )
    return events


def list_parser_ids() -> dict[str, str]:
    """Builtin + custom parser ids for discovery hints."""
    out: dict[str, str] = {}
    for pid, meta in load_builtin_catalog().get("parsers", {}).items():
        out[pid] = meta.get("description", "")
    if CUSTOM_PARSERS_DIR.is_dir():
        for path in sorted(CUSTOM_PARSERS_DIR.glob("*.json")):
            data = json.loads(path.read_text(encoding="utf-8"))
            pid = data.get("parser_id") or path.stem
            out[pid] = data.get("description", "custom parser")
    return out
