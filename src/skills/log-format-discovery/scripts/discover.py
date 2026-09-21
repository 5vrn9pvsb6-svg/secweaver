#!/usr/bin/env python3
"""Offline log format discovery: analyze samples vs evidence spec, draft field mappings."""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

SKILL_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = SKILL_ROOT.parents[2]
DATA_ACCESS = REPO_ROOT / "src" / "skills" / "_shared" / "data-access"
if str(DATA_ACCESS) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS))
from dataasset_paths import DATAASSET_ROOT, format_path  # noqa: E402

DATAASSET = DATAASSET_ROOT
EVIDENCE_SPEC = DATAASSET / "configure" / "evidence-minimum-fields.json"
CUSTOM_PARSERS_DIR = DATAASSET / "parsers"
PARSER_ID_RE = re.compile(r"^[A-Za-z][A-Za-z0-9_.-]*$")


def derived_correlation_keys(asset: dict[str, Any]) -> list[str]:
    try:
        from correlation_keys import derive_correlation_keys

        return derive_correlation_keys(asset)
    except Exception:
        return []


IPV4 = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
AUTH_HEADER = re.compile(
    r"^(?P<month>\w{3})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})\s+"
    r"(?P<host>\S+)\s+sshd(?:\[\d+\])?:\s+"
    r"(?P<result>Accepted|Failed|Invalid|Disconnected|Connection closed|error|fatal)\b"
)
NGINX = re.compile(
    r'^(?P<src_ip>\S+)\s+\S+\s+\S+\s+\[(?P<ts>[^\]]+)\]\s+'
    r'"(?P<method>\S+)\s+(?P<url>\S+)\s+\S+"\s+(?P<status>\d+)'
)
KV_PAIR = re.compile(r"(\w+)[=:]([^\s,|]+)")


def load_evidence_spec() -> dict[str, Any]:
    with EVIDENCE_SPEC.open(encoding="utf-8") as f:
        return json.load(f)


def load_samples(*, input_path: str | None, text: str | None) -> list[str]:
    if text is not None:
        raw = text
    elif input_path:
        raw = Path(input_path).read_text(encoding="utf-8")
    elif not sys.stdin.isatty():
        raw = sys.stdin.read()
    else:
        raise SystemExit("no samples: use -i file, --text, or pipe stdin")

    raw = raw.strip()
    if not raw:
        return []

    if raw.startswith("["):
        try:
            arr = json.loads(raw)
            if isinstance(arr, list):
                return [json.dumps(x, ensure_ascii=False) if isinstance(x, dict) else str(x) for x in arr]
        except json.JSONDecodeError:
            pass

    return [ln for ln in raw.splitlines() if ln.strip()]


def detect_format(lines: list[str]) -> str:
    if not lines:
        return "empty"
    json_hits = 0
    auth_hits = 0
    nginx_hits = 0
    for line in lines[: min(50, len(lines))]:
        s = line.strip()
        if s.startswith("{") and s.endswith("}"):
            try:
                json.loads(s)
                json_hits += 1
                continue
            except json.JSONDecodeError:
                pass
        if AUTH_HEADER.match(s):
            auth_hits += 1
        if NGINX.match(s):
            nginx_hits += 1
    if json_hits >= max(1, len(lines) // 2):
        return "json_lines"
    if auth_hits >= max(1, len(lines) // 3):
        return "syslog_auth"
    if nginx_hits >= max(1, len(lines) // 3):
        return "nginx_combined"
    return "text_unknown"


def parse_json_line(line: str) -> dict[str, Any] | None:
    try:
        obj = json.loads(line)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        return None


def collect_json_keys(lines: list[str]) -> Counter[str]:
    keys: Counter[str] = Counter()
    for line in lines:
        obj = parse_json_line(line)
        if obj:
            for k in obj:
                keys[k] += 1
    return keys


def parse_auth_preview(line: str) -> dict[str, Any]:
    text = line.strip()
    m = AUTH_HEADER.match(text)
    if not m:
        return {"raw_line": text}
    g = m.groupdict()
    user_m = re.search(r"for (?:invalid user )?(\S+)(?:\s+from|\s|$)", text)
    ip_m = re.search(r"from (\d{1,3}(?:\.\d{1,3}){3})", text)
    return {
        "host": g.get("host"),
        "result": g.get("result"),
        "user": user_m.group(1) if user_m else None,
        "src_ip": ip_m.group(1) if ip_m else None,
        "timestamp": f"{g.get('month')} {g.get('day')} {g.get('time')}",
        "raw_line": text,
    }


def parse_nginx_preview(line: str) -> dict[str, Any]:
    m = NGINX.match(line.strip())
    if not m:
        return {"raw_line": line.strip()}
    g = m.groupdict()
    return {
        "src_ip": g["src_ip"],
        "url": g["url"],
        "method": g["method"],
        "status": int(g["status"]),
        "timestamp": g["ts"],
        "raw_line": line.strip(),
    }


def preview_events(lines: list[str], fmt: str) -> list[dict[str, Any]]:
    events: list[dict[str, Any]] = []
    for line in lines[:20]:
        if fmt == "json_lines":
            obj = parse_json_line(line)
            events.append(obj or {"raw_line": line.strip()})
        elif fmt == "syslog_auth":
            events.append(parse_auth_preview(line))
        elif fmt == "nginx_combined":
            events.append(parse_nginx_preview(line))
        else:
            events.append({"raw_line": line.strip(), "_kv": dict(KV_PAIR.findall(line))})
    return events


def canonical_requirements(spec: dict[str, Any], asset_type: str) -> dict[str, list[str]]:
    by_type = spec.get("by_asset_type", {}).get(asset_type, {})
    common = list(spec.get("common_required") or [])
    return {
        "required": common + list(by_type.get("required") or []),
        "strongly_recommended": list(by_type.get("strongly_recommended") or []),
        "recommended": list(by_type.get("recommended") or []),
    }


def apply_existing_aliases(event: dict[str, Any], aliases: dict[str, str]) -> dict[str, Any]:
    out = dict(event)
    for src, dst in aliases.items():
        if src in out and dst not in out:
            out[dst] = out[src]
    return out


def infer_aliases_from_keys(
    key_counts: Counter[str],
    requirements: dict[str, list[str]],
    existing_aliases: dict[str, str],
) -> dict[str, str]:
    """Heuristic alias suggestions (source -> canonical)."""
    canonical = set(requirements["required"] + requirements["strongly_recommended"] + requirements["recommended"])
    proposed: dict[str, str] = {}
    synonym_map = {
        "src_ip": ["client_ip", "remote_addr", "remoteHost", "remote_ip", "ip", "source_ip", "c-ip"],
        "timestamp": ["@timestamp", "__time__", "time", "ts", "event_time", "log_time"],
        "url": ["request_uri", "uri", "path", "request_url", "http_url"],
        "host": ["hostname", "server", "dst_host", "machine"],
        "user": ["username", "account", "login_user"],
        "result": ["status", "auth_result", "login_result"],
        "action": ["rule_action", "waf_action", "disposition"],
        "command": ["cmd", "argv", "process_cmd", "exec_command"],
        "dst_ip": ["dest_ip", "destination_ip", "target_ip"],
    }
    observed = set(key_counts.keys())
    for canon, syns in synonym_map.items():
        if canon not in canonical:
            continue
        for syn in syns:
            if syn in observed and syn not in existing_aliases:
                proposed[syn] = canon
    for key in observed:
        if key in canonical or key in proposed or key in existing_aliases.values():
            continue
        lower = key.lower()
        for canon in canonical:
            if canon in lower or lower in canon:
                proposed[key] = canon
                break
    return proposed


def gap_analysis(
    preview: list[dict[str, Any]],
    requirements: dict[str, list[str]],
    aliases: dict[str, str],
) -> dict[str, Any]:
    all_fields: set[str] = set()
    for ev in preview:
        mapped = apply_existing_aliases(ev, aliases)
        all_fields.update(mapped.keys())

    def missing(level: str) -> list[str]:
        return [f for f in requirements[level] if f not in all_fields and f != "evidence_id"]

    return {
        "missing_required": missing("required"),
        "missing_strongly_recommended": missing("strongly_recommended"),
        "missing_recommended": missing("recommended"),
        "present_after_alias_preview": sorted(all_fields),
    }


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def list_discovery_assets() -> list[dict[str, Any]]:
    """Assets with status=discovery (format discovery queue only)."""
    assets: list[dict[str, Any]] = []
    assets_dir = DATAASSET / "assets"
    if not assets_dir.is_dir():
        return assets
    for path in sorted(assets_dir.glob("*.json")):
        asset = _load_json(path)
        if asset.get("status") == "discovery":
            assets.append(asset)
    return assets


def load_discovery_asset(asset_id: str, *, allow_any_status: bool = False) -> dict[str, Any]:
    path = DATAASSET / "assets" / f"{asset_id}.json"
    if not path.is_file():
        raise FileNotFoundError(f"asset not found: {asset_id}")
    asset = _load_json(path)
    if not allow_any_status and asset.get("status") != "discovery":
        raise ValueError(
            f"asset {asset_id!r} status={asset.get('status')!r}; "
            "log-format-discovery only processes status=discovery"
        )
    return asset


def load_dataasset_context(*, asset_id: str, allow_any_status: bool = False) -> dict[str, Any]:
    """Load a single asset, its connector, and matching templates."""
    asset = load_discovery_asset(asset_id, allow_any_status=allow_any_status)
    asset_type = asset.get("asset_type", "")
    schema = asset.get("schema", {})
    conn_id = asset.get("connector_id", "")
    connector: dict[str, Any] | None = None
    connector_type: str | None = None
    conn_path = DATAASSET / "connectors" / f"{conn_id}.json"
    if conn_id and conn_path.is_file():
        connector = _load_json(conn_path)
        connector_type = connector.get("connector_type")

    discovery_asset = {
        "asset_id": asset.get("asset_id"),
        "name": asset.get("name"),
        "status": asset.get("status"),
        "asset_type": asset_type,
        "connector_id": conn_id,
        "connector_type": connector_type,
        "connector_ids": asset.get("connector_ids", []),
        "fields": schema.get("fields", []),
        "derived_correlation_keys": derived_correlation_keys(asset),
        "time_field": schema.get("time_field"),
        "retention_days": schema.get("retention_days"),
        "query_template_ids": asset.get("query_template_ids", []),
        "masking": asset.get("masking", {}),
        "description": asset.get("description"),
    }

    matching_templates: list[dict[str, Any]] = []
    templates_path = DATAASSET / "query-templates" / "templates.json"
    if templates_path.is_file() and asset_type:
        catalog = _load_json(templates_path)
        for template_id, template in catalog.get("templates", {}).items():
            if asset_type not in template.get("asset_types", []):
                continue
            conn_types = template.get("connector_types", [])
            if connector_type and connector_type not in conn_types:
                continue
            matching_templates.append(
                {
                    "template_id": template_id,
                    "connector_types": conn_types,
                    "params": template.get("params", []),
                    "defaults": template.get("defaults", {}),
                    "has_sls_query": bool(template.get("sls_query")),
                    "has_ssh_command": bool(template.get("ssh_command")),
                    "has_sql": bool(template.get("sql")),
                    "has_es_query": bool(template.get("es_query")),
                }
            )

    return {
        "dataasset_root": format_path(DATAASSET),
        "discovery_asset": discovery_asset,
        "connector": (
            {
                "connector_id": connector.get("connector_id"),
                "connector_type": connector_type,
                "status": connector.get("status"),
            }
            if connector
            else None
        ),
        "matching_templates": matching_templates,
        "discovery_queue_count": len(list_discovery_assets()),
    }


def suggest_from_discovery_asset(dataasset_ctx: dict[str, Any]) -> dict[str, Any]:
    """Hints from the single discovery asset (no other dataasset assets)."""
    asset = dataasset_ctx.get("discovery_asset") or {}
    if not asset:
        return {"note": "no discovery asset loaded"}
    return {
        "asset_id": asset.get("asset_id"),
        "current_fields": asset.get("fields") or [],
        "derived_correlation_keys": asset.get("derived_correlation_keys")
        or derived_correlation_keys(asset),
        "current_template_ids": asset.get("query_template_ids") or [],
        "connector_type": asset.get("connector_type"),
    }


def build_template_hint(
    asset_type: str,
    connector_type: str | None,
    fmt: str,
    dataasset_ctx: dict[str, Any] | None = None,
) -> dict[str, Any]:
    hints: dict[str, Any] = {"connector_type": connector_type or "unknown"}
    matching = (dataasset_ctx or {}).get("matching_templates") or []
    if matching:
        hints["existing_templates_in_dataasset"] = matching
    elif connector_type == "sls":
        hints["suggest_add_to_templates_json"] = {
            "note": "Add sls_query with filters on mapped canonical fields",
            "example_params": ["src_ip", "time_start", "time_end", "limit"],
        }
    elif connector_type == "ssh_file":
        hints["suggest_add_to_templates_json"] = {
            "template_id": "ssh_file_grep_auth",
            "ssh_command": "grep -E '{grep_pattern}' {log_path} | tail -n {max_lines}",
        }
    elif connector_type == "local_file":
        hints["suggest_add_to_templates_json"] = {
            "template_id": "local_file_grep_auth",
            "local_file_command": "grep -E '{grep_pattern}' {log_path} | tail -n {max_lines}",
        }
    elif connector_type == "es":
        hints["suggest_add_to_templates_json"] = {
            "note": "Add es_query DSL with {src_ip} {time_start} {time_end} placeholders",
            "example_template_id": "waf_es_by_src_ip_time",
        }
    if fmt == "syslog_auth":
        hints["text_parser"] = "asset.text_parser: syslog_auth（内置，见 configure/text-log-parsers.json）"
    elif fmt == "nginx_combined":
        hints["text_parser"] = "asset.text_parser: nginx_combined"
    elif fmt == "json_lines":
        hints["text_parser"] = "asset.text_parser: json_lines；字段别名见 evidence-minimum-fields.json"
    elif fmt == "text_unknown":
        hints["text_parser"] = "新增 dataasset/parsers/<id>.json 或 asset.text_parser 内联 line_regex"
    hints["available_parsers"] = "dataasset/configure/text-log-parsers.json + dataasset/parsers/"
    return hints


def safe_parser_id(value: str) -> str:
    parser_id = str(value or "").strip()
    if not PARSER_ID_RE.fullmatch(parser_id):
        raise SystemExit(f"parser_id must match {PARSER_ID_RE.pattern}: {value!r}")
    return parser_id


def default_parser_id(asset_id: str) -> str:
    slug = re.sub(r"[^A-Za-z0-9_.-]+", "-", asset_id.strip()).strip("-")
    if not slug:
        slug = "custom-log"
    if not slug[0].isalpha():
        slug = f"p-{slug}"
    return f"{slug}-parser"


def _group_name(value: str, used: set[str]) -> str:
    name = re.sub(r"\W+", "_", value).strip("_")
    if not name or name[0].isdigit():
        name = f"field_{name or 'value'}"
    base = name
    index = 2
    while name in used:
        name = f"{base}_{index}"
        index += 1
    used.add(name)
    return name


def infer_custom_parser_draft(
    *,
    parser_id: str,
    lines: list[str],
    description: str | None = None,
) -> dict[str, Any]:
    sample = next((line.strip() for line in lines if line.strip()), "")
    used: set[str] = set()
    kv_pairs = [(key, value) for key, value in KV_PAIR.findall(sample) if key]
    timestamp_formats: list[str] = []
    prefix = "^"
    if re.match(r"\d{4}-\d{2}-\d{2}T", sample):
        used.add("timestamp")
        prefix = r"^(?P<timestamp>\d{4}-\d{2}-\d{2}T[^\s]+)"
        timestamp_formats = ["%Y-%m-%dT%H:%M:%S.%f%z", "%Y-%m-%dT%H:%M:%S%z"]
    elif re.match(r"\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}", sample):
        used.add("timestamp")
        prefix = r"^(?P<timestamp>\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2})"
        timestamp_formats = ["%Y-%m-%d %H:%M:%S"]

    if kv_pairs:
        pattern = prefix
        field_hints = ["timestamp"] if "timestamp" in used else []
        for key, _value in kv_pairs[:12]:
            group = _group_name(key, used)
            field_hints.append(group)
            pattern += rf".*?{re.escape(key)}[=:](?P<{group}>[^\s,|]+)"
        pattern += r".*$"
    else:
        pattern = r"^(?P<raw_line>.*)$"
        field_hints = ["raw_line"]

    draft: dict[str, Any] = {
        "parser_id": parser_id,
        "description": description or "Generated text parser draft. Review line_regex before promoting the asset.",
        "line_regex": pattern,
        "timestamp_field": "timestamp" if "timestamp" in field_hints else "",
        "timestamp_formats": timestamp_formats,
        "generated_field_hints": field_hints,
        "sample_lines": lines[:3],
        "generated_by": {
            "skill": "log-format-discovery",
            "note": "Draft only; adjust named capture groups to canonical fields or asset.field_aliases.",
        },
    }
    if not draft["timestamp_field"]:
        draft.pop("timestamp_field")
    if not draft["timestamp_formats"]:
        draft.pop("timestamp_formats")
    return draft


def attach_text_parser_draft(
    report: dict[str, Any],
    *,
    lines: list[str],
    parser_id: str,
    emit_path: str | None,
    force: bool,
    description: str | None,
) -> None:
    fmt = report.get("detected_format")
    if fmt in {"syslog_auth", "nginx_combined", "json_lines"}:
        report["proposed_text_parser"] = {
            "asset_text_parser": fmt,
            "use_builtin": True,
            "note": "Known format; set asset.text_parser to this built-in id.",
        }
        return

    draft = infer_custom_parser_draft(parser_id=parser_id, lines=lines, description=description)
    proposed = {
        "asset_text_parser": parser_id,
        "parser_file": f"dataasset/parsers/{parser_id}.json",
        "parser": draft,
    }
    if emit_path:
        path = Path(emit_path)
        if not path.is_absolute():
            path = REPO_ROOT / path
        if path.is_dir():
            path = path / f"{parser_id}.json"
        if path.exists() and not force:
            raise SystemExit(f"refuse to overwrite parser file: {path} (use --force-parser)")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(draft, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
        try:
            proposed["parser_file"] = path.relative_to(REPO_ROOT).as_posix()
        except ValueError:
            proposed["parser_file"] = path.as_posix()
    report["proposed_text_parser"] = proposed


def build_llm_prompt(report: dict[str, Any], sample_lines: list[str]) -> str:
    samples = "\n".join(f"  - {ln[:500]}" for ln in sample_lines[:8])
    req = report["requirements"]
    da_ctx = report.get("dataasset_context") or {}
    discovery_hints = report.get("discovery_asset_hints") or {}
    return f"""# Log format discovery — LLM task (required)

You are the **required LLM step** in the log-format-discovery skill. The script
has prepared context from **dataasset/** (evidence spec + registered assets/templates);
your mapping output is the skill deliverable.

## Context
- asset_type: `{report['asset_type']}`
- connector_type: `{report.get('connector_type') or 'unspecified'}`
- detected_format: `{report['detected_format']}`
- sample_count: {report['sample_count']}

## Evidence minimum fields (must map to these)
- required: {req['required']}
- strongly_recommended: {req['strongly_recommended']}
- recommended: {req['recommended']}

## dataasset discovery asset (status=discovery only)
```json
{json.dumps({
    'discovery_asset': da_ctx.get('discovery_asset'),
    'connector': da_ctx.get('connector'),
    'matching_templates': da_ctx.get('matching_templates'),
    'discovery_hints': discovery_hints,
}, ensure_ascii=False, indent=2)}
```

Update **only** this discovery asset in `dataasset/assets/{report['asset_id']}.json`.
After mapping is verified, change `status` from `discovery` → `draft` → `active`.
Do not modify other dataasset assets (draft/active/disabled).

## Sample lines (truncated)
{samples}

## Script heuristics already found
```json
{json.dumps({
    'observed_json_keys': report.get('observed_json_keys'),
    'applicable_existing_aliases': report.get('applicable_existing_aliases'),
    'proposed_field_aliases': report.get('proposed_field_aliases'),
    'gap_analysis': report.get('gap_analysis'),
    'preview_events': report.get('preview_events'),
}, ensure_ascii=False, indent=2)}
```

## Your tasks
1. Confirm or correct **field_aliases** (source field → canonical).
2. If text logs: set **asset.text_parser** (builtin id or dataasset/parsers/*.json), not Python code.
3. Update **discovery asset** `schema.fields` / `query_template_ids`（`correlation_keys` 由 matrix+fields 自动推导）.
4. Reuse **matching_templates** when suitable; else propose new template snippet.
5. Note **masking** for sensitive fields (e.g. payload truncate_500).

## Output format
Return a single JSON object matching `log-format-discovery/output-schema.json` keys:
- `asset_id` (must remain `{report.get('asset_id')}`)
- `proposed_field_aliases`
- `proposed_asset_schema`
- `proposed_normalizer`
- `proposed_query_template`
- `implementation_checklist`
- `confidence` (high/medium/low) per mapping

Do not invent live credentials or connector endpoints.
"""


def discover(
    *,
    asset_id: str,
    lines: list[str],
    allow_any_status: bool = False,
) -> dict[str, Any]:
    dataasset_ctx = load_dataasset_context(asset_id=asset_id, allow_any_status=allow_any_status)
    discovery_asset = dataasset_ctx["discovery_asset"]
    asset_type = discovery_asset["asset_type"]
    connector_type = discovery_asset.get("connector_type")
    discovery_hints = suggest_from_discovery_asset(dataasset_ctx)

    spec = load_evidence_spec()
    if asset_type not in spec.get("by_asset_type", {}) and asset_type != "custom":
        print(f"warning: asset_type {asset_type!r} not in evidence-minimum-fields.json", file=sys.stderr)

    fmt = detect_format(lines)
    key_counts = collect_json_keys(lines) if fmt == "json_lines" else Counter()
    requirements = canonical_requirements(spec, asset_type if asset_type != "custom" else "ssh_auth")
    existing_aliases = dict(spec.get("field_aliases") or {})
    proposed_aliases = infer_aliases_from_keys(key_counts, requirements, existing_aliases)
    observed_keys = set(key_counts.keys()) if key_counts else set()
    applicable_existing = {
        k: existing_aliases[k]
        for k in observed_keys
        if k in existing_aliases
    }

    preview = preview_events(lines, fmt)
    for i, ev in enumerate(preview):
        preview[i] = apply_existing_aliases(ev, {**existing_aliases, **proposed_aliases})

    gaps = gap_analysis(preview, requirements, {**existing_aliases, **proposed_aliases})

    template_hint = build_template_hint(asset_type, connector_type, fmt, dataasset_ctx)
    current_fields = discovery_hints.get("current_fields") or []
    proposed_schema_fields = sorted(
        set(requirements["required"] + requirements["strongly_recommended"]) - {"evidence_id"}
        | set(current_fields)
    )

    report: dict[str, Any] = {
        "skill": "log-format-discovery",
        "version": "1.2",
        "asset_id": asset_id,
        "asset_type": asset_type,
        "connector_type": connector_type,
        "dataasset_context": dataasset_ctx,
        "discovery_asset_hints": discovery_hints,
        "detected_format": fmt,
        "sample_count": len(lines),
        "requirements": requirements,
        "observed_json_keys": dict(key_counts.most_common(30)),
        "proposed_field_aliases": proposed_aliases,
        "applicable_existing_aliases": applicable_existing,
        "existing_field_aliases_overlap": {k: existing_aliases[k] for k in proposed_aliases if k in existing_aliases},
        "gap_analysis": gaps,
        "preview_events": preview[:5],
        "proposed_template_hint": template_hint,
        "implementation_targets": {
            "evidence_minimum_fields": format_path(EVIDENCE_SPEC),
            "normalizer": "src/skills/_shared/data-access/normalizer.py",
            "ssh_fetch_parsers": "src/skills/_shared/data-access/ssh_fetch.py",
            "query_templates": format_path(DATAASSET / "query-templates" / "templates.json"),
            "asset_json": format_path(DATAASSET / "assets" / f"{asset_id}.json"),
        },
        "implementation_checklist": [
            "Set asset.text_parser (syslog_auth / nginx_combined / custom parsers/*.json)",
            "Add field_aliases to evidence-minimum-fields.json (if new source keys)",
            "Update discovery asset schema + query_template_ids",
            f"Set dataasset/assets/{asset_id}.json status: discovery → draft → active",
            "Run: python3 src/dataasset/validate.py",
            f"Run: python3 src/dataasset/test_connector.py {asset_id} --by-asset --dry-run",
        ],
        "proposed_asset_schema": {
            "fields": proposed_schema_fields,
            "time_field": discovery_asset.get("time_field") or "timestamp",
            "retention_days": discovery_asset.get("retention_days") or 30,
            "query_template_ids": discovery_hints.get("current_template_ids") or [],
        },
        "derived_correlation_keys": discovery_hints.get("derived_correlation_keys") or [],
        "proposed_normalizer": {
            "action": "config_only"
            if fmt in ("syslog_auth", "nginx_combined", "json_lines")
            else "custom_parser_json",
            "notes": gaps,
        },
        # Existing templates are review candidates in proposed_template_hint;
        # apply accepts only one explicit new/updated template object.
        "proposed_query_template": template_hint.get("suggest_add_to_templates_json"),
        "confidence": "medium",
        "llm_review_required": bool(gaps.get("missing_required")),
    }
    report["llm_prompt"] = build_llm_prompt(report, lines)
    return report


def try_normalize_preview(
    asset_type: str,
    preview: list[dict[str, Any]],
    *,
    asset_id: str | None = None,
) -> list[dict[str, Any]] | None:
    if not DATA_ACCESS.is_dir():
        return None
    sys.path.insert(0, str(DATA_ACCESS))
    try:
        from normalizer import normalize_events  # noqa: WPS433

        asset: dict[str, Any] = {
            "asset_id": asset_id or "asset-discovery-preview",
            "asset_type": asset_type,
            "masking": {},
        }
        if asset_id:
            real_path = DATAASSET / "assets" / f"{asset_id}.json"
            if real_path.is_file():
                real = _load_json(real_path)
                if real.get("field_aliases"):
                    asset["field_aliases"] = real["field_aliases"]
        json_events = [ev for ev in preview if ev.keys() != {"raw_line"}]
        if not json_events:
            return None
        return normalize_events(json_events, asset)
    except Exception as exc:
        return [{"_normalize_error": str(exc)}]


def print_discovery_queue() -> int:
    assets = list_discovery_assets()
    if not assets:
        print("no assets with status=discovery", file=sys.stderr)
        return 1
    for asset in assets:
        conn_id = asset.get("connector_id", "")
        conn_path = DATAASSET / "connectors" / f"{conn_id}.json"
        ctype = _load_json(conn_path).get("connector_type") if conn_path.is_file() else None
        print(f"{asset['asset_id']}\t{asset.get('asset_type')}\t{ctype or '-'}\t{asset.get('name')}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Log format discovery for dataasset assets with status=discovery"
    )
    parser.add_argument(
        "--asset-id",
        help="dataasset asset_id (must have status=discovery)",
    )
    parser.add_argument(
        "--list-discovery",
        action="store_true",
        help="List assets in discovery queue and exit",
    )
    parser.add_argument("-i", "--input", help="Sample file (lines, JSON array, or JSONL)")
    parser.add_argument("--text", help="Inline sample text")
    parser.add_argument("-o", "--output", help="Write report JSON to file")
    parser.add_argument("--prompt", metavar="PATH", help="Write LLM prompt markdown to file")
    parser.add_argument("--parser-id", help="Custom text parser id to include in the discovery report.")
    parser.add_argument(
        "--emit-parser",
        metavar="PATH",
        help="Write a custom text parser draft JSON. PATH can be a file or directory.",
    )
    parser.add_argument("--parser-description", help="Description for the emitted custom parser draft.")
    parser.add_argument("--force-parser", action="store_true", help="Overwrite parser file when using --emit-parser.")
    parser.add_argument("--preview-normalize", action="store_true", help="Run normalizer on parsed preview")
    parser.add_argument("--pretty", action="store_true")
    parser.add_argument(
        "--allow-any-status",
        action="store_true",
        help="Allow running discovery for assets outside status=discovery. Intended for explicit local CLI/UI testing.",
    )
    parser.add_argument(
        "--apply",
        nargs="?",
        const="__inline__",
        metavar="MAPPING.json",
        help="Apply mapping to dataasset (use report from -o, inline discover result, or MAPPING file)",
    )
    parser.add_argument(
        "--apply-dry-run",
        action="store_true",
        help="With --apply: show changes without writing files",
    )
    parser.add_argument(
        "--global-aliases",
        action="store_true",
        help="With --apply: merge aliases into evidence-minimum-fields.json (default: per-asset field_aliases)",
    )
    parser.add_argument(
        "--force-aliases",
        action="store_true",
        help="With --apply --global-aliases: overwrite conflicting global aliases",
    )
    parser.add_argument(
        "--no-promote-draft",
        action="store_true",
        help="With --apply: do not change status discovery → draft",
    )
    args = parser.parse_args()

    if args.list_discovery:
        return print_discovery_queue()

    if not args.asset_id:
        parser.error("--asset-id required (or use --list-discovery)")

    lines = load_samples(input_path=args.input, text=args.text)
    # An ineligible asset is an actionable CLI input error, not a crash. Keep
    # the discovery-only gate and fail before emitting or applying a mapping.
    try:
        report = discover(asset_id=args.asset_id, lines=lines, allow_any_status=args.allow_any_status)
    except (ValueError, FileNotFoundError) as exc:
        parser.error(str(exc))

    if args.preview_normalize:
        norm = try_normalize_preview(
            report["asset_type"],
            report.get("preview_events") or [],
            asset_id=report.get("asset_id"),
        )
        if norm:
            report["normalized_preview"] = norm

    if args.parser_id or args.emit_parser:
        parser_id = safe_parser_id(args.parser_id or default_parser_id(args.asset_id))
        attach_text_parser_draft(
            report,
            lines=lines,
            parser_id=parser_id,
            emit_path=args.emit_parser,
            force=args.force_parser,
            description=args.parser_description,
        )
        report["llm_prompt"] = build_llm_prompt(report, lines)

    indent = 2 if args.pretty else None
    body = json.dumps(report, ensure_ascii=False, indent=indent)
    if args.output:
        Path(args.output).write_text(body + "\n", encoding="utf-8")
        print(f"wrote report → {args.output}", file=sys.stderr)
    else:
        print(body)

    if args.prompt:
        Path(args.prompt).write_text(report["llm_prompt"], encoding="utf-8")
        print(f"wrote LLM prompt → {args.prompt}", file=sys.stderr)

    if args.apply:
        from discover_apply import apply_discovery_mapping, apply_from_report_file

        dry = args.apply_dry_run
        promote = not args.no_promote_draft
        if args.apply != "__inline__":
            apply_result = apply_from_report_file(
                Path(args.apply),
                dry_run=dry,
                global_aliases=args.global_aliases,
                force_aliases=args.force_aliases,
                promote_draft=promote,
            )
        else:
            apply_result = apply_discovery_mapping(
                report,
                asset_id=args.asset_id,
                dry_run=dry,
                global_aliases=args.global_aliases,
                force_aliases=args.force_aliases,
                promote_draft=promote,
            )
        print(json.dumps(apply_result, ensure_ascii=False, indent=2 if args.pretty else None))

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
