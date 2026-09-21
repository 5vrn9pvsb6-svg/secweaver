#!/usr/bin/env python3
"""Build dataasset/examples/reference-assets.json — one merged asset with all platform fields."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any

REPO = Path(__file__).resolve().parents[2]


def resolve_dataasset_root() -> Path:
    configured = os.environ.get("DATAASSET_ROOT")
    if not configured:
        return REPO / "dataasset"
    path = Path(configured).expanduser()
    return path if path.is_absolute() else REPO / path


DATAASSET = resolve_dataasset_root()
EXAMPLES = DATAASSET / "examples"
DATA_ACCESS = REPO / "src" / "skills" / "_shared" / "data-access"

if str(DATA_ACCESS) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS))

from correlation_keys import derive_correlation_keys  # noqa: E402

EVIDENCE_SPEC = DATAASSET / "configure" / "evidence-minimum-fields.json"
MATRIX_PATH = DATAASSET / "assets" / "correlation-matrix.json"
CONNECTOR_ID = "conn-example-reference"
MERGED_ASSET_ID = "asset-example-all-fields"

EXTRA_FIELDS: dict[str, list[str]] = {
    "waf_alert": ["ip", "trace_id", "plugin_name", "event", "level", "app_name", "tenant_name", "@timestamp", "__time__"],
    "web_access_log": ["remote_addr", "client_ip", "request_uri", "path", "uri", "@timestamp"],
    "host_exec": [
        "host_name",
        "time",
        "audit_id",
        "pid_name",
        "ppid",
        "ppid_name",
        "uid",
        "uid_name",
        "auid",
        "auid_name",
        "comm",
        "exe",
        "command_line",
        "cmd",
        "argv",
        "listener_process",
        "listener_address",
    ],
    "host_connect": ["host_name", "time", "listener_pid", "listener_port", "dest_ip", "dip", "dport"],
    "host_file_op": ["host_name", "time", "listener_pid", "path"],
    "host_process": ["host_name", "time", "snapshot_id", "pid", "ppid", "process", "exe", "user"],
    "host_socket": ["host_name", "time", "snapshot_id", "protocol", "listen_address", "listen_port", "pid", "process", "user"],
    "host_identity": ["host_name", "time", "entity_type", "action", "user", "uid", "gid", "sid", "groups", "source"],
    "host_service": ["host_name", "time", "entity_type", "action", "service_name", "task_name", "state", "start_mode", "path"],
    "host_kernel_context": ["host_name", "time", "entity_type", "action", "module_name", "container_id", "container_runtime", "kernel_release"],
    "windows_event_log": ["Computer", "EventID", "Channel", "ProviderName", "Message", "Level", "computer"],
    "linux_syslog": ["ident", "syslogtag", "priority", "facility", "SYSLOG_IDENTIFIER", "_HOSTNAME", "unit"],
    "ssh_auth": ["auth_method", "port", "IpAddress"],
    "firewall_log": ["sport", "dport", "dip", "sip", "proto"],
    "network_traffic_audit": [
        "sport",
        "dport",
        "dip",
        "bytes",
        "packets",
        "application",
        "session_id",
        "duration",
        "sensor_id",
        "flow_id",
    ],
    "dns_log": ["query_name", "qname", "answer", "answers", "resolved_ip", "qtype", "host_ip"],
    "asset_inventory": ["host", "name", "host_ip", "updated_at"],
    "db_audit": ["database", "sql_text", "object"],
    "ids_alert": ["dst_ip", "signature", "rule_id", "severity"],
    "edr_event": ["process", "action"],
    "app_api_log": ["api", "sql", "endpoint"],
    "vuln_scan": ["cve", "severity", "hostname"],
}

FIELD_ALIASES_BY_TYPE: dict[str, dict[str, str]] = {
    "waf_alert": {"ip": "src_ip", "trace_id": "alert_id", "event": "rule_name", "plugin_name": "rule_id"},
    "web_access_log": {"remote_addr": "src_ip", "client_ip": "src_ip", "request_uri": "url"},
    "host_exec": {"host_name": "host", "time": "timestamp", "cmd": "command", "argv": "command"},
    "host_connect": {"host_name": "host", "time": "timestamp", "dest_ip": "dst_ip", "dip": "dst_ip", "dport": "dst_port"},
    "host_file_op": {"host_name": "host", "time": "timestamp"},
    "host_process": {"host_name": "host", "time": "timestamp"},
    "host_socket": {"host_name": "host", "time": "timestamp"},
    "host_identity": {"host_name": "host", "time": "timestamp"},
    "host_service": {"host_name": "host", "time": "timestamp"},
    "host_kernel_context": {"host_name": "host", "time": "timestamp"},
    "windows_event_log": {
        "Computer": "host",
        "EventID": "event_id",
        "Channel": "channel",
        "ProviderName": "provider",
        "Message": "message",
        "Level": "level",
    },
    "linux_syslog": {"ident": "program", "syslogtag": "program", "priority": "severity", "_HOSTNAME": "host"},
    "ssh_auth": {"IpAddress": "src_ip"},
    "firewall_log": {"sip": "src_ip", "dip": "dst_ip", "sport": "src_port", "dport": "dst_port", "proto": "protocol"},
    "network_traffic_audit": {
        "dip": "dst_ip",
        "sport": "src_port",
        "dport": "dst_port",
        "flow_id": "session_id",
        "app_name": "application",
    },
    "dns_log": {
        "query_name": "query",
        "qname": "query",
        "answer": "response",
        "answers": "response",
        "qtype": "query_type",
        "client_ip": "src_ip",
    },
    "asset_inventory": {"host": "hostname", "name": "hostname", "host_ip": "ip"},
    "db_audit": {},
}

FIELD_PRIORITY = [
    "evidence_id",
    "timestamp",
    "time",
    "ts",
    "@timestamp",
    "__time__",
    "updated_at",
    "src_ip",
    "host",
    "hostname",
    "host_ip",
    "host_name",
    "ip",
    "client_ip",
    "dst_ip",
    "dest_ip",
    "url",
    "alert_id",
    "trace_id",
    "action",
    "payload",
    "rule_id",
    "rule_name",
    "method",
    "status",
    "user_agent",
    "command",
    "event_type",
    "listener_pid",
    "listener_port",
    "listener_process",
    "pid",
    "dst_port",
    "src_port",
    "protocol",
    "path",
    "query",
    "response",
    "user",
    "result",
    "message",
    "program",
    "severity",
    "event_id",
    "channel",
    "provider",
    "level",
]


def load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def fields_for_type(asset_type: str, spec: dict[str, Any]) -> list[str]:
    """Combine minimum evidence requirements and documented source aliases.

    Types without a minimum-field specification retain a generic baseline, not
    a claim that these columns exhaust every possible vendor schema.
    """
    seen: set[str] = set()
    ordered: list[str] = []

    def add(*names: str) -> None:
        for name in names:
            if name and name not in seen:
                seen.add(name)
                ordered.append(name)

    type_spec = (spec.get("by_asset_type") or {}).get(asset_type) or {}
    for bucket in ("required", "strongly_recommended", "recommended"):
        add(*(type_spec.get(bucket) or []))
    add(*(spec.get("common_required") or []))

    add(*(EXTRA_FIELDS.get(asset_type) or []))

    if asset_type not in (spec.get("by_asset_type") or {}):
        add("timestamp", "host", "src_ip", "evidence_id")

    return ordered


def merge_field_lists(lists: list[list[str]]) -> list[str]:
    union = set()
    for items in lists:
        union.update(items)
    ordered: list[str] = []
    for name in FIELD_PRIORITY:
        if name in union:
            ordered.append(name)
            union.discard(name)
    ordered.extend(sorted(union))
    return ordered


def merge_field_aliases(fields: set[str], spec: dict[str, Any]) -> dict[str, str]:
    merged: dict[str, str] = {}
    for per_type in FIELD_ALIASES_BY_TYPE.values():
        for src, dst in per_type.items():
            if src in fields or dst in fields:
                merged[src] = dst
    for src, dst in (spec.get("field_aliases") or {}).items():
        if src in fields or dst in fields:
            if src not in merged:
                merged[src] = dst
    return dict(sorted(merged.items()))


def build_merged_asset(
    spec: dict[str, Any], matrix: dict[str, Any], schema: dict[str, Any]
) -> tuple[dict[str, Any], dict[str, Any]]:
    """Use the public Schema as the authoritative coverage set.

    Reject unknown specification types instead of silently dropping their fields.
    Matrix rules derive correlation keys; they do not invent vendor columns.
    """
    asset_types = sorted(set(schema["properties"]["asset_type"]["enum"]))
    unknown = set(spec.get("by_asset_type", {})) - set(asset_types)
    if unknown:
        raise ValueError(f"Evidence specification has unknown asset types: {sorted(unknown)}")
    fields_by_type = {t: fields_for_type(t, spec) for t in asset_types}
    all_fields = merge_field_lists(list(fields_by_type.values()))
    fields_set = set(all_fields)
    aliases = merge_field_aliases(fields_set, spec)

    correlation_by_type: dict[str, list[str]] = {}
    all_corr: set[str] = set()
    for t in asset_types:
        pseudo = {
            "asset_id": f"asset-example-{t.replace('_', '-')}",
            "asset_type": t,
            "field_aliases": FIELD_ALIASES_BY_TYPE.get(t, {}),
            "schema": {"fields": fields_by_type[t], "time_field": "timestamp", "retention_days": 30},
        }
        keys = derive_correlation_keys(pseudo, matrix)
        correlation_by_type[t] = keys
        all_corr.update(keys)

    asset: dict[str, Any] = {
        "asset_id": MERGED_ASSET_ID,
        "name": "平台全量字段参考（跨 asset_type 合并）",
        "asset_type": "linux_syslog",
        "domain": "D2",
        "owner_team": "security-ops",
        "environment": "development",
        "status": "draft",
        "connector_id": CONNECTOR_ID,
        "description": (
            f"覆盖 Schema 中 {len(asset_types)} 种 asset_type 的参考字段并集（自动生成，勿用于生产 bundle）。"
            "asset_type=linux_syslog 仅为满足 JSON Schema；接入真实源时请改为对应类型并删减无关字段。"
            "字段来源：evidence-minimum-fields.json 与生成器常见源字段；关联键由 correlation-matrix 推导。"
        ),
        "coverage": {"zones": ["example"], "apps": [], "hosts": []},
        "schema": {
            "fields": all_fields,
            "time_field": "timestamp",
            "retention_days": 30,
        },
        "query_template_ids": [],
        "sensitivity": "internal",
        "tags": ["example", "reference", "field-catalog", "all-fields", "not-for-production"],
    }
    if aliases:
        asset["field_aliases"] = aliases

    derived = {
        "field_count": len(all_fields),
        "alias_count": len(aliases),
        "asset_types_covered": asset_types,
        "fields_by_asset_type": fields_by_type,
        "correlation_keys_by_asset_type": correlation_by_type,
        "all_correlation_keys": sorted(all_corr),
    }
    return asset, derived


def main() -> None:
    spec = load_json(EVIDENCE_SPEC)
    matrix = load_json(MATRIX_PATH)
    schema = load_json(DATAASSET / "schema" / "data-asset.schema.json")
    asset, derived = build_merged_asset(spec, matrix, schema)

    catalog = {
        "version": "2.0",
        "description": "SecWeaver 全平台字段参考：单一合并资产 + 分类型索引",
        "connector_id": CONNECTOR_ID,
        "usage": "复制 asset 块到 dataasset/assets/ 后按真实 asset_type 删减 fields、改 connector 与 status",
        "sources": [
            "dataasset/schema/data-asset.schema.json",
            "src/dataasset/build_field_reference.py",
            "dataasset/configure/evidence-minimum-fields.json",
            "dataasset/assets/correlation-matrix.json",
        ],
        "asset": asset,
        "_derived": derived,
    }

    EXAMPLES.mkdir(parents=True, exist_ok=True)
    out = EXAMPLES / "reference-assets.json"
    out.write_text(json.dumps(catalog, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {out} — {derived['field_count']} fields, {len(derived['asset_types_covered'])} asset types")


if __name__ == "__main__":
    main()
