#!/usr/bin/env python3
"""Active dataasset connectivity and usability checker.

Checks active assets across registry, credentials, template rendering, and live fetch.
Never prints resolved secrets.
"""

from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

SCRIPT_PATH = Path(__file__).resolve()
REPO_ROOT = SCRIPT_PATH.parents[4]
DATA_ACCESS_ROOT = REPO_ROOT / "src" / "skills" / "_shared" / "data-access"

if str(DATA_ACCESS_ROOT) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS_ROOT))

logging.getLogger("paramiko").setLevel(logging.CRITICAL)

from aggregate import filter_connectors_by_host, resolve_connector_ids  # noqa: E402
from dataasset_paths import DATAASSET_ROOT  # noqa: E402
from fetch import EXECUTION_MODE_ONBOARDING_TEST, fetch  # noqa: E402
from registry import load_asset, load_connector, load_templates  # noqa: E402
from template_select import normalize_fetch_params, select_template_for_asset  # noqa: E402
from vault import credentials_ref_only, resolve_credentials  # noqa: E402

STATUS_OK_WITH_DATA = "OK_CONNECTED_WITH_DATA"
STATUS_OK_NO_DATA = "OK_CONNECTED_NO_DATA"
STATUS_FAILED_CONFIG = "FAILED_CONFIG"
STATUS_FAILED_CREDENTIAL = "FAILED_CREDENTIAL"
STATUS_FAILED_CONNECTOR = "FAILED_CONNECTOR"
STATUS_FAILED_TEMPLATE = "FAILED_TEMPLATE"
STATUS_FAILED_SCHEMA = "FAILED_SCHEMA"
STATUS_SKIPPED_DRAFT = "SKIPPED_DRAFT_CONNECTOR"
STATUS_SKIPPED_DISABLED = "SKIPPED_DISABLED"
STATUS_NO_TEMPLATE = "FAILED_TEMPLATE_NO_MATCH"


def repo_path(path: Path) -> str:
    try:
        return path.relative_to(REPO_ROOT).as_posix()
    except ValueError:
        return path.as_posix()


def load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def active_asset_ids() -> list[str]:
    ids: list[str] = []
    for path in sorted((DATAASSET_ROOT / "assets").glob("*.json")):
        if path.name == "correlation-matrix.json":
            continue
        try:
            data = load_json(path)
        except Exception:
            continue
        if data.get("status") == "active" and data.get("asset_id"):
            ids.append(data["asset_id"])
    return ids


def has_placeholder(value: Any) -> bool:
    if isinstance(value, str):
        upper = value.upper()
        return upper.startswith("YOUR_") or "REPLACE_ME" in upper or upper in {"TODO", "TBD"}
    if isinstance(value, dict):
        return any(has_placeholder(v) for v in value.values())
    if isinstance(value, list):
        return any(has_placeholder(v) for v in value)
    return False


def classify_failure(message: str) -> str:
    lower = message.lower()
    if any(token in lower for token in ("credential", "vault", "sops", "private_key", "accesskey", "access key")):
        return STATUS_FAILED_CREDENTIAL
    if any(token in lower for token in ("parameterinvalid", "syntaxerror", "parse_datetime", "template", "render", "query")):
        return STATUS_FAILED_TEMPLATE
    if any(token in lower for token in ("schema", "field_alias", "normaliz")):
        return STATUS_FAILED_SCHEMA
    return STATUS_FAILED_CONNECTOR


def safe_error(exc: Exception) -> str:
    text = str(exc).replace("\n", " ").strip()
    if "is not config as key value config" in text:
        text = (
            f"{text}；提示：SLS 字段未配置 key-value 索引。请确认查询使用的源字段名是否正确，"
            "并在对应 logstore 索引配置中为该源字段增加索引；字段可能不是 src_ip，需以实际日志字段为准。"
        )
    if len(text) > 500:
        text = text[:497] + "..."
    return f"{type(exc).__name__}: {text}"


def build_probe_params(args: argparse.Namespace) -> dict[str, Any]:
    now = datetime.now(timezone(timedelta(hours=args.timezone_offset_hours)))
    start = now - timedelta(minutes=args.window_minutes)
    params = {
        "time_start": start.isoformat(),
        "time_end": now.isoformat(),
        "limit": args.limit,
        "src_ip": args.src_ip,
        "client_ip": args.src_ip,
        "grep_pattern": args.grep_pattern,
        "max_lines": args.max_lines,
        "log_path": args.log_path,
    }
    if args.host:
        params["host"] = args.host
    if args.host_name:
        params["host_name"] = args.host_name
    return normalize_fetch_params(params)


def build_asset_probe_params(
    asset: dict[str, Any], base_params: dict[str, Any]
) -> tuple[dict[str, Any], str | None]:
    """Use an explicit host or derive one from this asset's declared coverage."""
    params = dict(base_params)
    if any(params.get(key) for key in ("host", "host_ip", "host_name", "hosts")):
        return normalize_fetch_params(params), "cli"

    coverage = asset.get("coverage") or {}
    hosts = coverage.get("hosts") if isinstance(coverage, dict) else None
    if isinstance(hosts, list):
        for value in hosts:
            host = str(value or "").strip()
            if host and not has_placeholder(host):
                params["host"] = host
                return normalize_fetch_params(params), "asset.coverage.hosts"

    return normalize_fetch_params(params), None


def sls_ping(connector: dict[str, Any]) -> dict[str, Any]:
    try:
        from aliyun.log import GetLogsRequest, LogClient
    except ImportError as exc:
        raise RuntimeError("live SLS ping requires aliyun-log-python-sdk") from exc

    credentials_ref = credentials_ref_only(connector)
    credentials = resolve_credentials(credentials_ref)
    if credentials.get("type") != "aliyun_ram":
        raise ValueError(f"unsupported SLS credential type: {credentials.get('type')}")

    cfg = connector.get("config") or {}
    now = datetime.now(timezone(timedelta(hours=8)))
    start = now - timedelta(minutes=5)
    client = LogClient(
        cfg["endpoint"],
        credentials["access_key_id"],
        credentials["access_key_secret"],
        credentials.get("security_token") or None,
    )
    req = GetLogsRequest(
        cfg["project"],
        cfg["logstore"],
        int(start.timestamp()),
        int(now.timestamp()),
        query="* | select count(1) as cnt",
        line=1,
        offset=0,
        reverse=False,
    )
    resp = client.get_logs(req)
    rows = [dict(item.contents) for item in (resp.get_logs() or [])]
    return {"ok": True, "mode": "sls_count", "rows": rows}


def connector_ping(connector: dict[str, Any]) -> dict[str, Any] | None:
    ctype = connector.get("connector_type")
    if ctype == "sls":
        return sls_ping(connector)
    return None


def check_one(
    asset_id: str,
    connector_id: str,
    params: dict[str, Any],
    templates: dict[str, Any],
    *,
    include_draft_connectors: bool,
    live: bool,
    probe_host_source: str | None = None,
) -> dict[str, Any]:
    """Probe transport and event presence, without promising analysis coverage.

    A one-row probe cannot evaluate a requested Skill's fields, sources or
    completeness. Keep that readiness unknown when data exists; empty successful
    queries and dry runs must never count as usable evidence or failed transport.
    """
    asset = load_asset(asset_id)
    row: dict[str, Any] = {
        "asset_id": asset_id,
        "asset_type": asset.get("asset_type"),
        "connector_id": connector_id,
        "connectable": None,
        "has_data": None,
        "usable_for_requested_skill": None,
        "usable_for_skill": False,
    }
    probe_host = params.get("host_ip") or params.get("host_name") or params.get("host")
    if probe_host:
        row["probe_host"] = probe_host
        row["probe_host_source"] = probe_host_source

    # Disabled assets are an unconditional kill switch. Stop before loading a
    # connector or resolving any credential, including explicit CLI probes.
    if asset.get("status") == "disabled":
        row.update(
            {
                "status": STATUS_SKIPPED_DISABLED,
                "reason": "asset is disabled",
                "usable_for_skill": False,
            }
        )
        return row

    try:
        connector = load_connector(connector_id)
    except Exception as exc:
        row.update({"status": STATUS_FAILED_CONFIG, "reason": safe_error(exc), "usable_for_skill": False})
        return row

    cfg = connector.get("config") or {}
    row.update(
        {
            "connector_type": connector.get("connector_type"),
            "connector_status": connector.get("status"),
            "credentials_ref": connector.get("credentials_ref") or "",
            "target": connector_target(connector),
            "placeholder_config": has_placeholder(cfg),
        }
    )

    if connector.get("status") == "disabled":
        row.update(
            {
                "status": STATUS_SKIPPED_DISABLED,
                "reason": "connector is disabled",
                "usable_for_skill": False,
            }
        )
        return row

    if connector.get("status") == "draft" and not include_draft_connectors:
        row.update(
            {
                "status": STATUS_SKIPPED_DRAFT,
                "reason": "active asset references a draft connector; pass --include-draft-connectors to probe it",
                "usable_for_skill": False,
            }
        )
        return row

    if has_placeholder(cfg):
        row.update(
            {
                "status": STATUS_FAILED_CONFIG,
                "reason": "connector.config contains placeholder values such as YOUR_* or REPLACE_ME",
                "usable_for_skill": False,
            }
        )
        return row

    try:
        if connector.get("connector_type") != "local_file":
            credentials_ref_only(connector)
            # Resolve only to verify availability/type; do not store or print returned secrets.
            resolve_credentials(connector["credentials_ref"])
        row["credential_status"] = "resolved"
    except Exception as exc:
        row.update({"status": STATUS_FAILED_CREDENTIAL, "reason": safe_error(exc), "usable_for_skill": False})
        return row

    template_id, reason = select_template_for_asset(asset, connector, params, templates)
    row.update({"template_id": template_id, "template_reason": reason})
    if not template_id:
        row.update({"status": STATUS_NO_TEMPLATE, "reason": reason or "no matching template", "usable_for_skill": False})
        return row

    if not live:
        row.update({"status": "DRY_RUN_OK", "reason": "template selected and credentials resolved; live readiness not evaluated"})
        return row

    try:
        # Connectivity diagnostics are the only Skill-side path allowed to test
        # draft/discovery objects before operators promote them to active.
        result = fetch(
            asset_id,
            template_id,
            params,
            connector_id=connector_id,
            resolve_secrets=True,
            execution_mode=EXECUTION_MODE_ONBOARDING_TEST,
        )
        events = result.get("events") or []
        status = STATUS_OK_WITH_DATA if events else STATUS_OK_NO_DATA
        data_presence_scope = "probe_host" if probe_host else "asset_window"
        no_data_reason = (
            f"connected; no events for probe host {probe_host} in probe window"
            if probe_host
            else "connected; no events in probe window"
        )
        row.update(
            {
                "status": status,
                "rows_returned": len(events),
                "reason": "connected" if events else no_data_reason,
                "data_presence_scope": data_presence_scope,
                "query_meta": result.get("query_meta", {}),
                "connectable": True,
                "has_data": bool(events),
                "usable_for_requested_skill": None if events else False,
                # Compatibility field now means candidate evidence only; a
                # positive probe still requires the selected Skill's precheck.
                "usable_for_skill": bool(events),
            }
        )
        return row
    except Exception as exc:
        fetch_error = safe_error(exc)
        status = classify_failure(fetch_error)
        row.update({"fetch_error": fetch_error, "status": status, "usable_for_skill": False})
        if status == STATUS_FAILED_TEMPLATE:
            try:
                ping = connector_ping(connector)
                row["connector_ping"] = ping
                row["reason"] = "fetch failed, but connector ping succeeded; likely query template issue"
            except Exception as ping_exc:
                row["connector_ping_error"] = safe_error(ping_exc)
                row["status"] = classify_failure(row["connector_ping_error"])
                row["reason"] = "fetch failed and connector ping also failed"
        else:
            row["reason"] = fetch_error
        return row


def connector_target(connector: dict[str, Any]) -> str:
    cfg = connector.get("config") or {}
    ctype = connector.get("connector_type")
    if ctype == "sls":
        return f"{cfg.get('project', '')}:{cfg.get('logstore', '')}"
    if ctype in {"ssh_file", "ssh_command"}:
        return f"{cfg.get('host', '')}:{cfg.get('port', 22)}"
    if ctype == "database_ro":
        return f"{cfg.get('engine', '')}:{cfg.get('host', '')}:{cfg.get('database', '')}"
    return str(cfg.get("endpoint") or cfg.get("path") or cfg.get("host") or "")


def summarize(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Keep no-data/dry-run states out of failure totals and split readiness."""
    by_status = Counter(row.get("status") for row in rows)
    active_assets = sorted({row.get("asset_id") for row in rows})
    usable_assets = sorted(
        {
            row.get("asset_id")
            for row in rows
            if row.get("usable_for_skill") and str(row.get("status", "")).startswith("OK_")
        }
    )
    failed_assets = sorted({row.get("asset_id") for row in rows
                            if str(row.get("status", "")).startswith(("FAILED_", "SKIPPED_"))})
    connected_assets = sorted({row.get("asset_id") for row in rows if row.get("connectable") is True})
    data_assets = sorted({row.get("asset_id") for row in rows if row.get("has_data") is True})
    return {
        "active_assets_total": len(active_assets),
        "connector_paths_total": len(rows),
        "usable_assets_total": len(usable_assets),
        "connected_assets_total": len(connected_assets),
        "assets_with_data_total": len(data_assets),
        "connected_assets": connected_assets,
        "assets_with_data": data_assets,
        "skill_readiness": "not_evaluated",
        "failed_assets_total": len(failed_assets),
        "by_status": dict(by_status),
        "usable_assets": usable_assets,
        "failed_assets": failed_assets,
    }


def markdown_report(payload: dict[str, Any]) -> str:
    summary = payload["summary"]
    rows = payload["results"]
    lines = [
        "## Active 资产连接性巡检结果",
        "",
        f"- Active 资产数：{summary['active_assets_total']}",
        f"- Connector 路径数：{summary['connector_paths_total']}",
        f"- 连接成功资产数：{summary['connected_assets_total']}",
        f"- 探测窗口有数据资产数：{summary['assets_with_data_total']}",
        "- 技能可运行性：未评估；需按目标技能核对字段、时间和所需数据源。",
        f"- 失败/不可用资产数：{summary['failed_assets_total']}",
        "",
        "### 状态分布",
        "",
    ]
    for status, count in summary["by_status"].items():
        lines.append(f"- `{status}`：{count}")
    lines.extend(["", "### 明细", ""])
    lines.append("| 资产 | Connector | 类型 | 状态 | 目标 | 原因 |")
    lines.append("|---|---|---|---|---|---|")
    for row in rows:
        reason = str(row.get("reason") or row.get("fetch_error") or "").replace("|", "\\|")
        if len(reason) > 120:
            reason = reason[:117] + "..."
        lines.append(
            f"| `{row.get('asset_id')}` | `{row.get('connector_id')}` | `{row.get('connector_type', '')}` | `{row.get('status')}` | `{row.get('target', '')}` | {reason} |"
        )
    return "\n".join(lines)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Check active dataasset connectivity and usability")
    parser.add_argument("--asset-id", action="append", help="Only check a specific active asset; may repeat")
    parser.add_argument("--window-minutes", type=int, default=5, help="Probe time window in minutes")
    parser.add_argument("--limit", type=int, default=1, help="Fetch limit per connector path")
    parser.add_argument("--src-ip", default="1.2.3.4", help="Generic source IP used for templates requiring src_ip")
    parser.add_argument(
        "--host",
        help="Override the probe host; otherwise each asset uses the first valid coverage.hosts entry",
    )
    parser.add_argument("--host-name", help="Override host_name independently of --host")
    parser.add_argument("--grep-pattern", default="sshd", help="Safe grep pattern for ssh_file probes")
    parser.add_argument("--log-path", default="/var/log/auth.log", help="Safe log path for ssh_file probes")
    parser.add_argument("--max-lines", type=int, default=1, help="Max lines for ssh_file probes")
    parser.add_argument("--timezone-offset-hours", type=int, default=8, help="Timezone offset used for generated timestamps")
    parser.add_argument("--include-draft-connectors", action="store_true", help="Also probe draft connectors referenced by active assets")
    parser.add_argument("--dry-run", action="store_true", help="Only check config, credentials, and template selection; no live fetch")
    parser.add_argument("--format", choices=("json", "markdown"), default="json")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    base_params = build_probe_params(args)
    asset_ids = args.asset_id or active_asset_ids()
    templates = load_templates()
    rows: list[dict[str, Any]] = []

    for asset_id in asset_ids:
        try:
            asset = load_asset(asset_id)
            params, probe_host_source = build_asset_probe_params(asset, base_params)
            connector_ids = filter_connectors_by_host(
                asset,
                resolve_connector_ids(asset),
                params,
                load_connector,
            )
        except Exception as exc:
            rows.append(
                {
                    "asset_id": asset_id,
                    "status": STATUS_FAILED_CONFIG,
                    "reason": safe_error(exc),
                    "usable_for_skill": False,
                }
            )
            continue
        for connector_id in connector_ids:
            rows.append(
                check_one(
                    asset_id,
                    connector_id,
                    params,
                    templates,
                    include_draft_connectors=args.include_draft_connectors,
                    live=not args.dry_run,
                    probe_host_source=probe_host_source,
                )
            )

    payload = {
        "check_type": "dataasset_connectivity_check",
        "checked_at": datetime.now(timezone(timedelta(hours=args.timezone_offset_hours))).isoformat(),
        "probe": {
            "window_minutes": args.window_minutes,
            "limit": args.limit,
            "host_selection": "explicit_cli_or_asset_coverage",
            "include_draft_connectors": args.include_draft_connectors,
            "live": not args.dry_run,
        },
        "summary": summarize(rows),
        "results": rows,
    }

    if args.format == "markdown":
        print(markdown_report(payload))
    else:
        print(json.dumps(payload, ensure_ascii=False, indent=2))

    return 0 if payload["summary"]["failed_assets_total"] == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
