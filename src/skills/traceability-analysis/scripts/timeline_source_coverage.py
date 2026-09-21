"""Timeline row coverage across evidence bundle types (data sources)."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

DATA_ACCESS_PATH = Path(__file__).resolve().parents[2] / "_shared" / "data-access"
if str(DATA_ACCESS_PATH) not in sys.path:
    sys.path.insert(0, str(DATA_ACCESS_PATH))

TIMELINE_CHECK = "✓"
TIMELINE_MISS = "✗"

SOURCE_ORDER = [
    "waf_alert",
    "web_access_log",
    "host_exec",
    "host_connect",
    "host_file_op",
    "host_persistence",
    "ssh_auth",
    "syslog_risk_alert",
    "firewall_log",
    "dns_log",
    "network_traffic_audit",
    "asset_inventory",
]

SOURCE_LABELS_ZH = {
    "waf_alert": "WAF",
    "web_access_log": "网关Access",
    "host_exec": "主机Exec",
    "host_connect": "主机Connect",
    "host_file_op": "文件操作",
    "host_persistence": "持久化",
    "ssh_auth": "SSH认证",
    "syslog_risk_alert": "Syslog风险",
    "firewall_log": "防火墙",
    "dns_log": "DNS",
    "network_traffic_audit": "全流量",
    "asset_inventory": "资产清单",
}

SOURCE_LABELS_EN = {
    "waf_alert": "WAF",
    "web_access_log": "Gateway",
    "host_exec": "Host Exec",
    "host_connect": "Host Connect",
    "host_file_op": "File Op",
    "host_persistence": "Persistence",
    "ssh_auth": "SSH Auth",
    "syslog_risk_alert": "Syslog Risk",
    "firewall_log": "Firewall",
    "dns_log": "DNS",
    "network_traffic_audit": "NTA",
    "asset_inventory": "Inventory",
}


def _asset_id_to_type(asset_id: str) -> str | None:
    try:
        from registry import load_asset  # noqa: WPS433

        asset_type = load_asset(asset_id).get("asset_type")
        return str(asset_type) if asset_type else None
    except Exception:
        return None


def resolve_timeline_source_types(result: dict[str, Any]) -> list[str]:
    """Ordered asset_type keys for timeline source columns."""
    found: set[str] = set()
    summary = result.get("fetch_summary") or {}
    for source_type in (summary.get("by_asset_type") or {}):
        found.add(str(source_type))
    for meta in (result.get("evidence_index") or {}).values():
        bundle = meta.get("bundle") if isinstance(meta, dict) else None
        if bundle:
            found.add(str(bundle))
    for asset_id in summary.get("asset_ids") or []:
        mapped = _asset_id_to_type(str(asset_id))
        if mapped:
            found.add(mapped)
    ordered = [source for source in SOURCE_ORDER if source in found]
    ordered.extend(sorted(found - set(ordered)))
    return ordered


def source_labels(source_types: list[str], *, zh: bool) -> list[str]:
    labels = SOURCE_LABELS_ZH if zh else SOURCE_LABELS_EN
    return [labels.get(source, source) for source in source_types]


def bundles_for_refs(refs: list[str], evidence_index: dict[str, Any]) -> set[str]:
    bundles: set[str] = set()
    for ref in refs or []:
        meta = evidence_index.get(str(ref)) or {}
        bundle = meta.get("bundle") if isinstance(meta, dict) else None
        if bundle:
            bundles.add(str(bundle))
    return bundles


def build_source_coverage(
    refs: list[str],
    evidence_index: dict[str, Any],
    source_types: list[str],
) -> dict[str, bool]:
    bundles = bundles_for_refs(refs, evidence_index)
    return {source: source in bundles for source in source_types}


def format_source_coverage_cells(
    coverage: dict[str, bool],
    source_types: list[str],
) -> list[str]:
    return [TIMELINE_CHECK if coverage.get(source) else TIMELINE_MISS for source in source_types]
