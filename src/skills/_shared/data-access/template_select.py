"""Select query templates from asset.query_template_ids with connector-aware fallback."""

from __future__ import annotations

from typing import Any, Callable

from aggregate import filter_connectors_by_host, resolve_connector_ids
from connector_registry import query_key_by_connector
TEMPLATE_CONNECTOR_ALIASES = {"sls_proxy": "sls"}


def normalize_fetch_params(params: dict[str, Any]) -> dict[str, Any]:
    """Align skill params with query-templates (src_ip, time range, host)."""
    out = dict(params)
    if "src_ip" not in out:
        out["src_ip"] = out.get("attacker_ip") or out.get("ip")
    if not out.get("client_ip"):
        out["client_ip"] = out.get("attacker_ip") or out.get("src_ip") or out.get("ip")
    if not out.get("host") and out.get("hosts"):
        hosts = out["hosts"]
        if isinstance(hosts, list) and hosts:
            out["host"] = hosts[0]
    if not out.get("host_ip") and out.get("host"):
        if _looks_like_ip(out["host"]):
            out["host_ip"] = out["host"]
    if not out.get("host_name") and out.get("host") and not _looks_like_ip(out["host"]):
        out["host_name"] = out["host"]
    out.setdefault("limit", 2000)
    if not out.get("grep_pattern"):
        out["grep_pattern"] = out.get("src_ip") or out.get("attacker_ip") or out.get("ip")
    out.setdefault("max_lines", 5000)
    return out


def _looks_like_ip(value: Any) -> bool:
    text = str(value or "").strip()
    if not text:
        return False
    try:
        import ipaddress

        ipaddress.ip_address(text)
        return True
    except ValueError:
        return False


def expand_multi_host_fetch_params(params: dict[str, Any]) -> list[dict[str, Any]]:
    """Expand hosts[] into per-host fetch param sets for live queries."""
    normalized = normalize_fetch_params(params)
    hosts = normalized.get("hosts")
    if not isinstance(hosts, list) or len(hosts) <= 1:
        return [normalized]
    expanded: list[dict[str, Any]] = []
    for host in hosts:
        host_text = str(host)
        item = dict(normalized)
        item["host"] = host_text
        if _looks_like_ip(host_text):
            item["host_ip"] = host_text
        else:
            item["host_name"] = host_text
        item["hosts"] = [host_text]
        expanded.append(item)
    return expanded


def merged_template_params(template: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
    return {**template.get("defaults", {}), **normalize_fetch_params(params)}


def params_satisfy_template(template: dict[str, Any], params: dict[str, Any]) -> bool:
    merged = merged_template_params(template, params)
    for key in template.get("params", []):
        if merged.get(key) in (None, ""):
            return False
    return True


def connector_supports_template(template: dict[str, Any], connector_type: str) -> bool:
    """Check current registry capabilities rather than an import-time snapshot."""
    allowed = template.get("connector_types") or []
    compatible_type = TEMPLATE_CONNECTOR_ALIASES.get(connector_type, connector_type)
    if connector_type not in allowed and compatible_type not in allowed:
        return False
    query_key = query_key_by_connector().get(connector_type)
    if query_key and not template.get(query_key):
        return False
    return True


def ordered_template_candidates(asset: dict[str, Any], params: dict[str, Any]) -> list[str]:
    """Prefer asset.query_template_ids; boost alert_id template when param present."""
    candidates = list(asset.get("query_template_ids") or [])
    merged = normalize_fetch_params(params)
    if merged.get("alert_id"):
        for tid in ("waf_gateway_plugin_by_trace_id", "waf_by_alert_id"):
            if tid in candidates:
                return [tid] + [t for t in candidates if t != tid]
    if merged.get("event_id"):
        for tid in ("windows_event_by_event_id",):
            if tid in candidates:
                return [tid] + [t for t in candidates if t != tid]
    if merged.get("program"):
        for tid in ("linux_syslog_by_program",):
            if tid in candidates:
                return [tid] + [t for t in candidates if t != tid]
    if merged.get("dst_port") and not merged.get("src_ip"):
        for tid in ("network_traffic_by_dst_port",):
            if tid in candidates:
                return [tid] + [t for t in candidates if t != tid]
    if merged.get("src_ip") and not merged.get("dst_ip"):
        for tid in ("firewall_by_src_ip_time",):
            if tid in candidates:
                return [tid] + [t for t in candidates if t != tid]
    if merged.get("host") or merged.get("hosts") or merged.get("host_ip") or merged.get("host_name"):
        host_specific = [
            tid
            for tid in candidates
            if tid.endswith("_by_host_ip_time") or tid.endswith("_by_host_time") or tid.endswith("_by_host_name_time")
        ]
        if host_specific:
            preferred: list[str] = []
            if merged.get("host_ip"):
                preferred.extend([tid for tid in host_specific if "host_ip" in tid])
            if merged.get("host"):
                preferred.extend([tid for tid in host_specific if tid.endswith("_by_host_time")])
            if merged.get("host_name"):
                preferred.extend([tid for tid in host_specific if "host_name" in tid])
            preferred.extend(host_specific)
            deprioritized = [tid for tid in candidates if tid not in preferred and tid != "host_exec_by_time"]
            tail = [tid for tid in candidates if tid == "host_exec_by_time"]
            seen: set[str] = set()
            ordered: list[str] = []
            for tid in preferred + deprioritized + tail:
                if tid in seen:
                    continue
                seen.add(tid)
                ordered.append(tid)
            return ordered
    return candidates


def default_template_id_for_asset(
    asset: dict[str, Any], connector: dict[str, Any], templates: dict[str, Any]
) -> str | None:
    """Return connector-aware default template_id from templates.default_templates."""
    connector_type = connector.get("connector_type", "")
    asset_type = asset.get("asset_type", "")
    defaults = templates.get("default_templates") or {}
    compatible_type = TEMPLATE_CONNECTOR_ALIASES.get(connector_type, connector_type)
    by_connector = defaults.get(connector_type) or defaults.get(compatible_type) or {}
    if isinstance(by_connector, dict):
        value = by_connector.get(asset_type)
        return str(value) if value else None
    return None


def select_template_for_asset(
    asset: dict[str, Any],
    connector: dict[str, Any],
    params: dict[str, Any],
    templates: dict[str, Any],
) -> tuple[str | None, str | None]:
    """Return (template_id, reason). reason set when using default or None on failure."""
    connector_type = connector.get("connector_type", "")
    catalog = templates.get("templates", templates)

    for template_id in ordered_template_candidates(asset, params):
        template = catalog.get(template_id)
        if not template:
            continue
        if not connector_supports_template(template, connector_type):
            continue
        if not params_satisfy_template(template, params):
            continue
        return template_id, None

    fallback_id = default_template_id_for_asset(asset, connector, templates)
    if fallback_id:
        template = catalog.get(fallback_id)
        if template and connector_supports_template(template, connector_type):
            if params_satisfy_template(template, params):
                return fallback_id, "default_template_by_connector"
            return None, "default_template_params_missing"
        return None, "default_template_invalid"

    return None, "no_matching_template"


SRC_IP_WEB_ACCESS_TEMPLATES = frozenset(
    {
        "web_access_by_ip_time",
        "web_access_by_remote_addr_time",
        "web_access_by_src_ip_time",
    }
)


def resolve_src_ip_web_access_template_id(
    asset: dict[str, Any],
    connector: dict[str, Any],
    params: dict[str, Any],
    templates: dict[str, Any],
    requested_template_id: str,
) -> str:
    """Matrix/correlation may request web_access_by_src_ip_time; pick asset-appropriate index field."""
    if requested_template_id not in SRC_IP_WEB_ACCESS_TEMPLATES:
        return requested_template_id
    catalog = templates.get("templates", templates)
    for template_id in ordered_template_candidates(asset, params):
        if template_id not in SRC_IP_WEB_ACCESS_TEMPLATES:
            continue
        template = catalog.get(template_id)
        if not template:
            continue
        if not connector_supports_template(template, connector.get("connector_type", "")):
            continue
        if params_satisfy_template(template, params):
            return template_id
    return requested_template_id


def build_fetch_plan(
    asset_ids: list[str],
    params: dict[str, Any],
    *,
    load_asset: Callable[[str], dict[str, Any]],
    load_connector: Callable[[str], dict[str, Any]],
    load_templates: Callable[[], dict[str, Any]],
) -> list[dict[str, str]]:
    """Expand assets to (asset_id, connector_id, template_id) for multi-source fetch."""
    templates = load_templates()
    plan: list[dict[str, str]] = []
    for asset_id in asset_ids:
        asset = load_asset(asset_id)
        connector_ids = filter_connectors_by_host(
            asset, resolve_connector_ids(asset), params, load_connector
        )
        for connector_id in connector_ids:
            connector = load_connector(connector_id)
            template_id, _ = select_template_for_asset(asset, connector, params, templates)
            if template_id:
                plan.append(
                    {
                        "asset_id": asset_id,
                        "connector_id": connector_id,
                        "template_id": template_id,
                    }
                )
    return plan


def build_template_map_for_assets(
    asset_ids: list[str],
    params: dict[str, Any],
    *,
    load_asset,
    load_connector,
    load_templates,
) -> dict[str, str]:
    """Map asset_id → template_id (first connector in fetch plan; backward compatible)."""
    mapping: dict[str, str] = {}
    for item in build_fetch_plan(
        asset_ids, params, load_asset=load_asset, load_connector=load_connector, load_templates=load_templates
    ):
        mapping.setdefault(item["asset_id"], item["template_id"])
    return mapping
