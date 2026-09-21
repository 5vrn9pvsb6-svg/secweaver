"""Load dataasset registry: assets, connectors, bundles, templates."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from correlation_keys import derive_correlation_keys
from dataasset_paths import DATAASSET_ROOT
from field_inventory import canonical_fields, effective_fields


ASSET_ID_COMPATIBILITY_ALIASES = {
    "asset-secweaver-gateway-access": "asset-tigersec-tsin-access",
    "asset-secweaver-host-exec": "asset-tigersec-host-exec",
    "asset-secweaver-host-connect": "asset-tigersec-host-connect",
    "asset-secweaver-host-file-op": "asset-tigersec-host-file-op",
    "asset-secweaver-host-persistence": "asset-tigersec-host-persistence",
    "asset-secweaver-sys-risk-alert": "asset-tigersec-sys-risk-alert",
    "asset-ssh-demo-web-exec-file": "asset-ssh-101-24-file",
}


def _compatible_object_path(directory: str, object_id: str) -> Path:
    path = DATAASSET_ROOT / directory / f"{object_id}.json"
    if path.is_file():
        return path
    alias = ASSET_ID_COMPATIBILITY_ALIASES.get(object_id)
    if alias:
        alias_path = DATAASSET_ROOT / directory / f"{alias}.json"
        if alias_path.is_file():
            return alias_path
    return path


def _load_json(path: Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)


def load_asset(asset_id: str) -> dict[str, Any]:
    path = _compatible_object_path("assets", asset_id)
    if not path.is_file():
        raise FileNotFoundError(f"asset not found: {asset_id} ({path})")
    return _load_json(path)


def load_connector(connector_id: str) -> dict[str, Any]:
    path = DATAASSET_ROOT / "connectors" / f"{connector_id}.json"
    if not path.is_file():
        raise FileNotFoundError(f"connector not found: {connector_id}")
    return _load_json(path)


def load_bundle(bundle_id: str) -> dict[str, Any]:
    path = DATAASSET_ROOT / "bundles" / f"{bundle_id}.json"
    if not path.is_file():
        raise FileNotFoundError(f"bundle not found: {bundle_id}")
    return _load_json(path)


def load_templates() -> dict[str, Any]:
    return _load_json(DATAASSET_ROOT / "query-templates" / "templates.json")


def list_active_assets() -> list[dict[str, Any]]:
    assets: list[dict[str, Any]] = []
    assets_dir = DATAASSET_ROOT / "assets"
    for path in sorted(assets_dir.glob("*.json")):
        asset = _load_json(path)
        if asset.get("status") == "active":
            assets.append(asset)
    return assets


def coverage_to_list(coverage: dict[str, Any]) -> list[str]:
    items: list[str] = []
    for key in ("zones", "apps", "hosts"):
        for value in coverage.get(key, []):
            items.append(str(value))
    return items or ["any"]


def load_host(host_id: str) -> dict[str, Any]:
    path = DATAASSET_ROOT / "hosts" / f"{host_id}.json"
    if not path.is_file():
        raise FileNotFoundError(f"host not found: {host_id} ({path})")
    return _load_json(path)


def list_hosts(status: str | None = "active") -> list[dict[str, Any]]:
    hosts: list[dict[str, Any]] = []
    hosts_dir = DATAASSET_ROOT / "hosts"
    if not hosts_dir.is_dir():
        return hosts
    for path in sorted(hosts_dir.glob("*.json")):
        host = _load_json(path)
        if status is None or host.get("status") == status:
            hosts.append(host)
    return hosts


def host_registry_to_registered_asset(
    hosts: list[dict[str, Any]] | None = None,
) -> dict[str, Any] | None:
    """Expose dataasset/hosts as the built-in CMDB asset_inventory source."""
    active_hosts = list_hosts(status="active") if hosts is None else [
        host for host in hosts if host.get("status", "active") == "active"
    ]
    if not active_hosts:
        return None

    covered_hosts: list[str] = []
    for host in active_hosts:
        for value in (
            host.get("host_ip"),
            host.get("hostname"),
            host.get("host_id"),
            *(host.get("aliases") or []),
        ):
            text = str(value or "").strip()
            if text and text not in covered_hosts:
                covered_hosts.append(text)

    fields = [
        "host_id",
        "hostname",
        "ip",
        "host_ip",
        "network_id",
        "environment",
        "roles",
        "status",
    ]
    return {
        "asset_id": "registry-dataasset-hosts",
        "name": "dataasset/hosts 主机资产清单",
        "type": "asset_inventory",
        "domain": "D6",
        "fields": fields,
        "field_aliases": {"host_ip": "ip", "name": "hostname"},
        "canonical_fields": [],
        "effective_fields": fields,
        "correlation_keys": ["host", "host_ip"],
        "coverage": ["full", *covered_hosts],
        "coverage_detail": {
            "zones": ["full"],
            "apps": [],
            "hosts": covered_hosts,
        },
        "retention_days": 36500,
        "status": "registered",
        "credentials_ref": None,
        "connector_count": 0,
        "registry_source": "dataasset/hosts",
        "record_count": len(active_hosts),
    }


def asset_to_registered(asset: dict[str, Any]) -> dict[str, Any]:
    schema = asset.get("schema", {})
    st = asset.get("status")
    status = "registered" if st == "active" else "not_registered"
    fields = schema.get("fields", [])
    correlation_keys = derive_correlation_keys(asset)
    return {
        "asset_id": asset["asset_id"],
        "name": asset["name"],
        "type": asset["asset_type"],
        "covers_asset_types": list(asset.get("covers_asset_types") or []),
        "domain": asset.get("domain", ""),
        "fields": fields,
        "field_aliases": asset.get("field_aliases", {}),
        "canonical_fields": sorted(canonical_fields(asset) - set(fields)),
        "effective_fields": sorted(effective_fields(asset)),
        "correlation_keys": correlation_keys,
        "coverage": coverage_to_list(asset.get("coverage", {})),
        "coverage_detail": asset.get("coverage") if isinstance(asset.get("coverage"), dict) else None,
        "retention_days": schema.get("retention_days", 0),
        "status": status,
        "credentials_ref": load_connector(asset["connector_id"]).get("credentials_ref"),
        "connector_count": len(resolve_asset_connector_ids(asset)),
    }


def bundle_to_registered_assets(bundle_id: str) -> list[dict[str, Any]]:
    bundle = load_bundle(bundle_id)
    assets: list[dict[str, Any]] = []
    for asset_id in bundle.get("asset_ids", []):
        asset = load_asset(asset_id)
        assets.append(asset_to_registered(asset))
    host_registry = host_registry_to_registered_asset()
    if host_registry and not any(
        asset.get("asset_id") == host_registry["asset_id"] for asset in assets
    ):
        assets.append(host_registry)
    return assets


def get_connector_for_asset(asset_id: str) -> dict[str, Any]:
    asset = load_asset(asset_id)
    return load_connector(asset["connector_id"])


def resolve_asset_connector_ids(asset: dict[str, Any]) -> list[str]:
    from aggregate import resolve_connector_ids

    return resolve_connector_ids(asset)


def render_template(template_id: str, params: dict[str, Any]) -> dict[str, Any]:
    from es_fetch import render_es_query
    from connector_registry import query_key_by_connector

    catalog = load_templates()
    template = catalog["templates"].get(template_id)
    if not template:
        raise KeyError(f"unknown template_id: {template_id}")

    merged = {**template.get("defaults", {}), **params}
    rendered: dict[str, Any] = {"template_id": template_id, "params": merged}

    query_keys = {
        "sls_query",
        "sql",
        "ssh_command",
        "stream_query",
        "local_file_command",
        "syslog_query",
        "cloudwatch_query",
        "object_query",
        "kql",
        "gcp_logging_filter",
        "cls_query",
        "lts_query",
        "splunk_search",
    }
    query_keys.update(query_key_by_connector().values())
    for key in sorted(query_keys):
        raw = template.get(key)
        if raw:
            rendered[key] = raw.format(**merged) if isinstance(raw, str) else render_es_query(raw, merged)
    es_query = template.get("es_query")
    if es_query:
        rendered["es_query"] = render_es_query(es_query, merged)
    return rendered
