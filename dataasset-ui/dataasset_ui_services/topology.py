"""Topology graph builder for the DataAsset UI."""

from __future__ import annotations

from typing import Any

from .common import ASSETS_DIR, EXCLUDED_ASSET_FILES, HOSTS_DIR, NETWORKS_DIR, read_json


def _asset_topology_summary(asset: dict[str, Any]) -> dict[str, Any]:
    return {
        "asset_id": asset.get("asset_id"),
        "name": asset.get("name"),
        "asset_type": asset.get("asset_type"),
        "domain": asset.get("domain"),
        "coverage_hosts": (asset.get("coverage") or {}).get("hosts") or [],
    }


def _resolve_external_ip(host: dict[str, Any]) -> str:
    exposure = host.get("exposure") if isinstance(host.get("exposure"), dict) else {}
    return str(exposure.get("internet_ip") or "").strip()


def _host_topology_summary(host: dict[str, Any], assets: list[dict[str, Any]]) -> dict[str, Any]:
    host_ip = str(host.get("host_ip") or "").strip()
    external_ip = _resolve_external_ip(host)
    if external_ip and external_ip == host_ip:
        external_ip = ""
    return {
        "host_id": host.get("host_id"),
        "name": host.get("name"),
        "hostname": host.get("hostname"),
        "host_ip": host_ip or host.get("host_ip"),
        "external_ip": external_ip,
        "host_type": host.get("host_type"),
        "host_os": host.get("host_os"),
        "zone": host.get("zone"),
        "description": host.get("description") or host.get("source_host_description") or "",
        "roles": host.get("roles") or [],
        "assets": assets,
        "asset_count": len(assets),
    }


def _index_active_hosts(hosts: list[dict[str, Any]]) -> tuple[dict[str, dict], dict[str, dict], dict[str, dict]]:
    by_id: dict[str, dict] = {}
    by_hostname: dict[str, dict] = {}
    by_alias: dict[str, dict] = {}
    for host in hosts:
        host_id = str(host.get("host_id") or "")
        if not host_id:
            continue
        by_id[host_id] = host
        hostname = str(host.get("hostname") or "").strip().lower()
        if hostname:
            by_hostname[hostname] = host
        for alias in host.get("aliases") or []:
            key = str(alias).strip().lower()
            if key:
                by_alias[key] = host
        host_ip = str(host.get("host_ip") or "").strip().lower()
        if host_ip:
            by_alias[host_ip] = host
    return by_id, by_hostname, by_alias


def _match_coverage_host_ids(
    asset: dict[str, Any],
    *,
    by_hostname: dict[str, dict],
    by_alias: dict[str, dict],
) -> list[str]:
    """Resolve active host ids from asset.coverage.hosts (log source IPs)."""
    matched: list[str] = []
    seen: set[str] = set()
    coverage_hosts = (asset.get("coverage") or {}).get("hosts") or []
    for token in coverage_hosts:
        key = str(token).strip().lower()
        if not key:
            continue
        host = by_hostname.get(key) or by_alias.get(key)
        if not host:
            continue
        host_id = str(host.get("host_id") or "")
        if host_id and host_id not in seen:
            seen.add(host_id)
            matched.append(host_id)
    return matched


def _resolve_asset_host_ids(
    asset: dict[str, Any],
    *,
    by_hostname: dict[str, dict],
    by_alias: dict[str, dict],
) -> tuple[list[str], str]:
    """Topology links are derived only from coverage.hosts after removing asset-side host binding."""
    coverage_ids = _match_coverage_host_ids(asset, by_hostname=by_hostname, by_alias=by_alias)
    if coverage_ids:
        link_kind = "single" if len(coverage_ids) == 1 else "coverage"
        return coverage_ids, link_kind
    return [], "platform"


def build_topology() -> dict[str, Any]:
    """Active-only network -> host -> asset graph for the home page."""
    networks: list[dict[str, Any]] = []
    for path in sorted(NETWORKS_DIR.glob("*.json")):
        data = read_json(path)
        if data.get("status") == "active":
            networks.append(data)

    hosts: list[dict[str, Any]] = []
    for path in sorted(HOSTS_DIR.glob("*.json")):
        data = read_json(path)
        if data.get("status") == "active":
            hosts.append(data)

    assets: list[dict[str, Any]] = []
    for path in sorted(ASSETS_DIR.glob("*.json")):
        if path.name in EXCLUDED_ASSET_FILES:
            continue
        data = read_json(path)
        if data.get("status") == "active":
            assets.append(data)

    by_id, by_hostname, by_alias = _index_active_hosts(hosts)
    host_assets: dict[str, list[dict[str, Any]]] = {host_id: [] for host_id in by_id}
    platform_assets: list[dict[str, Any]] = []
    aggregated_assets: list[dict[str, Any]] = []
    unbound_assets: list[dict[str, Any]] = []

    for asset in assets:
        summary = _asset_topology_summary(asset)
        host_ids, link_kind = _resolve_asset_host_ids(
            asset,
            by_hostname=by_hostname,
            by_alias=by_alias,
        )
        summary["link_kind"] = link_kind
        if link_kind == "platform":
            platform_assets.append(summary)
            continue
        if link_kind == "coverage":
            summary["coverage_hosts"] = (asset.get("coverage") or {}).get("hosts") or []
            aggregated_assets.append(summary)
        for host_id in host_ids:
            host_assets.setdefault(host_id, []).append(summary)

    hosts_by_network: dict[str, list[dict[str, Any]]] = {}
    orphan_hosts: list[dict[str, Any]] = []
    for host in hosts:
        network_id = str(host.get("network_id") or "")
        host_id = str(host.get("host_id") or "")
        host_summary = _host_topology_summary(host, host_assets.get(host_id, []))
        if network_id:
            hosts_by_network.setdefault(network_id, []).append(host_summary)
        else:
            orphan_hosts.append(host_summary)

    network_nodes: list[dict[str, Any]] = []
    for network in networks:
        network_id = str(network.get("network_id") or "")
        net_hosts = sorted(
            hosts_by_network.get(network_id, []),
            key=lambda item: str(item.get("hostname") or item.get("host_id") or ""),
        )
        asset_count = sum(item.get("asset_count", 0) for item in net_hosts)
        network_nodes.append(
            {
                "network_id": network_id,
                "name": network.get("name"),
                "cidr": network.get("cidr"),
                "zone": network.get("zone"),
                "network_type": network.get("network_type"),
                "trust_level": network.get("trust_level"),
                "hosts": net_hosts,
                "host_count": len(net_hosts),
                "asset_count": asset_count,
            }
        )

    network_nodes.sort(key=lambda item: (-item.get("host_count", 0), str(item.get("name") or "")))

    return {
        "networks": network_nodes,
        "orphan_hosts": orphan_hosts,
        "platform_assets": platform_assets,
        "aggregated_assets": aggregated_assets,
        "unbound_assets": unbound_assets,
        "stats": {
            "networks": len(network_nodes),
            "hosts": len(hosts),
            "assets": len(assets),
            "linked_assets": len(assets) - len(platform_assets) - len(unbound_assets),
            "platform_assets": len(platform_assets),
            "aggregated_assets": len(aggregated_assets),
            "unbound_assets": len(unbound_assets),
        },
    }
