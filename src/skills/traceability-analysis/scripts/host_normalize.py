"""Host identity normalization for traceability (generic + TigerSec adapter)."""

from __future__ import annotations

import copy
import sys
from pathlib import Path
from typing import Any

from source_adapters.tigersec import (  # noqa: E402
    extract_host_ip_from_event,
    extract_ssh_lateral_targets,
    is_plausible_ip,
    is_web_listener_exec,
)

DATA_ACCESS_PATH = Path(__file__).resolve().parents[2] / "_shared" / "data-access"

GENERIC_HOSTS = frozenset(
    {
        "localhost",
        "localhost.localdomain",
        "127.0.0.1",
        "::1",
        "unknown",
    }
)


def is_generic_host(value: Any) -> bool:
    if value in (None, ""):
        return True
    text = str(value).strip().lower()
    if text in GENERIC_HOSTS:
        return True
    return text.startswith("localhost")


def investigation_host_set(params: dict[str, Any], host_ip_map: dict[str, str] | None = None) -> set[str]:
    hosts: set[str] = set()
    for key in ("hosts", "seed_hosts"):
        for item in params.get(key) or []:
            if item:
                hosts.add(str(item))
    for key, val in (host_ip_map or {}).items():
        if is_plausible_ip(key):
            hosts.add(str(key))
        if is_plausible_ip(val):
            hosts.add(str(val))
    for key, val in (params.get("host_ips") or {}).items():
        if is_plausible_ip(key):
            hosts.add(str(key))
        if is_plausible_ip(val):
            hosts.add(str(val))
    return hosts


def remote_execution_context(command: str, source_host: str | None = None) -> dict[str, Any]:
    """Return canonical target metadata for SSH-family remote execution commands."""
    targets: list[str] = []
    users: list[str] = []
    for user, target in extract_ssh_lateral_targets(command or ""):
        if not target or target == source_host:
            continue
        if target not in targets:
            targets.append(target)
        if user and user != "?" and user not in users:
            users.append(user)
    if not targets:
        return {}
    context: dict[str, Any] = {
        "execution_target_host": targets[0],
        "execution_target_hosts": targets,
    }
    if users:
        context["execution_remote_user"] = users[0]
    return context


def victim_host_from_event(ev: dict[str, Any], host_ip_map: dict[str, str] | None = None) -> str | None:
    """Resolve the victim host IP/name for correlation and attack-chain stages."""
    host_ip_map = host_ip_map or {}
    ip = extract_host_ip_from_event(ev)
    if ip:
        return ip
    host = ev.get("host") or ev.get("host_name") or ev.get("hostname")
    if host and not is_generic_host(host):
        mapped = host_ip_map.get(str(host))
        if mapped and is_plausible_ip(mapped):
            return str(mapped)
        if is_plausible_ip(host):
            return str(host)
        return str(host)
    if host and is_generic_host(host):
        return extract_host_ip_from_event(ev)
    return None


def canonicalize_event_host(ev: dict[str, Any], host_ip_map: dict[str, str] | None = None) -> dict[str, Any]:
    """Return a copy with host/host_ip aligned to victim IP when possible."""
    out = dict(ev)
    host_ip_map = dict(host_ip_map or {})
    victim = victim_host_from_event(out, host_ip_map)
    if victim and is_plausible_ip(victim):
        out["host"] = victim
        out["host_ip"] = victim
        out["_canonical_host"] = victim
        return out
    if victim:
        out["host"] = victim
        out.setdefault("host_ip", victim)
        out["_canonical_host"] = victim
    return out


def build_trace_host_ip_map(bundles: dict[str, list[dict[str, Any]]], params: dict[str, Any]) -> dict[str, str]:
    """Extend params.host_ips with inventory and event-derived mappings."""
    mapping: dict[str, str] = dict(params.get("host_ips") or {})
    for item in bundles.get("asset_inventory") or []:
        host = item.get("hostname") or item.get("host")
        ip = item.get("ip")
        if host and ip:
            mapping[str(host)] = str(ip)
            mapping[str(ip)] = str(ip)
    for bundle in ("host_exec", "host_connect", "host_file_op", "ssh_auth"):
        for ev in bundles.get(bundle) or []:
            victim = victim_host_from_event(ev, mapping)
            if victim and is_plausible_ip(victim):
                mapping[victim] = victim
            host = ev.get("host") or ev.get("host_name")
            ip = ev.get("host_ip") or ev.get("_victim_host") or ev.get("__source__")
            if host and ip and not is_generic_host(host):
                mapping[str(host)] = str(ip)
            elif host and victim:
                mapping[str(host)] = victim
    for hip in params.get("hosts") or []:
        if is_plausible_ip(hip):
            mapping[str(hip)] = str(hip)
    return mapping


def normalize_bundles_for_trace(
    bundles: dict[str, list[dict[str, Any]]],
    params: dict[str, Any],
) -> dict[str, list[dict[str, Any]]]:
    """Deep-copy and canonicalize host fields before indexing / matrix joins."""
    host_ip_map = build_trace_host_ip_map(bundles, params)
    out: dict[str, list[dict[str, Any]]] = {}
    for bundle_type, events in (bundles or {}).items():
        normalized: list[dict[str, Any]] = []
        for ev in events or []:
            row = canonicalize_event_host(copy.deepcopy(ev), host_ip_map)
            normalized.append(row)
        out[bundle_type] = normalized
    return out


def investigation_scope_from_params(params: dict[str, Any]) -> tuple[set[str], set[str]]:
    """IPs and host_ids/hostnames in scope for hosts/ registry injection."""
    ips: set[str] = set()
    ids: set[str] = set()
    for key in ("hosts", "seed_hosts"):
        for item in params.get(key) or []:
            if not item:
                continue
            text = str(item)
            if is_plausible_ip(text):
                ips.add(text)
            else:
                ids.add(text)
    for key, val in (params.get("host_ips") or {}).items():
        if key:
            ids.add(str(key))
            if is_plausible_ip(key):
                ips.add(str(key))
        if val and is_plausible_ip(val):
            ips.add(str(val))
    for hid in params.get("host_ids") or []:
        if hid:
            ids.add(str(hid))
    return ips, ids


def ips_from_evidence_bundles(bundles: dict[str, list[dict[str, Any]]]) -> set[str]:
    ips: set[str] = set()
    for bundle in ("host_exec", "host_connect", "host_file_op", "ssh_auth"):
        for ev in bundles.get(bundle) or []:
            victim = victim_host_from_event(ev)
            if victim and is_plausible_ip(victim):
                ips.add(victim)
            dst = ev.get("dst_ip")
            if dst and is_plausible_ip(dst):
                ips.add(str(dst))
    return ips


def registered_host_to_inventory(host: dict[str, Any]) -> dict[str, Any]:
    """Map dataasset/hosts/*.json → asset_inventory event for host_to_cmdb join."""
    hip = str(host.get("host_ip") or "")
    cmdb_hostname = str(host.get("hostname") or host.get("host_id") or hip)
    join_hostname = hip or cmdb_hostname
    network_id = str(host.get("network_id") or "")
    return {
        "evidence_id": f"inventory-{host.get('host_id', cmdb_hostname)}",
        "source": "dataasset/hosts",
        "host_id": host.get("host_id"),
        "hostname": join_hostname,
        "host": join_hostname,
        "cmdb_hostname": cmdb_hostname,
        "name": host.get("name") or cmdb_hostname,
        "ip": hip,
        "host_ip": hip,
        "zone": network_id.replace("net-", "") if network_id.startswith("net-") else network_id,
        "network_id": network_id,
        "environment": host.get("environment"),
        "roles": list(host.get("roles") or []),
        "host_type": host.get("host_type"),
        "status": host.get("status"),
        "description": host.get("description"),
        "tags": list(host.get("tags") or []),
        "aliases": list(host.get("aliases") or []) + ([cmdb_hostname] if cmdb_hostname != join_hostname else []),
    }


def host_in_investigation_scope(
    host: dict[str, Any],
    scope_ips: set[str],
    scope_ids: set[str],
) -> bool:
    if not scope_ips and not scope_ids:
        return False
    hid = str(host.get("host_id") or "")
    hip = str(host.get("host_ip") or "")
    if hid in scope_ids or hip in scope_ips:
        return True
    if str(host.get("hostname") or "") in scope_ids:
        return True
    for alias in host.get("aliases") or []:
        if str(alias) in scope_ips:
            return True
    return False


def merge_registry_host_ips(
    params: dict[str, Any],
    inventory: list[dict[str, Any]],
) -> dict[str, Any]:
    """Extend params.host_ips from injected hosts/ registry rows."""
    out = dict(params)
    host_ips = dict(out.get("host_ips") or {})
    for row in inventory:
        if row.get("source") != "dataasset/hosts":
            continue
        hip = row.get("ip") or row.get("host_ip")
        if not hip:
            continue
        host_ips[str(hip)] = str(hip)
        hostname = row.get("hostname")
        if hostname:
            host_ips[str(hostname)] = str(hip)
        for alias in row.get("aliases") or []:
            host_ips[str(alias)] = str(hip)
    out["host_ips"] = host_ips
    return out


def inject_registered_hosts(
    bundles: dict[str, list[dict[str, Any]]],
    params: dict[str, Any],
) -> tuple[dict[str, list[dict[str, Any]]], list[str]]:
    """Load dataasset/hosts/ into evidence_bundles.asset_inventory for host_to_cmdb join."""
    out: dict[str, list[dict[str, Any]]] = {k: list(v or []) for k, v in (bundles or {}).items()}
    existing: set[str] = set()
    for item in out.get("asset_inventory") or []:
        for key in ("host_id", "evidence_id", "ip", "hostname"):
            val = item.get(key)
            if val:
                existing.add(str(val))

    if str(DATA_ACCESS_PATH) not in sys.path:
        sys.path.insert(0, str(DATA_ACCESS_PATH))
    from registry import list_hosts

    scope_ips, scope_ids = investigation_scope_from_params(params)
    if not scope_ips and not scope_ids:
        scope_ips = ips_from_evidence_bundles(out)

    injected_ids: list[str] = []
    for host in list_hosts(status="active"):
        if not host_in_investigation_scope(host, scope_ips, scope_ids):
            continue
        row = registered_host_to_inventory(host)
        keys = {str(row.get(k)) for k in ("host_id", "evidence_id", "ip", "hostname") if row.get(k)}
        if keys & existing:
            continue
        out.setdefault("asset_inventory", []).append(row)
        injected_ids.append(str(host.get("host_id") or row["evidence_id"]))
        existing.update(keys)

    return out, injected_ids


def inventory_lookup(
    inventory: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index asset_inventory by ip / hostname / host_id."""
    by_key: dict[str, dict[str, Any]] = {}
    for item in inventory:
        for key in ("ip", "host_ip", "hostname", "host", "host_id"):
            val = item.get(key)
            if val:
                by_key[str(val)] = item
        for alias in item.get("aliases") or []:
            by_key[str(alias)] = item
    return by_key


def enrich_impacted_with_registry(
    impacted: list[dict[str, Any]],
    inventory: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    lookup = inventory_lookup(inventory)
    enriched: list[dict[str, Any]] = []
    for row in impacted:
        item = dict(row)
        reg = lookup.get(str(item.get("host") or ""))
        if reg:
            item["host_id"] = reg.get("host_id")
            item["name"] = reg.get("name")
            item["network_id"] = reg.get("network_id")
            item["environment"] = reg.get("environment")
            item["roles"] = reg.get("roles")
            item["registry_source"] = "dataasset/hosts"
        enriched.append(item)
    return enriched
