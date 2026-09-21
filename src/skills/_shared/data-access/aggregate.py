"""Multi-connector aggregation for a single logical asset."""

from __future__ import annotations

from typing import Any, Callable


def resolve_connector_ids(asset: dict[str, Any]) -> list[str]:
    """Return ordered unique connector ids for an asset (primary first)."""
    primary = asset.get("connector_id")
    extra = list(asset.get("connector_ids") or [])
    ordered: list[str] = []
    if primary:
        ordered.append(primary)
    for cid in extra:
        if cid and cid not in ordered:
            ordered.append(cid)
    return ordered


def is_aggregated(asset: dict[str, Any]) -> bool:
    return len(resolve_connector_ids(asset)) > 1


def _connector_host_label(connector: dict[str, Any]) -> str | None:
    config = connector.get("config") or {}
    return config.get("hostname")


def filter_connectors_by_host(
    asset: dict[str, Any],
    connector_ids: list[str],
    params: dict[str, Any],
    load_connector: Callable[[str], dict[str, Any]],
) -> list[str]:
    """When params.host is set, include host-bound connectors only if they match."""
    host = params.get("host")
    if not host:
        return connector_ids

    bound: list[str] = []
    global_sources: list[str] = []
    for cid in connector_ids:
        connector = load_connector(cid)
        label = _connector_host_label(connector)
        if not label:
            global_sources.append(cid)
            continue
        if str(label) == str(host):
            bound.append(cid)

    if bound:
        return bound + global_sources
    return connector_ids


def dedupe_events(events: list[dict[str, Any]], keys: list[str]) -> list[dict[str, Any]]:
    seen: set[tuple[str, ...]] = set()
    out: list[dict[str, Any]] = []
    for ev in events:
        sig = tuple(str(ev.get(k) or "") for k in keys)
        if sig in seen and any(sig):
            continue
        seen.add(sig)
        out.append(ev)
    return out


def merge_aggregate_events(asset: dict[str, Any], events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    agg = asset.get("aggregate") or {}
    keys = agg.get("dedupe_by") or ["evidence_id"]
    merged = dedupe_events(events, keys)
    max_events = agg.get("max_events")
    if max_events is not None:
        merged = merged[: int(max_events)]
    return merged
