"""Derive per-asset correlation keys from correlation-matrix + schema.fields."""

from __future__ import annotations

from functools import lru_cache
from typing import Any

from correlation_engine import expand_path, get_join, load_matrix
from normalizer import field_aliases


def _join_side_keys(join_def: dict[str, Any], side: str) -> set[str]:
    keys: set[str] = set()
    for block in (join_def.get("join_keys") or []) + (join_def.get("secondary_keys") or []):
        key = block.get(side)
        if key:
            keys.add(str(key))
    return keys


def _collect_join_keys(matrix: dict[str, Any], join_def: dict[str, Any], asset_type: str) -> set[str]:
    keys: set[str] = set()
    join_id = join_def.get("id")
    if join_def.get("path") and join_id:
        for step_id in expand_path(str(join_id), matrix):
            step = get_join(step_id, matrix)
            if step:
                keys |= _collect_join_keys(matrix, step, asset_type)
        return keys

    from_type = join_def.get("from_asset_type")
    to_type = join_def.get("to_asset_type")
    if from_type == asset_type:
        keys |= _join_side_keys(join_def, "left")
    if to_type == asset_type:
        keys |= _join_side_keys(join_def, "right")
    return keys


@lru_cache(maxsize=1)
def matrix_canonical_keys_by_asset_type() -> dict[str, frozenset[str]]:
    matrix = load_matrix()
    out: dict[str, set[str]] = {}
    for section in ("internal_joins", "cross_source_joins"):
        for join_def in matrix.get(section) or []:
            for asset_type in (join_def.get("from_asset_type"), join_def.get("to_asset_type")):
                if not asset_type:
                    continue
                out.setdefault(str(asset_type), set()).update(
                    _collect_join_keys(matrix, join_def, str(asset_type))
                )
    for asset_type in out:
        out[asset_type].add("timestamp")
    return {k: frozenset(v) for k, v in out.items()}


def available_canonical_fields(asset: dict[str, Any], matrix: dict[str, Any] | None = None) -> set[str]:
    """Field names reachable from schema.fields after global/asset aliases and time_field."""
    matrix = matrix or load_matrix()
    schema = asset.get("schema") or {}
    raw = {str(f) for f in (schema.get("fields") or [])}
    available = set(raw)

    aliases = field_aliases(asset)
    for src, dst in aliases.items():
        if src in raw or dst in raw:
            available.add(str(dst))

    time_field = schema.get("time_field") or "timestamp"
    if time_field in raw:
        available.add(str(time_field))
    if time_field != "timestamp" and any(t in raw for t in ("timestamp", "time", "__time__", "@timestamp", "ts")):
        available.add("timestamp")

    return available


_PRIORITY = (
    "timestamp",
    "src_ip",
    "host",
    "url",
    "alert_id",
    "host_ip",
    "dst_ip",
    "dst_port",
    "pid",
    "listener_pid",
    "listener_port",
    "user",
    "hostname",
    "ip",
    "client_ip",
    "query",
    "response",
)


def derive_correlation_keys(asset: dict[str, Any], matrix: dict[str, Any] | None = None) -> list[str]:
    """
    Intersection of matrix join keys for asset_type and fields available on this asset.

    Replaces hand-written schema.correlation_keys.
    """
    matrix = matrix or load_matrix()
    asset_type = str(asset.get("asset_type") or "")
    asset_types = [asset_type, *(str(t) for t in (asset.get("covers_asset_types") or []))]
    needed: set[str] = set()
    keys_by_type = matrix_canonical_keys_by_asset_type()
    for item_type in asset_types:
        if item_type:
            needed.update(keys_by_type.get(item_type, frozenset()))
    if not needed:
        needed.add("timestamp")
    available = available_canonical_fields(asset, matrix)

    ordered: list[str] = []
    for key in _PRIORITY:
        if key in needed and key in available and key not in ordered:
            ordered.append(key)
    for key in sorted(needed):
        if key in available and key not in ordered:
            ordered.append(key)
    return ordered


def enrich_asset_schema(asset: dict[str, Any], matrix: dict[str, Any] | None = None) -> dict[str, Any]:
    """Return schema dict with derived correlation_keys (does not mutate asset)."""
    schema = dict(asset.get("schema") or {})
    schema["correlation_keys"] = derive_correlation_keys(asset, matrix)
    return schema
