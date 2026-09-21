"""Shared field inventory and completeness checks for data assets."""

from __future__ import annotations

from typing import Any

from correlation_engine import load_matrix
from normalizer import field_aliases


def raw_fields(asset: dict[str, Any]) -> set[str]:
    """Raw/source field names declared by a full DataAsset or registered asset."""
    schema = asset.get("schema") if isinstance(asset.get("schema"), dict) else {}
    fields = schema.get("fields") if schema else asset.get("fields")
    return {str(f) for f in (fields or [])}


def canonical_fields(asset: dict[str, Any], matrix: dict[str, Any] | None = None) -> set[str]:
    """Canonical field names reachable from raw fields via global/asset aliases and time_field."""
    matrix = matrix or load_matrix()
    raw = raw_fields(asset)
    available = set(raw)

    aliases = field_aliases(asset)
    changed = True
    while changed:
        changed = False
        for src, dst in aliases.items():
            src_text = str(src)
            dst_text = str(dst)
            if src_text in available or dst_text in raw or src_text.startswith("__"):
                if dst_text not in available:
                    available.add(dst_text)
                    changed = True

    schema = asset.get("schema") if isinstance(asset.get("schema"), dict) else {}
    time_field = asset.get("time_field") or schema.get("time_field") or "timestamp"
    if time_field in raw:
        available.add(str(time_field))
    if time_field != "timestamp" and any(t in raw for t in ("timestamp", "time", "__time__", "@timestamp", "ts")):
        available.add("timestamp")

    return available


def effective_fields(asset: dict[str, Any], matrix: dict[str, Any] | None = None) -> set[str]:
    """All usable fields for semantic checks: raw fields plus reachable canonical fields."""
    return raw_fields(asset) | canonical_fields(asset, matrix)


def check_required_fields(
    asset: dict[str, Any],
    required: list[str],
    matrix: dict[str, Any] | None = None,
) -> tuple[bool, list[str]]:
    """Return whether required canonical/raw fields are available and which are missing."""
    have = effective_fields(asset, matrix)
    missing = [str(f) for f in required if str(f) not in have]
    return len(missing) == 0, missing


def explain_field_coverage(
    asset: dict[str, Any],
    required: list[str],
    matrix: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Debug-friendly field coverage summary for Skill outputs and troubleshooting."""
    raw = raw_fields(asset)
    canonical = canonical_fields(asset, matrix)
    ok, missing = check_required_fields(asset, required, matrix)
    return {
        "ok": ok,
        "missing": missing,
        "raw_fields": sorted(raw),
        "canonical_fields": sorted(canonical - raw),
        "effective_fields": sorted(raw | canonical),
        "field_aliases": dict(asset.get("field_aliases") or {}),
    }
