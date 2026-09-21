"""Resolve canonical or raw field values for correlation-matrix joins."""

from __future__ import annotations

import json
from functools import lru_cache
from typing import Any

from dataasset_paths import DATAASSET_ROOT
from normalizer import field_aliases as normalizer_aliases
from normalizer import normalize_ip

MATRIX_PATH = DATAASSET_ROOT / "assets" / "correlation-matrix.json"


@lru_cache(maxsize=1)
def load_correlation_matrix() -> dict[str, Any]:
    with MATRIX_PATH.open(encoding="utf-8") as f:
        return json.load(f)


def _merged_aliases(asset: dict[str, Any] | None, matrix: dict[str, Any]) -> dict[str, str]:
    """Global + asset-level aliases. Matrix no longer owns normalization aliases."""
    return dict(normalizer_aliases(asset))


def field_candidates(
    field_name: str,
    *,
    matrix: dict[str, Any] | None = None,
    asset: dict[str, Any] | None = None,
    asset_type: str | None = None,
    extra_variants: list[str] | None = None,
) -> list[str]:
    """Ordered candidate keys for a matrix join key.

    The join key may be canonical (host) or source/raw (host_name). We first try
    the declared key, then join-local variants, then alias reverse/forward forms.
    """
    matrix = matrix or load_correlation_matrix()
    names: list[str] = [str(field_name)]
    for variant in extra_variants or []:
        variant = str(variant)
        if variant not in names:
            names.append(variant)

    aliases = _merged_aliases(asset, matrix)
    declared = str(field_name)

    # If declared is canonical, add source keys that map to it.
    for src, dst in aliases.items():
        if dst == declared and src not in names:
            names.append(src)

    # If declared is a source key, add its canonical destination and sibling source keys.
    mapped = aliases.get(declared)
    if mapped:
        if mapped not in names:
            names.append(mapped)
        for src, dst in aliases.items():
            if dst == mapped and src not in names:
                names.append(src)

    return names


def canonical_variants(
    canonical: str,
    *,
    matrix: dict[str, Any] | None = None,
    asset_type: str | None = None,
    extra_variants: list[str] | None = None,
) -> list[str]:
    """Backward-compatible candidate list for callers that expect canonical-first variants."""
    return field_candidates(
        canonical,
        matrix=matrix,
        asset=None,
        asset_type=asset_type,
        extra_variants=extra_variants,
    )


def alias_source_keys(field_name: str, asset: dict[str, Any] | None, matrix: dict[str, Any]) -> list[str]:
    """Source keys that map to a declared canonical field via global/asset aliases."""
    sources: list[str] = []
    for src, dst in _merged_aliases(asset, matrix).items():
        if dst == field_name and src not in sources:
            sources.append(src)
    return sources


def resolve_field_value(
    event: dict[str, Any],
    field_name: str,
    *,
    asset: dict[str, Any] | None = None,
    asset_type: str | None = None,
    extra_variants: list[str] | None = None,
    matrix: dict[str, Any] | None = None,
) -> Any:
    """Read a join field from canonical or raw/aliased evidence."""
    if not event:
        return None
    matrix = matrix or load_correlation_matrix()
    asset_type = asset_type or (asset or {}).get("asset_type")

    for key in field_candidates(
        field_name,
        matrix=matrix,
        asset=asset,
        asset_type=asset_type,
        extra_variants=extra_variants,
    ):
        if key in event and event[key] not in (None, ""):
            return event[key]

    return None


def join_key_candidates(
    side: str,
    join_key: dict[str, Any],
    *,
    asset: dict[str, Any] | None = None,
    asset_type: str | None = None,
    matrix: dict[str, Any] | None = None,
) -> tuple[str, list[str]]:
    """Return (declared field name, all candidate keys) for one join key side."""
    matrix = matrix or load_correlation_matrix()
    declared = str(join_key.get(side) or "")
    variant_key = f"{side}_variants"
    extra = [str(v) for v in (join_key.get(variant_key) or [])]
    candidates = field_candidates(
        declared,
        matrix=matrix,
        asset=asset,
        asset_type=asset_type,
        extra_variants=extra,
    )
    return declared, candidates


def _is_ip_field(field_name: str | None) -> bool:
    """Identify join fields whose values must use canonical IP semantics."""
    return str(field_name or "").strip().lower() in {
        "src_ip",
        "source_ip",
        "attacker_ip",
        "client_ip",
        "remote_addr",
        "rhost",
        "target_ip",
        "host_ip",
        "upstream_addr",
    }


def values_match(
    left: Any,
    right: Any,
    match: str = "exact",
    *,
    left_field: str | None = None,
    right_field: str | None = None,
) -> bool:
    """Compare join values, normalizing IP fields before exact matching."""
    if left in (None, "") or right in (None, ""):
        return False
    if match == "exact":
        if _is_ip_field(left_field) or _is_ip_field(right_field):
            left_ip = normalize_ip(left)
            right_ip = normalize_ip(right)
            return left_ip is not None and left_ip == right_ip
        return str(left).strip().lower() == str(right).strip().lower()
    return str(left).strip().lower() == str(right).strip().lower()


def match_join_key(
    left_event: dict[str, Any],
    right_event: dict[str, Any],
    join_key: dict[str, Any],
    *,
    left_asset: dict[str, Any] | None = None,
    right_asset: dict[str, Any] | None = None,
    matrix: dict[str, Any] | None = None,
) -> bool:
    """Evaluate one join key row using canonical + raw/alias fallback."""
    matrix = matrix or load_correlation_matrix()
    match = str(join_key.get("match") or "exact")
    left_type = (left_asset or {}).get("asset_type")
    right_type = (right_asset or {}).get("asset_type")

    left_val = resolve_field_value(
        left_event,
        str(join_key.get("left") or ""),
        asset=left_asset,
        asset_type=left_type,
        extra_variants=[str(v) for v in (join_key.get("left_variants") or [])],
        matrix=matrix,
    )
    right_val = resolve_field_value(
        right_event,
        str(join_key.get("right") or ""),
        asset=right_asset,
        asset_type=right_type,
        extra_variants=[str(v) for v in (join_key.get("right_variants") or [])],
        matrix=matrix,
    )
    return values_match(
        left_val,
        right_val,
        match,
        left_field=str(join_key.get("left") or ""),
        right_field=str(join_key.get("right") or ""),
    )
