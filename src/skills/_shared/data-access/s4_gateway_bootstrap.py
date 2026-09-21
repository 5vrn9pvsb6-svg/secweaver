"""S4 alert-confirmation gateway bootstrap — auto-append D1 when only WAF asset is selected.

WAF-only fetch cannot run gateway_miss_scan or gateway_success_hint. When the asset
list includes WAF but not gateway web_access, append production gateway (+ optional
host D2 assets for Layer 2) before bundle fetch.
"""

from __future__ import annotations

import os
from typing import Any

from registry import load_asset
from s4_fetch_bootstrap import _assets_by_type

# Public assets are canonical in the Community catalog. Private dataasset roots
# may still resolve this public id through registry.py to their TigerSec file.
DEFAULT_S4_GATEWAY_ASSET_ID = "asset-secweaver-gateway-access"
LEGACY_S4_GATEWAY_ASSET_IDS = ("asset-tigersec-tsin-access",)
S4_GATEWAY_ASSET_ENV = "SECWEAVER_S4_GATEWAY_ASSET_ID"
DEFAULT_S4_EXEC_ASSET_ID = "asset-secweaver-host-exec"
DEFAULT_S4_CONNECT_ASSET_ID = "asset-secweaver-host-connect"
DEFAULT_S4_FILE_OP_ASSET_ID = "asset-secweaver-host-file-op"


def resolve_s4_gateway_asset_id() -> str:
    """Resolve the S4 web-access source with an explicit compatibility policy.

    ``asset-secweaver-gateway-access`` is the canonical public web-access asset.
    Private dataasset roots may resolve it to ``asset-tigersec-tsin-access`` through
    the registry compatibility map; fallback is allowed only for a missing or
    wrongly typed asset, never after a live query fails, so logs from different
    gateways cannot be silently mixed during incident confirmation.
    """
    configured = str(os.environ.get(S4_GATEWAY_ASSET_ENV) or "").strip()
    candidates: list[str] = []
    for asset_id in (configured, DEFAULT_S4_GATEWAY_ASSET_ID, *LEGACY_S4_GATEWAY_ASSET_IDS):
        if asset_id and asset_id not in candidates:
            candidates.append(asset_id)

    for asset_id in candidates:
        try:
            asset = load_asset(asset_id)
        except (FileNotFoundError, OSError, ValueError):
            continue
        if str(asset.get("asset_type") or "") == "web_access_log":
            return asset_id

    # Keep the selected id visible in fetch metadata when a deployment has not
    # registered any candidate yet; the fetch layer will report the missing asset.
    return configured or DEFAULT_S4_GATEWAY_ASSET_ID


def should_s4_gateway_append(asset_ids: list[str] | None) -> bool:
    """True when WAF asset present but gateway web_access asset is missing."""
    if not asset_ids:
        return False
    by_type = _assets_by_type(asset_ids)
    return "waf_alert" in by_type and "web_access_log" not in by_type


def ensure_s4_alert_asset_ids(
    asset_ids: list[str] | None,
    *,
    include_exec: bool = True,
    include_connect: bool | None = None,
    include_file_op: bool | None = None,
) -> list[str]:
    """Append the canonical gateway and host D2 sources for WAF-only S4 input.

    The selected gateway id is resolved before appending so a private dataasset
    root can use the canonical file while older roots continue to work through
    the compatibility alias. Host evidence is still appended for Layer 2, but
    the later S4 phase will skip it when no valid upstream target is correlated.
    """
    merged = list(asset_ids or [])
    seen = set(merged)
    by_type = _assets_by_type(merged)
    if include_connect is None:
        include_connect = include_exec
    if include_file_op is None:
        include_file_op = include_exec

    if "waf_alert" in by_type and "web_access_log" not in by_type:
        gateway_asset_id = resolve_s4_gateway_asset_id()
        if gateway_asset_id not in seen:
            merged.append(gateway_asset_id)
            seen.add(gateway_asset_id)

    if include_exec and "host_exec" not in by_type:
        if DEFAULT_S4_EXEC_ASSET_ID not in seen:
            merged.append(DEFAULT_S4_EXEC_ASSET_ID)
            seen.add(DEFAULT_S4_EXEC_ASSET_ID)
    if include_connect and "host_connect" not in by_type:
        if DEFAULT_S4_CONNECT_ASSET_ID not in seen:
            merged.append(DEFAULT_S4_CONNECT_ASSET_ID)
            seen.add(DEFAULT_S4_CONNECT_ASSET_ID)
    if include_file_op and "host_file_op" not in by_type:
        if DEFAULT_S4_FILE_OP_ASSET_ID not in seen:
            merged.append(DEFAULT_S4_FILE_OP_ASSET_ID)
            seen.add(DEFAULT_S4_FILE_OP_ASSET_ID)

    return merged


def s4_gateway_bootstrap_meta(original_ids: list[str], merged_ids: list[str]) -> dict[str, Any]:
    """Describe the actual gateway asset appended to this fetch request.

    Reporting the resolved id matters operationally: the canonical asset and the
    legacy alias may point at different logstores, so a report must identify the
    source that was really queried rather than printing a static default.
    """
    appended = [aid for aid in merged_ids if aid not in set(original_ids)]
    gateway_asset_id = next(
        (
            aid
            for aid in appended
            if str(_asset_type(aid) or "") == "web_access_log"
        ),
        resolve_s4_gateway_asset_id(),
    )
    gateway_source = (
        "configured"
        if gateway_asset_id == str(os.environ.get(S4_GATEWAY_ASSET_ENV) or "").strip()
        else "preferred"
        if gateway_asset_id == DEFAULT_S4_GATEWAY_ASSET_ID
        else "legacy_compatibility"
    )
    return {
        "fetch_strategy": "s4_gateway_bootstrap+asset_list",
        "s4_gateway_bootstrap": {
            "original_asset_ids": list(original_ids),
            "appended_asset_ids": appended,
            "gateway_asset_id": gateway_asset_id,
            "gateway_asset_source": gateway_source,
            "exec_asset_id": DEFAULT_S4_EXEC_ASSET_ID if DEFAULT_S4_EXEC_ASSET_ID in appended else None,
            "connect_asset_id": DEFAULT_S4_CONNECT_ASSET_ID
            if DEFAULT_S4_CONNECT_ASSET_ID in appended
            else None,
            "file_op_asset_id": DEFAULT_S4_FILE_OP_ASSET_ID
            if DEFAULT_S4_FILE_OP_ASSET_ID in appended
            else None,
        },
    }


def _asset_type(asset_id: str) -> str | None:
    """Read an asset type for metadata without hiding a fetch-time asset error."""
    try:
        return str(load_asset(asset_id).get("asset_type") or "")
    except (FileNotFoundError, OSError, ValueError):
        return None
