"""Static runtime-readiness assessment for DataAsset bundle graphs."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

try:
    from ..credential_contracts import credential_secret_path, validate_credentials_ref
    from ..transport_contracts import resolve_ca_file, validate_secure_endpoint
    from .connector_contracts import connector_runtime_modes
except ImportError:  # validate.py also supports direct script execution.
    from credential_contracts import credential_secret_path, validate_credentials_ref
    from transport_contracts import resolve_ca_file, validate_secure_endpoint
    from validate_lib.connector_contracts import connector_runtime_modes


PLACEHOLDER_TOKEN = re.compile(r"(?:^|[^A-Z0-9])YOUR_[A-Z0-9_]+(?:$|[^A-Z0-9])", re.IGNORECASE)


def _contains_placeholder(value: Any) -> bool:
    """Detect explicit onboarding placeholders without rejecting real host names."""
    if isinstance(value, dict):
        return any(_contains_placeholder(item) for item in value.values())
    if isinstance(value, list):
        return any(_contains_placeholder(item) for item in value)
    if not isinstance(value, str):
        return False
    text = value.strip()
    return bool(PLACEHOLDER_TOKEN.search(text)) or text.upper() in {"TODO", "TBD", "REPLACE_ME"}


def _connector_ids(asset: dict[str, Any]) -> list[str]:
    values = [asset.get("connector_id"), *(asset.get("connector_ids") or [])]
    return list(dict.fromkeys(str(value) for value in values if value))


def _credential_file(root: Path, credential_ref: str) -> Path:
    return credential_secret_path(root / "credentials", credential_ref)


def _blocker(
    code: str,
    message: str,
    *,
    object_type: str,
    object_id: str,
    path: Path | None = None,
) -> dict[str, str]:
    return {
        "code": code,
        "message": message,
        "object_type": object_type,
        "object_id": object_id,
        "path": str(path or ""),
    }


def _assess_connector(
    root: Path,
    connector_id: str,
    connectors: dict[str, tuple[Path, dict[str, Any]]],
    credential_statuses: dict[str, str],
    validation_blockers: dict[tuple[str, str], list[dict[str, str]]],
    *,
    visited: set[str],
) -> list[dict[str, str]]:
    """Check one connector and its declared sink without resolving credentials.

    Sink traversal is bounded by connector ids already seen. A cycle is reported
    as a configuration blocker rather than recursing indefinitely.
    """
    if connector_id in visited:
        return [
            _blocker(
                "runtime-connector-cycle",
                f"connector chain contains a cycle at {connector_id}",
                object_type="connector",
                object_id=connector_id,
            )
        ]
    item = connectors.get(connector_id)
    if item is None:
        return [
            _blocker(
                "runtime-connector-missing",
                f"connector {connector_id!r} does not exist",
                object_type="connector",
                object_id=connector_id,
            )
        ]

    path, connector = item
    blockers = list(validation_blockers.get(("connector", connector_id), []))
    status = str(connector.get("status") or "draft")
    if status != "active":
        blockers.append(
            _blocker(
                "runtime-connector-inactive",
                f"connector {connector_id!r} is not active (status={status!r})",
                object_type="connector",
                object_id=connector_id,
                path=path,
            )
        )
    config = connector.get("config") or {}
    if _contains_placeholder(config):
        blockers.append(
            _blocker(
                "runtime-connector-placeholder",
                f"connector {connector_id!r} still contains onboarding placeholders",
                object_type="connector",
                object_id=connector_id,
                path=path,
            )
        )

    connector_type = str(connector.get("connector_type") or "")
    ca_file = config.get("ca_file")
    if ca_file is not None:
        try:
            resolve_ca_file(ca_file, root, label=f"{connector_type} connector")
        except ValueError as exc:
            blockers.append(
                _blocker(
                    "runtime-ca-file",
                    str(exc),
                    object_type="connector",
                    object_id=connector_id,
                    path=path,
                )
            )
    runtime = connector_runtime_modes(root).get(connector_type, "")
    if runtime in {"local_or_external_executor", "live_or_external_executor"}:
        endpoint = str(config.get("executor_endpoint") or config.get("external_endpoint") or "")
        if not endpoint and runtime == "local_or_external_executor":
            endpoint = str(config.get("endpoint") or config.get("base_url") or "")
        if endpoint:
            try:
                validate_secure_endpoint(endpoint, label=f"active {connector_type} external executor")
            except ValueError as exc:
                blockers.append(
                    _blocker(
                        "runtime-connector-transport",
                        str(exc),
                        object_type="connector",
                        object_id=connector_id,
                        path=path,
                    )
                )
    raw_credential_ref = str(connector.get("credentials_ref") or "")
    credential_ref = ""
    if raw_credential_ref:
        try:
            credential_ref = validate_credentials_ref(raw_credential_ref)
        except ValueError:
            blockers.append(
                _blocker(
                    "runtime-credential-ref",
                    f"connector {connector_id!r} has invalid credentials_ref {raw_credential_ref!r}",
                    object_type="connector",
                    object_id=connector_id,
                    path=path,
                )
            )
    if connector_type != "local_file":
        if not credential_ref:
            if not raw_credential_ref:
                blockers.append(
                    _blocker(
                        "runtime-credential-ref",
                        f"connector {connector_id!r} has no valid credentials_ref",
                        object_type="connector",
                        object_id=connector_id,
                        path=path,
                    )
                )
        elif credential_statuses.get(credential_ref) == "disabled":
            blockers.append(
                _blocker(
                    "runtime-credential-disabled",
                    f"credential {credential_ref!r} is disabled",
                    object_type="credential",
                    object_id=credential_ref,
                    path=_credential_file(root, credential_ref),
                )
            )
        elif not _credential_file(root, credential_ref).is_file():
            blockers.append(
                _blocker(
                    "runtime-credential-missing",
                    f"credential ciphertext for {credential_ref!r} is missing",
                    object_type="credential",
                    object_id=credential_ref,
                    path=_credential_file(root, credential_ref),
                )
            )

    sink_id = str(config.get("sink_connector_id") or "").strip()
    if connector_type == "agent_stream":
        if not sink_id:
            blockers.append(
                _blocker(
                    "runtime-connector-sink-missing",
                    f"agent_stream connector {connector_id!r} has no sink_connector_id",
                    object_type="connector",
                    object_id=connector_id,
                    path=path,
                )
            )
        else:
            blockers.extend(
                _assess_connector(
                    root,
                    sink_id,
                    connectors,
                    credential_statuses,
                    validation_blockers,
                    visited={*visited, connector_id},
                )
            )
    return blockers


def assess_runtime_readiness(
    root: Path,
    bundles: dict[str, tuple[Path, dict[str, Any]]],
    assets: dict[str, tuple[Path, dict[str, Any]]],
    connectors: dict[str, tuple[Path, dict[str, Any]]],
    credential_statuses: dict[str, str],
    *,
    bundle_ids: list[str] | None = None,
    validation_issues: list[Any] | None = None,
) -> dict[str, Any]:
    """Return derived bundle readiness from the complete local execution graph.

    This is intentionally static: encrypted credential presence is checked, but
    secrets are never decrypted and no backend is contacted. Operators must run
    the connectivity Skill after this gate to prove transport and data presence.
    """
    # Base validation remains the authority for object structure and references.
    # Indexing its errors by object lets readiness reuse that result instead of
    # maintaining a second, inevitably divergent Connector contract.
    validation_blockers: dict[tuple[str, str], list[dict[str, str]]] = {}
    registry_errors = 0
    for issue in validation_issues or []:
        severity = str(getattr(issue, "severity", ""))
        if severity != "error":
            continue
        registry_errors += 1
        object_type = str(getattr(issue, "object_type", "unknown"))
        object_id = str(getattr(issue, "object_id", ""))
        if object_type == "unknown" or not object_id:
            continue
        validation_blockers.setdefault((object_type, object_id), []).append(
            _blocker(
                "runtime-object-validation",
                str(getattr(issue, "message", "object validation failed")),
                object_type=object_type,
                object_id=object_id,
                path=Path(str(getattr(issue, "path", ""))) if getattr(issue, "path", "") else None,
            )
        )

    selected_ids = list(dict.fromkeys(bundle_ids or []))
    if not selected_ids:
        selected_ids = sorted(
            bundle_id
            for bundle_id, (_path, bundle) in bundles.items()
            if bundle.get("status") == "active"
        )

    rows: list[dict[str, Any]] = []
    for bundle_id in selected_ids:
        bundle_item = bundles.get(bundle_id)
        blockers = list(validation_blockers.get(("bundle", bundle_id), []))
        if bundle_item is None:
            blockers.append(
                _blocker(
                    "runtime-bundle-missing",
                    f"bundle {bundle_id!r} does not exist",
                    object_type="bundle",
                    object_id=bundle_id,
                )
            )
            rows.append(
                {
                    "bundle_id": bundle_id,
                    "status": "not_ready",
                    "asset_count": 0,
                    "blockers": blockers,
                }
            )
            continue

        bundle_path, bundle = bundle_item
        if bundle.get("status") != "active":
            blockers.append(
                _blocker(
                    "runtime-bundle-inactive",
                    f"bundle {bundle_id!r} is not active (status={bundle.get('status')!r})",
                    object_type="bundle",
                    object_id=bundle_id,
                    path=bundle_path,
                )
            )

        asset_ids = bundle.get("asset_ids") or []
        if not asset_ids:
            blockers.append(
                _blocker(
                    "runtime-bundle-empty",
                    f"bundle {bundle_id!r} contains no assets",
                    object_type="bundle",
                    object_id=bundle_id,
                    path=bundle_path,
                )
            )

        for asset_id in asset_ids:
            asset_item = assets.get(str(asset_id))
            if asset_item is None:
                blockers.append(
                    _blocker(
                        "runtime-asset-missing",
                        f"asset {asset_id!r} does not exist",
                        object_type="asset",
                        object_id=str(asset_id),
                    )
                )
                continue
            asset_path, asset = asset_item
            blockers.extend(validation_blockers.get(("asset", str(asset_id)), []))
            asset_status = str(asset.get("status") or "draft")
            if asset_status != "active":
                blockers.append(
                    _blocker(
                        "runtime-asset-inactive",
                        f"asset {asset_id!r} is not active (status={asset_status!r})",
                        object_type="asset",
                        object_id=str(asset_id),
                        path=asset_path,
                    )
                )
            for connector_id in _connector_ids(asset):
                blockers.extend(
                    _assess_connector(
                        root,
                        connector_id,
                        connectors,
                        credential_statuses,
                        validation_blockers,
                        visited=set(),
                    )
                )

        # One connector may serve several assets. Deduplicate identical blockers
        # so the report remains bounded and points to each repair only once.
        unique: list[dict[str, str]] = []
        seen: set[tuple[str, str, str]] = set()
        for blocker in blockers:
            key = (blocker["code"], blocker["object_id"], blocker["message"])
            if key not in seen:
                seen.add(key)
                unique.append(blocker)
        rows.append(
            {
                "bundle_id": bundle_id,
                "status": "ready" if not unique else "not_ready",
                "asset_count": len(asset_ids),
                "blockers": unique,
            }
        )

    ready = [row["bundle_id"] for row in rows if row["status"] == "ready"]
    not_ready = [row["bundle_id"] for row in rows if row["status"] != "ready"]
    return {
        "mode": "static",
        "live_connectivity_checked": False,
        "registry_valid": registry_errors == 0,
        "ready_for_execution": registry_errors == 0 and not not_ready,
        "summary": {
            "checked_bundle_count": len(rows),
            "ready_bundle_count": len(ready),
            "not_ready_bundle_count": len(not_ready),
        },
        "ready_bundle_ids": ready,
        "not_ready_bundle_ids": not_ready,
        "bundles": rows,
    }
