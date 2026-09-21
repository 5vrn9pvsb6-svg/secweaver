"""Migrate DataAsset connector catalogs to the current format contract."""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any

FORMAT_VERSION = "2.0"
CATALOG_NAMES = ("connector-catalog.json", "external-connectors.json")
LEGACY_PROFILE_NAME = "onboarding-connector-profiles.json"


def _read_object(path: Path) -> dict[str, Any]:
    """Read a JSON object and fail with a path-specific migration error."""
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError(f"cannot read JSON object {path}: {exc}") from exc
    if not isinstance(value, dict):
        raise ValueError(f"expected JSON object in {path}")
    return value


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    """Replace one catalog atomically so interruption cannot leave partial JSON."""
    path.parent.mkdir(parents=True, exist_ok=True)
    descriptor, temporary_name = tempfile.mkstemp(prefix=f".{path.name}.", dir=path.parent)
    temporary = Path(temporary_name)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
            json.dump(value, handle, ensure_ascii=False, indent=2)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        temporary.replace(path)
    except Exception:
        temporary.unlink(missing_ok=True)
        raise


def _legacy_profiles(root: Path) -> dict[str, dict[str, Any]]:
    path = root / "configure" / LEGACY_PROFILE_NAME
    if not path.is_file():
        return {}
    value = _read_object(path).get("profiles")
    if not isinstance(value, dict):
        raise ValueError(f"expected profiles object in {path}")
    return {str(key): profile for key, profile in value.items() if isinstance(profile, dict)}


def _template_name(root: Path, connector_type: str) -> str:
    """Prefer a type-specific skeleton and otherwise use the external fallback."""
    if (root / "onboarding" / connector_type).is_dir():
        return connector_type
    return "external_generic"


def migrate_catalog(
    root: Path,
    catalog: dict[str, Any],
    profiles: dict[str, dict[str, Any]],
) -> tuple[dict[str, Any], list[str], list[str]]:
    """Return a v2 catalog plus deterministic change and error descriptions."""
    migrated = json.loads(json.dumps(catalog, ensure_ascii=False))
    changes: list[str] = []
    errors: list[str] = []
    connectors = migrated.get("connectors")
    if not isinstance(connectors, dict):
        return migrated, changes, ["connectors must be a JSON object"]

    if migrated.get("format_version") != FORMAT_VERSION:
        migrated["format_version"] = FORMAT_VERSION
        changes.append(f"set format_version={FORMAT_VERSION}")

    for connector_type, raw_spec in connectors.items():
        if not isinstance(raw_spec, dict):
            errors.append(f"connectors.{connector_type} must be a JSON object")
            continue
        template_name = str(raw_spec.get("onboarding_template") or "").strip()
        if not template_name:
            template_name = _template_name(root, str(connector_type))
            raw_spec["onboarding_template"] = template_name
            changes.append(f"connectors.{connector_type}.onboarding_template={template_name}")

        if not isinstance(raw_spec.get("onboarding_profile"), dict):
            profile = profiles.get(str(connector_type)) or profiles.get(template_name)
            if profile is None:
                errors.append(
                    f"connectors.{connector_type} has no onboarding_profile and no legacy profile"
                )
                continue
            raw_spec["onboarding_profile"] = json.loads(json.dumps(profile, ensure_ascii=False))
            changes.append(f"inline connectors.{connector_type}.onboarding_profile")

    return migrated, changes, errors


def migrate_root(root: Path, *, write: bool = False) -> dict[str, Any]:
    """Preview or write all connector catalog migrations under one DataAsset root.

    The legacy profile file is intentionally retained. Operators may remove it
    only after strict validation succeeds, which keeps rollback possible across a
    multi-file migration.
    """
    root = root.expanduser().resolve()
    profiles = _legacy_profiles(root)
    catalogs: list[dict[str, Any]] = []
    pending: list[tuple[Path, dict[str, Any]]] = []
    all_errors: list[str] = []

    for name in CATALOG_NAMES:
        path = root / "configure" / name
        if not path.is_file():
            all_errors.append(f"missing catalog: {path}")
            continue
        migrated, changes, errors = migrate_catalog(root, _read_object(path), profiles)
        catalogs.append(
            {
                "path": str(path),
                "changes": changes,
                "errors": errors,
                "changed": bool(changes),
            }
        )
        all_errors.extend(f"{path}: {error}" for error in errors)
        if changes:
            pending.append((path, migrated))

    written: list[str] = []
    # Do not partially migrate a root when any catalog cannot be converted.
    if write and not all_errors:
        for path, migrated in pending:
            _write_json_atomic(path, migrated)
            written.append(str(path))

    return {
        "ok": not all_errors,
        "root": str(root),
        "format_version": FORMAT_VERSION,
        "mode": "write" if write else "preview",
        "catalogs": catalogs,
        "errors": all_errors,
        "written": written,
        "legacy_profile_retained": (root / "configure" / LEGACY_PROFILE_NAME).is_file(),
    }
